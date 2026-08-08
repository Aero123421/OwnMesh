//! Portable PTY/ConPTY spawn + long-lived host helpers.
//!
//! Uses `portable-pty` which selects ConPTY on Windows and openpty on POSIX.
//! Docs: https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session

use ownmesh_session::{PtyBackend, PtyCommand, PtySize, SessionHostHandle};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize as PortableSize};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

/// Aggregate byte budget for one live host's unread output ring.
pub const LIVE_OUTPUT_RING_BYTES: usize = 1024 * 1024;
/// Hard cap for the one-shot pipe fallback (CLI session-host only).
/// Never `Command::output()` an attacker-controlled stream into memory.
pub const PIPE_FALLBACK_MAX_BYTES: usize = 256 * 1024;
/// Wall-clock bound for pipe-fallback collection before process-tree kill.
pub const PIPE_FALLBACK_TIMEOUT: Duration = Duration::from_secs(15);

/// Live PTY session used by the standalone CLI (or pipe fallback).
pub struct PtySession {
    pub handle: SessionHostHandle,
    kind: SessionKindInner,
}

enum SessionKindInner {
    Pty {
        reader: Mutex<Option<Box<dyn Read + Send>>>,
        writer: Mutex<Option<Box<dyn Write + Send>>>,
        child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
        _master: Box<dyn MasterPty + Send>,
    },
    Pipe {
        output: Mutex<Option<String>>,
    },
}

impl PtySession {
    /// Write one line to the child and surface both write and flush failures.
    pub fn write_stdin_line(&self, line: &str) -> Result<(), String> {
        let SessionKindInner::Pty { writer, .. } = &self.kind else {
            return Err("stdin is unavailable for the pipe fallback".into());
        };
        let mut writer = writer.lock().map_err(|err| err.to_string())?;
        let writer = writer
            .as_mut()
            .ok_or_else(|| "PTY stdin writer is unavailable".to_owned())?;
        write_stdin_line(writer.as_mut(), line).map_err(|err| err.to_string())
    }

    /// Stop and reap the child process tree. `Drop` repeats this as a backstop.
    pub fn terminate_and_wait(&self) -> Result<(), String> {
        let SessionKindInner::Pty { child, .. } = &self.kind else {
            return Ok(());
        };
        let mut child = child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminate_child_tree(child.as_mut(), self.handle.pid)
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if let SessionKindInner::Pty { child, .. } = &mut self.kind {
            let child = child
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = terminate_child_tree(child.as_mut(), self.handle.pid);
        }
    }
}

/// Long-lived PTY owned by `ownmeshd` for a cloud session.
///
/// A background reader fills a bounded byte ring. Callers drain the ring into
/// the session replay spool on attach/replay/write so slow consumers never force
/// unbounded allocation inside the reader thread.
pub struct LiveHost {
    pub handle: SessionHostHandle,
    writer: Mutex<Option<Box<dyn Write + Send>>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
    output: Arc<Mutex<ByteRing>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

struct ByteRing {
    buf: VecDeque<u8>,
    bytes: usize,
    /// Visible fact: reader dropped oldest bytes under backpressure.
    truncated: bool,
    /// Child exited (EOF observed or try_wait succeeded).
    exited: bool,
    exit_code: Option<u32>,
}

impl ByteRing {
    fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            bytes: 0,
            truncated: false,
            exited: false,
            exit_code: None,
        }
    }

    fn push(&mut self, chunk: &[u8]) {
        if chunk.is_empty() {
            return;
        }
        self.buf.extend(chunk.iter().copied());
        self.bytes = self.bytes.saturating_add(chunk.len());
        while self.bytes > LIVE_OUTPUT_RING_BYTES {
            if self.buf.pop_front().is_some() {
                self.bytes = self.bytes.saturating_sub(1);
                self.truncated = true;
            } else {
                break;
            }
        }
    }

    /// Drain up to `max_bytes`. Returns `(bytes, ring_truncated, remaining_after)`.
    ///
    /// `remaining_after > 0` is a durable continuation fact: the caller must not
    /// treat this drain as EOF while unread live-ring bytes remain.
    fn drain(&mut self, max_bytes: usize) -> (Vec<u8>, bool, usize) {
        let take = max_bytes.min(self.bytes);
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            if let Some(b) = self.buf.pop_front() {
                out.push(b);
                self.bytes = self.bytes.saturating_sub(1);
            } else {
                break;
            }
        }
        let truncated = self.truncated;
        // truncation flag is sticky until a full successful drain observes empty.
        if self.bytes == 0 {
            self.truncated = false;
        }
        (out, truncated, self.bytes)
    }

    fn remaining(&self) -> usize {
        self.bytes
    }
}

impl LiveHost {
    /// Spawn a long-lived PTY and start the output reader.
    ///
    /// Fails closed when a real PTY/ConPTY cannot be opened — cloud sessions
    /// must not silently degrade to metadata-only stubs.
    pub fn spawn(cmd: &PtyCommand, size: PtySize) -> Result<Self, String> {
        spawn_live_portable(cmd, size)
    }

    /// Write raw bytes to the child stdin (no forced newline).
    pub fn write_stdin(&self, data: &[u8]) -> Result<(), String> {
        let mut guard = self.writer.lock().map_err(|e| e.to_string())?;
        let writer = guard
            .as_mut()
            .ok_or_else(|| "PTY stdin writer is unavailable".to_owned())?;
        writer.write_all(data).map_err(|e| e.to_string())?;
        writer.flush().map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Resize the live PTY geometry.
    pub fn resize(&self, cols: u16, rows: u16) -> Result<(), String> {
        let master = self.master.lock().map_err(|e| e.to_string())?;
        master
            .resize(PortableSize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("resize: {e}"))
    }

    /// Drain up to `max_bytes` of pending UTF-8 lossy output.
    ///
    /// Returns `(text, ring_truncated, child_exited, exit_code, remaining_bytes)`.
    /// `remaining_bytes > 0` means more live-ring data is pending and must be
    /// surfaced as a continuation (never a silent EOF).
    pub fn drain_output(
        &self,
        max_bytes: usize,
    ) -> Result<(String, bool, bool, Option<u32>, usize), String> {
        // Opportunistically observe child exit without blocking.
        if let Ok(mut child) = self.child.lock() {
            if let Ok(Some(status)) = child.try_wait() {
                if let Ok(mut ring) = self.output.lock() {
                    ring.exited = true;
                    // portable-pty ExitStatus exposes success(); keep code optional.
                    ring.exit_code = if status.success() { Some(0) } else { Some(1) };
                }
            }
        }
        let mut ring = self.output.lock().map_err(|e| e.to_string())?;
        let (bytes, truncated, remaining) = ring.drain(max_bytes.max(1));
        let text = String::from_utf8_lossy(&bytes).into_owned();
        Ok((text, truncated, ring.exited, ring.exit_code, remaining))
    }

    /// Bytes still buffered in the live ring (not yet drained into the spool).
    pub fn pending_output_bytes(&self) -> usize {
        self.output.lock().map(|ring| ring.remaining()).unwrap_or(0)
    }

    /// True when the child has exited (best-effort).
    pub fn is_exited(&self) -> bool {
        if let Ok(ring) = self.output.lock() {
            if ring.exited {
                return true;
            }
        }
        if let Ok(mut child) = self.child.lock() {
            matches!(child.try_wait(), Ok(Some(_)))
        } else {
            false
        }
    }

    /// Kill and reap the child process tree; stop the reader thread.
    ///
    /// Uses OS process-tree containment (Windows `taskkill /T`, Unix session/pgid
    /// kill) so background descendants of interactive shells do not survive.
    pub fn terminate(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        // Drop writer so the child sees EOF on stdin before kill.
        if let Ok(mut w) = self.writer.lock() {
            *w = None;
        }
        let kill_result = {
            let mut child = self
                .child
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            terminate_child_tree(child.as_mut(), self.handle.pid)
        };
        // Never join the reader on the request/Drop path: ConPTY read() can stay
        // blocked after kill on some Windows hosts and would hang the daemon.
        // Detach the join into a daemon thread; the stop flag + dropped pipes are
        // enough for eventual exit.
        if let Some(handle) = self.reader.take() {
            let _ = std::thread::Builder::new()
                .name("ownmesh-pty-reader-join".into())
                .spawn(move || {
                    let _ = handle.join();
                });
        }
        kill_result
    }
}

impl Drop for LiveHost {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

/// Default interactive shell for the current platform.
#[must_use]
pub fn default_shell_command() -> PtyCommand {
    if cfg!(windows) {
        PtyCommand {
            program: "cmd.exe".into(),
            args: vec!["/Q".into(), "/K".into(), "prompt $G".into()],
            cwd: None,
            env: vec![("TERM".into(), "dumb".into())],
        }
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
        PtyCommand {
            program: shell,
            args: vec![],
            cwd: None,
            env: vec![("TERM".into(), "xterm-256color".into())],
        }
    }
}

fn write_stdin_line(writer: &mut dyn Write, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Kill a process tree by OS facilities that do not require `unsafe`.
///
/// - Windows: `taskkill /T /F` walks the parent/child tree (Job Object would need
///   `unsafe` which this workspace forbids).
/// - Unix: portable-pty `setsid()` makes the shell a session leader; kill the
///   session (`pkill -s`) plus process-group and direct PID so background jobs
///   (`sleep &`) cannot outlive the session.
fn kill_process_tree(pid: u32) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        // Session kill first (covers background jobs that changed PGID).
        let _ = std::process::Command::new("pkill")
            .args(["-KILL", "-s", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        // Negative PID = process group (session leader is usually its own PGID).
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &format!("-{pid}")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

fn terminate_child_tree(
    child: &mut (dyn portable_pty::Child + Send + Sync),
    known_pid: Option<u32>,
) -> Result<(), String> {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return Ok(());
    }

    let pid = known_pid.or_else(|| child.process_id());
    if let Some(pid) = pid {
        kill_process_tree(pid);
    }

    // Direct kill remains as a backstop when tree kill is unavailable/racy.
    if let Err(kill_err) = child.kill() {
        return match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(format!("kill child: {kill_err}; child is still running")),
            Err(wait_err) => Err(format!(
                "kill child: {kill_err}; query child after kill failure: {wait_err}"
            )),
        };
    }

    // Never block indefinitely in Drop/terminate paths (ConPTY can stall wait()).
    for _ in 0..40 {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(err) => return Err(format!("wait for child: {err}")),
        }
    }
    // Best-effort: child was signaled; accept unreaped state rather than hang the daemon.
    Ok(())
}

/// Spawn a PTY-backed process (pipe fallback on failure) for CLI one-shot use.
pub fn spawn_pty(cmd: &PtyCommand, size: PtySize) -> Result<PtySession, String> {
    match spawn_portable(cmd, size) {
        Ok(s) => Ok(s),
        Err(pty_err) => spawn_pipe_fallback(cmd, size, &pty_err),
    }
}

fn spawn_portable(cmd: &PtyCommand, size: PtySize) -> Result<PtySession, String> {
    let system = native_pty_system();
    let pair = system
        .openpty(PortableSize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("openpty: {e}"))?;

    let mut builder = CommandBuilder::new(&cmd.program);
    for a in &cmd.args {
        builder.arg(a);
    }
    if let Some(cwd) = &cmd.cwd {
        builder.cwd(cwd);
    }
    for (k, v) in &cmd.env {
        builder.env(k, v);
    }

    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("reader: {e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("writer: {e}"))?;

    let child = pair
        .slave
        .spawn_command(builder)
        .map_err(|e| format!("spawn: {e}"))?;
    drop(pair.slave);

    let pid = child.process_id();
    let backend = PtyBackend::preferred();
    let handle = SessionHostHandle {
        session_id: format!("pty_{}", pid.unwrap_or(0)),
        backend,
        pid,
        cols: size.cols,
        rows: size.rows,
    };

    Ok(PtySession {
        handle,
        kind: SessionKindInner::Pty {
            reader: Mutex::new(Some(reader)),
            writer: Mutex::new(Some(writer)),
            child: Mutex::new(child),
            _master: pair.master,
        },
    })
}

fn spawn_live_portable(cmd: &PtyCommand, size: PtySize) -> Result<LiveHost, String> {
    let system = native_pty_system();
    let pair = system
        .openpty(PortableSize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("openpty: {e}"))?;

    let mut builder = CommandBuilder::new(&cmd.program);
    for a in &cmd.args {
        builder.arg(a);
    }
    if let Some(cwd) = &cmd.cwd {
        builder.cwd(cwd);
    }
    for (k, v) in &cmd.env {
        builder.env(k, v);
    }

    let mut reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("reader: {e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("writer: {e}"))?;

    let child = pair
        .slave
        .spawn_command(builder)
        .map_err(|e| format!("spawn: {e}"))?;
    drop(pair.slave);

    let pid = child.process_id();
    let backend = PtyBackend::preferred();
    let handle = SessionHostHandle {
        session_id: format!("pty_{}", pid.unwrap_or(0)),
        backend,
        pid,
        cols: size.cols,
        rows: size.rows,
    };

    let output = Arc::new(Mutex::new(ByteRing::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let output_reader = Arc::clone(&output);
    let stop_reader = Arc::clone(&stop);

    let reader_handle = std::thread::Builder::new()
        .name("ownmesh-pty-reader".into())
        .spawn(move || {
            let mut buf = [0u8; 4096];
            while !stop_reader.load(Ordering::Relaxed) {
                match reader.read(&mut buf) {
                    Ok(0) => {
                        if let Ok(mut ring) = output_reader.lock() {
                            ring.exited = true;
                        }
                        break;
                    }
                    Ok(n) => {
                        if let Ok(mut ring) = output_reader.lock() {
                            ring.push(&buf[..n]);
                        }
                    }
                    Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(15));
                    }
                    Err(_) => {
                        if let Ok(mut ring) = output_reader.lock() {
                            ring.exited = true;
                        }
                        break;
                    }
                }
            }
        })
        .map_err(|e| format!("spawn reader thread: {e}"))?;

    Ok(LiveHost {
        handle,
        writer: Mutex::new(Some(writer)),
        master: Mutex::new(pair.master),
        child: Mutex::new(child),
        output,
        stop,
        reader: Some(reader_handle),
    })
}

fn spawn_pipe_fallback(
    cmd: &PtyCommand,
    size: PtySize,
    pty_err: &str,
) -> Result<PtySession, String> {
    use std::process::{Command, Stdio};
    use std::time::Instant;
    let mut c = Command::new(&cmd.program);
    c.args(&cmd.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &cmd.cwd {
        c.current_dir(cwd);
    }
    for (k, v) in &cmd.env {
        c.env(k, v);
    }
    let mut child = c
        .spawn()
        .map_err(|e| format!("pty failed ({pty_err}); pipe fallback spawn failed: {e}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| format!("pty failed ({pty_err}); pipe fallback missing stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| format!("pty failed ({pty_err}); pipe fallback missing stderr"))?;

    // Concurrent capped readers — never Command::output() an unbounded stream.
    let out_join =
        std::thread::spawn(move || read_pipe_capped(stdout, PIPE_FALLBACK_MAX_BYTES / 2));
    let err_join =
        std::thread::spawn(move || read_pipe_capped(stderr, PIPE_FALLBACK_MAX_BYTES / 2));

    let deadline = Instant::now() + PIPE_FALLBACK_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "pty failed ({pty_err}); pipe fallback wait failed: {e}"
                ));
            }
        }
    }

    let (out_text, out_trunc) = out_join.join().unwrap_or_else(|_| (String::new(), true));
    let (err_text, err_trunc) = err_join.join().unwrap_or_else(|_| (String::new(), true));

    let mut text = out_text;
    if !err_text.is_empty() {
        if !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&err_text);
    }
    if out_trunc || err_trunc {
        text.push_str("\n[ownmesh: pipe fallback output truncated]\n");
    }
    // Final hard cap after merge (UTF-8 safe).
    if text.len() > PIPE_FALLBACK_MAX_BYTES {
        let mut end = PIPE_FALLBACK_MAX_BYTES.min(text.len());
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push_str("\n[ownmesh: pipe fallback output truncated]\n");
    }
    let handle = SessionHostHandle {
        session_id: format!("pipe_{}", std::process::id()),
        backend: PtyBackend::PipeFallback,
        pid: None,
        cols: size.cols,
        rows: size.rows,
    };
    Ok(PtySession {
        handle,
        kind: SessionKindInner::Pipe {
            output: Mutex::new(Some(text)),
        },
    })
}

/// Read a pipe with a hard byte cap. Does not grow without bound on infinite output.
fn read_pipe_capped(mut reader: impl Read, max_bytes: usize) -> (String, bool) {
    let max_bytes = max_bytes.max(1);
    let mut buf = vec![0u8; 4096];
    let mut acc = Vec::with_capacity(max_bytes.min(64 * 1024));
    let mut truncated = false;
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let room = max_bytes.saturating_sub(acc.len());
                if room == 0 {
                    truncated = true;
                    // Drain remaining to avoid blocking the writer forever, but
                    // do not retain bytes. Bound drain iterations.
                    let mut drained = 0usize;
                    while drained < PIPE_FALLBACK_MAX_BYTES {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(m) => drained = drained.saturating_add(m),
                            Err(_) => break,
                        }
                    }
                    break;
                }
                let take = n.min(room);
                acc.extend_from_slice(&buf[..take]);
                if take < n {
                    truncated = true;
                    // Best-effort short drain of the remainder of this read cycle.
                    let mut drained = 0usize;
                    while drained < 64 * 1024 {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(m) => drained = drained.saturating_add(m),
                            Err(_) => break,
                        }
                    }
                    break;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    (String::from_utf8_lossy(&acc).into_owned(), truncated)
}

/// Read PTY output until child exits or `max_ms` elapses (0 = 5s default for safety).
///
/// The child is terminated and reaped before this function returns, including when
/// acquiring or reading PTY state fails.
pub fn read_until(session: &PtySession, max_ms: u64) -> Result<String, String> {
    let read_result = (|| -> Result<String, String> {
        match &session.kind {
            SessionKindInner::Pipe { output } => {
                let mut g = output.lock().map_err(|e| e.to_string())?;
                Ok(g.take().unwrap_or_default())
            }
            SessionKindInner::Pty { reader, child, .. } => {
                let max = if max_ms == 0 { 5_000 } else { max_ms };
                let mut reader_opt = reader.lock().map_err(|e| e.to_string())?;
                let Some(mut rdr) = reader_opt.take() else {
                    return Ok(String::new());
                };
                let (tx, rx) = mpsc::channel::<Vec<u8>>();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut acc = Vec::new();
                    loop {
                        match rdr.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                acc.extend_from_slice(&buf[..n]);
                                if acc.len() > 2 * 1024 * 1024 {
                                    break;
                                }
                                let _ = tx.send(acc.clone());
                            }
                            Err(_) => break,
                        }
                    }
                    let _ = tx.send(acc);
                });

                let deadline = std::time::Instant::now() + Duration::from_millis(max);
                let mut last = Vec::new();
                loop {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match rx.recv_timeout(Duration::from_millis(50).min(remaining)) {
                        Ok(chunk) => last = chunk,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if let Ok(mut ch) = child.lock() {
                                if let Ok(Some(_)) = ch.try_wait() {
                                    if let Ok(chunk) = rx.recv_timeout(Duration::from_millis(200)) {
                                        last = chunk;
                                    }
                                    break;
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    if !last.is_empty() {
                        if let Ok(mut ch) = child.lock() {
                            if let Ok(Some(_)) = ch.try_wait() {
                                break;
                            }
                        }
                    }
                }
                Ok(String::from_utf8_lossy(&last).into_owned())
            }
        }
    })();

    let cleanup_result = session.terminate_and_wait();
    match (read_result, cleanup_result) {
        (Ok(output), Ok(())) => Ok(output),
        (Err(read_err), Ok(())) => Err(read_err),
        (Ok(_), Err(cleanup_err)) => Err(cleanup_err),
        (Err(read_err), Err(cleanup_err)) => {
            Err(format!("{read_err}; child cleanup failed: {cleanup_err}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingWriter {
        fail_flush: bool,
    }

    impl Write for FailingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            if self.fail_flush {
                Ok(buf.len())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "write failed",
                ))
            }
        }

        fn flush(&mut self) -> std::io::Result<()> {
            if self.fail_flush {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "flush failed",
                ))
            } else {
                Ok(())
            }
        }
    }

    #[test]
    fn stdin_write_failure_is_returned() {
        let err = write_stdin_line(&mut FailingWriter { fail_flush: false }, "input")
            .expect_err("write failure must surface");
        assert!(err.to_string().contains("write failed"));
    }

    #[test]
    fn stdin_flush_failure_is_returned() {
        let err = write_stdin_line(&mut FailingWriter { fail_flush: true }, "input")
            .expect_err("flush failure must surface");
        assert!(err.to_string().contains("flush failed"));
    }

    #[test]
    fn pipe_fallback_bounds_infinite_output_and_terminates() {
        // Force the pipe fallback path by calling it directly with a producer that
        // would OOM under Command::output().
        #[cfg(windows)]
        let cmd = PtyCommand {
            program: "cmd.exe".into(),
            args: vec![
                "/Q".into(),
                "/C".into(),
                // tight loop writing to stdout; kill/timeout must contain it
                "for /L %i in (1,0,2) do @echo INFINITE_PIPE_FALLBACK_LINE_%i".into(),
            ],
            cwd: None,
            env: vec![],
        };
        #[cfg(not(windows))]
        let cmd = PtyCommand {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "while true; do printf 'INFINITE_PIPE_FALLBACK_LINE\n'; done".into(),
            ],
            cwd: None,
            env: vec![],
        };
        let started = std::time::Instant::now();
        let session = spawn_pipe_fallback(&cmd, PtySize::default(), "forced-test-fallback")
            .expect("bounded pipe fallback must succeed");
        assert_eq!(session.handle.backend, PtyBackend::PipeFallback);
        let text = match &session.kind {
            SessionKindInner::Pipe { output } => output
                .lock()
                .ok()
                .and_then(|mut g| g.take())
                .unwrap_or_default(),
            SessionKindInner::Pty { .. } => panic!("expected pipe session"),
        };
        assert!(
            text.len() <= PIPE_FALLBACK_MAX_BYTES + 128,
            "pipe fallback must cap output, got {} bytes",
            text.len()
        );
        assert!(
            text.contains("truncated") || text.len() <= PIPE_FALLBACK_MAX_BYTES,
            "overflow must be visible; got len={}",
            text.len()
        );
        assert!(
            started.elapsed() < PIPE_FALLBACK_TIMEOUT + Duration::from_secs(5),
            "fallback must terminate near timeout bound"
        );
    }

    #[test]
    fn live_host_echo_roundtrip() {
        #[cfg(windows)]
        let cmd = PtyCommand {
            program: "cmd.exe".into(),
            args: vec!["/Q".into(), "/C".into(), "echo LIVE_HOST_MARKER_OK".into()],
            cwd: None,
            env: vec![],
        };
        #[cfg(not(windows))]
        let cmd = PtyCommand {
            program: "/bin/sh".into(),
            args: vec!["-c".into(), "printf 'LIVE_HOST_MARKER_OK\\n'".into()],
            cwd: None,
            env: vec![],
        };
        let mut host = LiveHost::spawn(&cmd, PtySize::default()).expect("spawn live host");
        let mut acc = String::new();
        for _ in 0..80 {
            let (chunk, _trunc, exited, _, _remaining) =
                host.drain_output(64 * 1024).expect("drain");
            acc.push_str(&chunk);
            if acc.contains("LIVE_HOST_MARKER_OK") || exited {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = host.terminate();
        assert!(
            acc.contains("LIVE_HOST_MARKER_OK"),
            "live host must capture real process output, got: {acc:?}"
        );
    }

    #[test]
    fn byte_ring_drain_reports_remaining_continuation() {
        let mut ring = ByteRing::new();
        // 128 KiB of pending live output; drain only 64 KiB at a time.
        ring.push(&vec![b'A'; 128 * 1024]);
        let (first, trunc1, rem1) = ring.drain(64 * 1024);
        assert_eq!(first.len(), 64 * 1024);
        assert!(!trunc1);
        assert_eq!(rem1, 64 * 1024, "must surface remaining live-ring bytes");
        assert_eq!(ring.remaining(), 64 * 1024);
        let (second, trunc2, rem2) = ring.drain(64 * 1024);
        assert_eq!(second.len(), 64 * 1024);
        assert!(!trunc2);
        assert_eq!(rem2, 0);
        assert_eq!(ring.remaining(), 0);
    }

    #[test]
    fn terminate_kills_background_descendant_process_tree() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("bg-child-alive");

        #[cfg(windows)]
        let cmd = {
            // Child of the session shell sleeps then writes a marker. Terminate
            // must kill the whole tree (taskkill /T) so the marker never appears.
            let marker_win = marker.to_string_lossy().replace('/', "\\");
            PtyCommand {
                program: "cmd.exe".into(),
                args: vec![
                    "/Q".into(),
                    "/C".into(),
                    format!(
                        "start /b cmd /c \"ping -n 9 127.0.0.1 >nul & echo survived>{marker_win}\" & ping -n 30 127.0.0.1 >nul"
                    ),
                ],
                cwd: None,
                env: vec![],
            }
        };
        #[cfg(unix)]
        let cmd = {
            let marker_s = marker.to_string_lossy().replace('\\', "/");
            PtyCommand {
                program: "/bin/sh".into(),
                args: vec![
                    "-c".into(),
                    format!("(sleep 8; printf survived > '{marker_s}') & wait"),
                ],
                cwd: None,
                env: vec![],
            }
        };

        let mut host = LiveHost::spawn(&cmd, PtySize::default()).expect("spawn tree host");
        // Give the background child time to start.
        std::thread::sleep(Duration::from_millis(600));
        host.terminate().expect("terminate process tree");
        // Wait past the child's sleep window; marker must not appear.
        std::thread::sleep(Duration::from_millis(9_000));
        assert!(
            !marker.exists(),
            "background descendant survived session terminate (process-tree kill failed)"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dropping_session_kills_child_before_it_can_continue() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("child-survived");
        let command = PtyCommand {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!("sleep 1; printf survived > {}", marker.display()),
            ],
            cwd: None,
            env: vec![],
        };

        let session = spawn_portable(&command, PtySize::default()).expect("spawn PTY child");
        drop(session);
        std::thread::sleep(Duration::from_millis(1_300));

        assert!(
            !marker.exists(),
            "child continued running after session drop"
        );
    }
}
