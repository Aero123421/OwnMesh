//! Portable PTY/ConPTY spawn + long-lived host helpers.
//!
//! Uses `portable-pty` which selects ConPTY on Windows and openpty on POSIX.
//! Docs: https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session

use ownmesh_session::{PtyBackend, PtyCommand, PtySize, SessionHostHandle};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize as PortableSize};
use std::collections::VecDeque;
use std::io::{Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
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

// Darwin can lag or miss the stdlib's non-blocking child-state observation
// after concurrent PTY teardown. Retain a finite confirmation window while the
// macOS path also confirms absence from the OS process table below.
#[cfg(target_os = "macos")]
const TERMINATION_POLL_ATTEMPTS: usize = 200;
#[cfg(not(target_os = "macos"))]
const TERMINATION_POLL_ATTEMPTS: usize = 40;

/// Host I/O contract selected by the supervisor spawn request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostIoMode {
    #[default]
    Pty,
    StructuredPipes,
}

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

    /// Stop the child process tree and reap it when the OS permits an
    /// immediate non-blocking reap. `Drop` repeats this as a backstop.
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

/// A long-lived structured child with three distinct pipe channels.
///
/// Unlike a PTY this never performs terminal encoding.  Each reader owns a
/// separate bounded raw-byte ring, so stderr cannot be mistaken for a protocol
/// event and a noisy child cannot grow memory without bound.
pub struct StructuredProcessHost {
    pub handle: SessionHostHandle,
    stdin: Mutex<Option<ChildStdin>>,
    child: Mutex<Child>,
    stdout: Arc<Mutex<ByteRing>>,
    stderr: Arc<Mutex<ByteRing>>,
    stop: Arc<AtomicBool>,
    readers: Vec<JoinHandle<()>>,
}

impl StructuredProcessHost {
    pub fn spawn(cmd: &PtyCommand, size: PtySize) -> Result<Self, String> {
        // P1-C/P1-D review: same shared launchable resolver as PTY spawns and
        // command execution, so structured session launch agrees with profile
        // detection and never spawns a bare name the daemon PATH lacks.
        let resolved = ownmesh_exec::resolve_spawn_argv(
            &cmd.program,
            &cmd.args,
            cmd.cwd.as_deref().map(std::path::Path::new),
        )
        .map_err(|e| format!("resolve structured session program `{}`: {e}", cmd.program))?;
        let program = resolved[0].clone();
        let args: Vec<String> = resolved[1..].to_vec();
        let mut command = Command::new(&program);
        command
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(cwd) = &cmd.cwd {
            command.current_dir(cwd);
        }
        for (key, value) in &cmd.env {
            command.env(key, value);
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("structured spawn: {e}"))?;
        let pid = child.id();
        let stdin = child.stdin.take().ok_or("structured stdin unavailable")?;
        let stdout = child.stdout.take().ok_or("structured stdout unavailable")?;
        let stderr = child.stderr.take().ok_or("structured stderr unavailable")?;
        let stop = Arc::new(AtomicBool::new(false));
        let out_ring = Arc::new(Mutex::new(ByteRing::new()));
        let err_ring = Arc::new(Mutex::new(ByteRing::new()));
        let out_reader = spawn_pipe_ring_reader(stdout, Arc::clone(&out_ring), Arc::clone(&stop));
        let err_reader = spawn_pipe_ring_reader(stderr, Arc::clone(&err_ring), Arc::clone(&stop));
        Ok(Self {
            handle: SessionHostHandle {
                session_id: format!("proc_{pid}"),
                backend: PtyBackend::PipeFallback,
                pid: Some(pid),
                cols: size.cols,
                rows: size.rows,
            },
            stdin: Mutex::new(Some(stdin)),
            child: Mutex::new(child),
            stdout: out_ring,
            stderr: err_ring,
            stop,
            readers: vec![out_reader, err_reader],
        })
    }

    pub fn write_frame(&self, frame: &[u8]) -> Result<(), String> {
        if frame.is_empty() || frame.len() > 64 * 1024 || !frame.ends_with(b"\n") {
            return Err("structured frame must be LF terminated and <= 64KiB".into());
        }
        let mut stdin = self.stdin.lock().map_err(|e| e.to_string())?;
        let writer = stdin.as_mut().ok_or("structured stdin closed")?;
        writer
            .write_all(frame)
            .and_then(|()| writer.flush())
            .map_err(|e| e.to_string())
    }

    pub fn drain_stdout(&self, max: usize) -> Result<RawDrainOutput, String> {
        drain_ring(&self.stdout, max)
    }
    pub fn drain_stderr(&self, max: usize) -> Result<RawDrainOutput, String> {
        drain_ring(&self.stderr, max)
    }
    pub fn pending_stdout_bytes(&self) -> usize {
        self.stdout.lock().map(|r| r.remaining()).unwrap_or(0)
    }
    pub fn pending_stderr_bytes(&self) -> usize {
        self.stderr.lock().map(|r| r.remaining()).unwrap_or(0)
    }
    pub fn pending_output_bytes(&self) -> usize {
        self.pending_stdout_bytes()
            .saturating_add(self.pending_stderr_bytes())
    }
    pub fn is_exited(&self) -> bool {
        self.stdout.lock().map(|r| r.exited).unwrap_or(true)
            && self.stderr.lock().map(|r| r.exited).unwrap_or(true)
    }

    pub fn terminate(&mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        if let Ok(mut stdin) = self.stdin.lock() {
            *stdin = None;
        }
        let mut child = self.child.lock().map_err(|e| e.to_string())?;
        let result = terminate_std_child_tree(&mut child);
        for reader in self.readers.drain(..) {
            let _ = std::thread::Builder::new().spawn(move || {
                let _ = reader.join();
            });
        }
        result
    }
}

impl Drop for StructuredProcessHost {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

fn spawn_pipe_ring_reader<R: Read + Send + 'static>(
    mut reader: R,
    ring: Arc<Mutex<ByteRing>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    std::thread::spawn(move || {
        let mut buf = [0_u8; 8192];
        while !stop.load(Ordering::SeqCst) {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if let Ok(mut r) = ring.lock() {
                        r.push(&buf[..n]);
                    }
                }
                Err(_) => break,
            }
        }
    })
}

fn drain_ring(ring: &Arc<Mutex<ByteRing>>, max: usize) -> Result<RawDrainOutput, String> {
    let mut ring = ring.lock().map_err(|e| e.to_string())?;
    let (bytes, truncated, remaining) = ring.drain(max.clamp(1, LIVE_OUTPUT_RING_BYTES));
    Ok((bytes, truncated, ring.exited, ring.exit_code, remaining))
}

fn terminate_std_child_tree(child: &mut Child) -> Result<(), String> {
    if child.try_wait().map_err(|e| e.to_string())?.is_some() {
        return Ok(());
    }
    #[cfg(windows)]
    {
        let status = Command::new("taskkill")
            .args(["/PID", &child.id().to_string(), "/T", "/F"])
            .status()
            .map_err(|e| e.to_string())?;
        if !status.success() {
            return Err("taskkill failed".into());
        }
    }
    #[cfg(unix)]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &format!("-{}", child.id())])
            .status();
        let _ = child.kill();
    }
    let _ = child.wait();
    Ok(())
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

    /// Drain up to `max_bytes` of raw PTY output bytes.
    ///
    /// Returns `(bytes, ring_truncated, child_exited, exit_code, remaining_bytes)`.
    /// Callers that need display text must perform their own explicitly lossy
    /// conversion; durable supervisor spools retain these bytes unchanged.
    pub fn drain_output_bytes(&self, max_bytes: usize) -> Result<RawDrainOutput, String> {
        // `remaining_bytes > 0` means more live-ring data is pending and must
        // be surfaced as a continuation (never a silent EOF).
        let mut ring = self.output.lock().map_err(|e| e.to_string())?;
        let (bytes, truncated, remaining) = ring.drain(max_bytes.max(1));
        // Reader EOF is the ordering barrier for process exit. Polling the
        // child first can publish `exited` before the reader has transferred
        // the PTY's final bytes into this ring, creating a false empty EOF.
        let exited = ring.exited;
        let mut exit_code = ring.exit_code;
        drop(ring);

        if exited && exit_code.is_none() {
            if let Ok(mut child) = self.child.lock() {
                if let Ok(Some(status)) = child.try_wait() {
                    // portable-pty ExitStatus exposes success(); keep code optional.
                    exit_code = if status.success() { Some(0) } else { Some(1) };
                    if let Ok(mut ring) = self.output.lock() {
                        ring.exit_code = exit_code;
                    }
                }
            }
        }

        Ok((bytes, truncated, exited, exit_code, remaining))
    }

    /// Drain up to `max_bytes` of pending output as explicitly lossy UTF-8.
    ///
    /// This compatibility view is for terminal presentation only. Persistent
    /// supervisor output uses [`Self::drain_output_bytes`] instead.
    pub fn drain_output(
        &self,
        max_bytes: usize,
    ) -> Result<(String, bool, bool, Option<u32>, usize), String> {
        let (bytes, truncated, exited, exit_code, remaining) =
            self.drain_output_bytes(max_bytes)?;
        Ok((
            String::from_utf8_lossy(&bytes).into_owned(),
            truncated,
            exited,
            exit_code,
            remaining,
        ))
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

    /// Kill the child process tree, reap it when immediately safe, and stop
    /// the reader thread.
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
///
/// The program is resolved through the shared executable resolver so session
/// launch agrees with command execution, profile detection and review pinning:
/// on Windows a bare `cmd.exe` would let `CreateProcess` search the current
/// directory for a shadowing `cmd.exe` (a workspace or cwd file could impersonate
/// the pinned system shell), so the default is the absolute system path
/// (`%SystemRoot%\System32\cmd.exe`) exactly like batch shims are. On Unix the
/// resolved `$SHELL`/`/bin/sh` is an absolute launchable path. Resolution
/// failure is fail-closed: the caller-supplied name is NEVER preserved as-is —
/// a bare name handed to a spawner would be re-searched by a different PATH or
/// (on Windows) by `CreateProcess`'s current-directory search, letting a
/// workspace/cwd file shadow the pinned system shell. The platform's absolute
/// default shell (`/bin/sh` on Unix, the system `cmd.exe` on Windows) is used
/// instead, so the spawn either runs the known-good interpreter or fails with a
/// clear OS error.
#[must_use]
pub fn default_shell_command() -> PtyCommand {
    default_shell_command_with(
        std::env::var("SHELL").ok().as_deref(),
        std::env::var("SystemRoot").ok().as_deref(),
    )
}

/// Pure core of [`default_shell_command`]; parameters keep the resolution and
/// fallback unit-testable on any platform without mutating process env.
///
/// `shell` is the `$SHELL` value (Unix) and `system_root` is `%SystemRoot%`
/// (Windows). The returned program is always an absolute launchable path (see
/// [`default_shell_command`] for the fail-closed rationale).
#[must_use]
fn default_shell_command_with(shell: Option<&str>, system_root: Option<&str>) -> PtyCommand {
    let (program, args, env) = if cfg!(windows) {
        (
            ownmesh_exec::windows_system_cmd_exe(system_root),
            vec!["/Q".to_string(), "/K".to_string(), "prompt $G".to_string()],
            vec![("TERM".to_string(), "dumb".to_string())],
        )
    } else {
        let shell = shell.unwrap_or("/bin/sh");
        (
            shell.to_string(),
            Vec::new(),
            vec![("TERM".to_string(), "xterm-256color".to_string())],
        )
    };
    let (program, args) = match ownmesh_exec::resolve_spawn_argv(&program, &args, None) {
        Ok(resolved) => (resolved[0].clone(), resolved[1..].to_vec()),
        Err(_) => {
            // Fail-closed fallback: never return the caller-supplied bare
            // name. Use the platform's absolute default shell so the spawn
            // runs a known-good interpreter or fails with a clear OS error.
            if cfg!(windows) {
                (ownmesh_exec::windows_system_cmd_exe(system_root), args)
            } else {
                ("/bin/sh".to_string(), args)
            }
        }
    };
    PtyCommand {
        program,
        args,
        cwd: None,
        env,
    }
}

fn write_stdin_line(writer: &mut dyn Write, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

/// Resolve a Darwin PTY leader's controlling terminal while the leader still
/// exists. The returned name is already in the form accepted by `pkill -t`.
#[cfg(target_os = "macos")]
fn macos_controlling_tty(root_pid: u32) -> Option<String> {
    std::process::Command::new("/bin/ps")
        .args(["-p", &root_pid.to_string(), "-o", "tty="])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|output| output.status.success() && output.stdout.len() <= 128)
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|tty| tty.trim().to_owned())
        .filter(|tty| !tty.is_empty() && tty != "??" && tty != "-")
}

/// Signal every process attached to one dedicated Darwin PTY. `pattern` is
/// fixed and `tty` comes from the exact process-table field above, not input.
#[cfg(target_os = "macos")]
fn signal_macos_tty(tty: &str, signal: &str) {
    let _ = std::process::Command::new("/usr/bin/pkill")
        .args([signal, "-t", tty, ".*"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Snapshot and kill Darwin descendants before signalling the PTY session
/// leader. This is a fallback for runners where session/process-group signals
/// are refused; capturing the PIDs first prevents them being orphaned when the
/// leader exits. Traversal and accepted output are explicitly capped.
#[cfg(target_os = "macos")]
#[allow(clippy::too_many_lines)] // bounded TTY/session/ancestry snapshots form one kill transaction
fn kill_macos_descendants(root_pid: u32, known_tty: Option<&str>) {
    const MAX_DESCENDANTS: usize = 4096;
    const MAX_PGREP_BYTES: usize = 128 * 1024;
    const MAX_PS_BYTES: usize = 1024 * 1024;

    let mut pending = vec![root_pid];
    let mut descendants = Vec::new();
    let mut seen = std::collections::HashSet::from([root_pid]);

    // The controlling PTY is the strongest containment boundary available on
    // Darwin without unsafe process APIs. It catches background jobs even if
    // their parent or process group changed. Query it while the leader still
    // exists, then ask Apple's supported `pgrep -t` selector for exact PIDs;
    // the leader itself remains reserved for `Child::kill()` below.
    let discovered_tty;
    let tty = if let Some(known_tty) = known_tty {
        Some(known_tty)
    } else {
        discovered_tty = macos_controlling_tty(root_pid);
        discovered_tty.as_deref()
    };
    if let Some(tty) = tty {
        if let Ok(output) = std::process::Command::new("/usr/bin/pgrep")
            .args(["-t", tty, ".*"])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        {
            if output.status.success() && output.stdout.len() <= MAX_PGREP_BYTES {
                for line in output.stdout.split(|byte| *byte == b'\n') {
                    let Ok(text) = std::str::from_utf8(line) else {
                        continue;
                    };
                    let Ok(pid) = text.trim().parse::<u32>() else {
                        continue;
                    };
                    if seen.insert(pid) && descendants.len() < MAX_DESCENDANTS {
                        descendants.push(pid);
                        pending.push(pid);
                    }
                }
            }
        }
    }

    // Apple's pgrep/pkill deliberately do not implement the `-s sid` filter.
    // portable-pty makes the command PID a session leader, so snapshot the
    // numeric process table instead. Match both the session and controlling
    // TTY so this remains authoritative if Darwin reports an unexpected
    // session value during concurrent PTY teardown.
    if let Ok(output) = std::process::Command::new("/bin/ps")
        .args(["-axo", "pid=,sess=,tty="])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    {
        if output.status.success() && output.stdout.len() <= MAX_PS_BYTES {
            for line in output.stdout.split(|byte| *byte == b'\n') {
                let Ok(text) = std::str::from_utf8(line) else {
                    continue;
                };
                let mut fields = text.split_whitespace();
                let (Some(pid), Some(session), Some(process_tty), None) =
                    (fields.next(), fields.next(), fields.next(), fields.next())
                else {
                    continue;
                };
                let (Ok(pid), Ok(session)) = (pid.parse::<u32>(), session.parse::<u32>()) else {
                    continue;
                };
                if (session == root_pid || tty == Some(process_tty))
                    && seen.insert(pid)
                    && descendants.len() < MAX_DESCENDANTS
                {
                    descendants.push(pid);
                    pending.push(pid);
                }
            }
        }
    }

    while let Some(parent) = pending.pop() {
        if descendants.len() >= MAX_DESCENDANTS {
            break;
        }
        let Ok(output) = std::process::Command::new("/usr/bin/pgrep")
            .args(["-P", &parent.to_string()])
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .output()
        else {
            break;
        };
        // `pgrep` exits 1 when no child matched. Other failures cannot safely
        // expand the snapshot, but the session/group kill below still runs.
        if output.status.code() == Some(1) {
            continue;
        }
        if !output.status.success() || output.stdout.len() > MAX_PGREP_BYTES {
            break;
        }
        for line in output.stdout.split(|byte| *byte == b'\n') {
            let Ok(text) = std::str::from_utf8(line) else {
                continue;
            };
            let Ok(pid) = text.trim().parse::<u32>() else {
                continue;
            };
            if seen.insert(pid) {
                descendants.push(pid);
                pending.push(pid);
            }
        }
    }

    // Every captured PID is signalled directly. The second snapshot after the
    // leader signal handles anything created between this snapshot and kill.
    for pid in descendants {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
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
        #[cfg(target_os = "macos")]
        let kill_program = "/bin/kill";
        #[cfg(not(target_os = "macos"))]
        let (pkill_program, kill_program) = ("pkill", "kill");

        // Apple pgrep/pkill do not support `-s sid`; use the bounded Darwin
        // session/ancestry snapshot and direct PID signals instead.
        #[cfg(target_os = "macos")]
        kill_macos_descendants(pid, None);

        // Session kill first (covers background jobs that changed PGID).
        #[cfg(not(target_os = "macos"))]
        let _ = std::process::Command::new(pkill_program)
            .args(["-KILL", "-s", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        // Negative PID = process group (session leader is usually its own PGID).
        let _ = std::process::Command::new(kill_program)
            .args(["-KILL", "--", &format!("-{pid}")])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        let _ = std::process::Command::new(kill_program)
            .args(["-KILL", &pid.to_string()])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
    }
}

/// Exact Darwin process-table observation for post-kill confirmation.
#[cfg(target_os = "macos")]
#[derive(Debug)]
enum MacosProcessState {
    Absent,
    Zombie,
    Exiting(String),
    Live(String),
}

/// Classify Darwin's compact `ps stat` value. The first character is the run
/// state; later characters are flags. In particular, Apple documents `E` as
/// `P_WEXIT` (the process is trying to exit), so it must not be confused with
/// a runnable child merely because its primary state is temporarily `?`.
#[cfg(target_os = "macos")]
fn classify_macos_process_state(state: String) -> MacosProcessState {
    if state.starts_with('Z') {
        MacosProcessState::Zombie
    } else if state.chars().skip(1).any(|flag| flag == 'E') {
        MacosProcessState::Exiting(state)
    } else {
        MacosProcessState::Live(state)
    }
}

/// `/bin/ps` is an absolute OS tool. Exit 1 means the exact PID selection
/// matched nothing; exit 0 returns the bounded state code. Any other outcome is
/// an observation failure and must not prove death.
#[cfg(target_os = "macos")]
fn macos_process_state(pid: u32) -> Result<MacosProcessState, String> {
    const MAX_STATE_BYTES: usize = 128;
    let output = std::process::Command::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "stat="])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .map_err(|err| format!("query killed child {pid} in process table: {err}"))?;
    match output.status.code() {
        Some(0) if output.stdout.len() <= MAX_STATE_BYTES => {
            let state = std::str::from_utf8(&output.stdout)
                .map_err(|err| format!("decode killed child {pid} process state: {err}"))?
                .trim()
                .to_owned();
            Ok(classify_macos_process_state(state))
        }
        Some(0) => Err(format!(
            "query killed child {pid} in process table: oversized state output"
        )),
        Some(1) => Ok(MacosProcessState::Absent),
        Some(code) => Err(format!(
            "query killed child {pid} in process table: ps exited with {code}"
        )),
        None => Err(format!(
            "query killed child {pid} in process table: ps ended without an exit code"
        )),
    }
}

/// Confirm/reap a Darwin child without accepting a live process as dead.
/// Waiting is used only after `ps` reports `Z`, where the process has already
/// exited and `wait` is an immediate OS reap rather than an unbounded liveness
/// wait. `P_WEXIT` (`E`) is also authoritative confirmation that Darwin has
/// committed the process to exit; it can be blocked in kernel teardown, so a
/// synchronous wait here would violate the bounded termination contract.
#[cfg(target_os = "macos")]
fn macos_confirm_child_exit(
    child: &mut (dyn portable_pty::Child + Send + Sync),
    pid: u32,
) -> Result<bool, String> {
    match macos_process_state(pid)? {
        MacosProcessState::Absent => Ok(true),
        MacosProcessState::Zombie => child
            .wait()
            .map(|_| true)
            .map_err(|err| format!("reap zombie child {pid}: {err}")),
        MacosProcessState::Exiting(_) => Ok(true),
        MacosProcessState::Live(_) => Ok(false),
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
    // Do not externally kill the Darwin leader before `Child::kill()` gets to
    // update its own process state. Snapshot/kill descendants first; the full
    // session/group backstop runs immediately after the direct child signal.
    #[cfg(target_os = "macos")]
    let macos_tty = pid.and_then(macos_controlling_tty);
    #[cfg(target_os = "macos")]
    if let Some(pid) = pid {
        // Freeze the dedicated PTY before killing descendants. Without this
        // barrier, killing a leaf such as `sleep` can wake its parent shell and
        // let the next command run in the few milliseconds before that parent
        // receives its own signal.
        if let Some(tty) = macos_tty.as_deref() {
            signal_macos_tty(tty, "-STOP");
        }
        kill_macos_descendants(pid, macos_tty.as_deref());
    }
    #[cfg(not(target_os = "macos"))]
    if let Some(pid) = pid {
        kill_process_tree(pid);
    }

    // Direct kill remains as a backstop when tree kill is unavailable/racy.
    let kill_result = child.kill();
    #[cfg(target_os = "macos")]
    if let Some(pid) = pid {
        // Reuse the pre-kill TTY name: once the leader is gone it can no longer
        // be rediscovered, while an orphan created during teardown may still
        // be attached to that PTY. Kill the frozen remainder before the normal
        // session/group/direct-PID backstops run.
        if let Some(tty) = macos_tty.as_deref() {
            signal_macos_tty(tty, "-KILL");
        }
        kill_process_tree(pid);
    }
    if let Err(kill_err) = kill_result {
        #[cfg(target_os = "macos")]
        if let Some(pid) = pid {
            if matches!(macos_confirm_child_exit(child, pid), Ok(true)) {
                return Ok(());
            }
        }
        return match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(format!("kill child: {kill_err}; child is still running")),
            Err(wait_err) => Err(format!(
                "kill child: {kill_err}; query child after kill failure: {wait_err}"
            )),
        };
    }

    // Never block indefinitely in Drop/terminate paths (ConPTY can stall wait()).
    for _ in 0..TERMINATION_POLL_ATTEMPTS {
        match child.try_wait() {
            Ok(Some(_)) => return Ok(()),
            Ok(None) => {
                // On Darwin, `Child::try_wait()` can continue returning None
                // after a concurrently torn-down PTY child has disappeared.
                // Absence from the process table is an independent, exact
                // confirmation; a zombie is reaped only after `ps` proves it
                // has exited. Darwin's `P_WEXIT` state is already committed
                // to kernel exit and is accepted without a potentially
                // blocking wait; an ordinary live state is never accepted.
                #[cfg(target_os = "macos")]
                if let Some(pid) = pid {
                    if macos_confirm_child_exit(child, pid)? {
                        return Ok(());
                    }
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(format!("wait for child: {err}")),
        }
    }
    // The child was signaled but has not confirmed exit within the bounded
    // poll window. Reporting success here would let the supervisor untrack a
    // host whose child may still be alive, and daemon transition recovery
    // treats "not tracked" as authoritative proof of death (P0-A review).
    // Fail honestly instead: the host stays tracked and the next sweep
    // retries the kill. Drop paths ignore this error, so the never-hang
    // contract is preserved.
    #[cfg(target_os = "macos")]
    if let Some(pid) = pid {
        let state = match macos_process_state(pid) {
            Ok(MacosProcessState::Absent) => "absent".to_owned(),
            Ok(MacosProcessState::Zombie) => "zombie".to_owned(),
            Ok(MacosProcessState::Exiting(state)) => format!("exiting:{state}"),
            Ok(MacosProcessState::Live(state)) => format!("live:{state}"),
            Err(err) => format!("observation-error:{err}"),
        };
        return Err(format!(
            "child did not confirm exit within the termination poll window (Darwin state: {state})"
        ));
    }
    Err("child did not confirm exit within the termination poll window".into())
}

/// Spawn a PTY-backed process (pipe fallback on failure) for CLI one-shot use.
pub fn spawn_pty(cmd: &PtyCommand, size: PtySize) -> Result<PtySession, String> {
    // P1-C/P1-D review: resolve through the shared launchable resolver before
    // any spawner sees the program, exactly like profile detection, command
    // execution and review pinning. The daemon service PATH is system-only, so
    // a user-local CLI found by deterministic discovery must launch by its
    // absolute path, and on Windows an extensionless npm shim must never beat
    // its invocable `.exe/.com/.cmd/.bat` sibling (Win32 error 193). A
    // program that cannot be resolved fails closed with the exact reason
    // instead of a bare-name spawn the daemon's PATH may not contain.
    let resolved = ownmesh_exec::resolve_spawn_argv(
        &cmd.program,
        &cmd.args,
        cmd.cwd.as_deref().map(std::path::Path::new),
    )
    .map_err(|e| format!("resolve session program `{}`: {e}", cmd.program))?;
    let resolved_cmd = PtyCommand {
        program: resolved[0].clone(),
        args: resolved[1..].to_vec(),
        ..cmd.clone()
    };
    match spawn_portable(&resolved_cmd, size) {
        Ok(s) => Ok(s),
        Err(pty_err) => spawn_pipe_fallback(&resolved_cmd, size, &pty_err),
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
    // P1-C/P1-D review (defense-in-depth): resolve through the shared
    // launchable resolver before the spawner sees the program, exactly like
    // `spawn_pty` and `StructuredProcessHost` do. A bare name must never reach
    // the spawner — `CreateProcess` would search the working directory for a
    // shadowing `cmd.exe`/`cmd.com` (a workspace or cwd file could impersonate
    // the pinned shell), and a Unix spawner would re-search a PATH that may
    // differ from the resolver's. Unresolved programs fail closed with the
    // exact reason instead of being spawned as-is. Re-resolving an already
    // absolute path is idempotent (launchable-file check only), so the
    // daemon-resolved argv and the supervisor-resolved argv stay consistent.
    let resolved = ownmesh_exec::resolve_spawn_argv(
        &cmd.program,
        &cmd.args,
        cmd.cwd.as_deref().map(std::path::Path::new),
    )
    .map_err(|e| format!("resolve session program `{}`: {e}", cmd.program))?;
    let resolved_cmd = PtyCommand {
        program: resolved[0].clone(),
        args: resolved[1..].to_vec(),
        ..cmd.clone()
    };
    let system = native_pty_system();
    let pair = system
        .openpty(PortableSize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|e| format!("openpty: {e}"))?;

    let mut builder = CommandBuilder::new(&resolved_cmd.program);
    for a in &resolved_cmd.args {
        builder.arg(a);
    }
    if let Some(cwd) = &resolved_cmd.cwd {
        builder.cwd(cwd);
    }
    for (k, v) in &resolved_cmd.env {
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

/// Aggregate byte budget for one-shot `read_until` collection (CLI helper).
pub const READ_UNTIL_MAX_BYTES: usize = 256 * 1024;

/// Raw PTY drain result: bytes, ring truncation, child exit, exit status, and
/// remaining live-ring bytes.
pub type RawDrainOutput = (Vec<u8>, bool, bool, Option<u32>, usize);
/// Bounded channel depth for reader→collector chunks (4 KiB each).
const READ_UNTIL_CHANNEL_CHUNKS: usize = 64;

/// Read PTY output until child exits or `max_ms` elapses (0 = 5s default for safety).
///
/// Collection is strictly bounded: fixed-size chunks over a bounded channel and a
/// single aggregate byte cap (`READ_UNTIL_MAX_BYTES`). Never clones a growing
/// accumulator per read. Truncation is visible via the returned UTF-8 lossy text
/// length being capped; the child is always terminated before return.
///
/// The child is terminated before this function returns, including when
/// acquiring or reading PTY state fails. It is reaped immediately when the OS
/// exposes a non-blocking reap; Darwin kernel-exit teardown may finish
/// asynchronously after the bounded return.
#[allow(clippy::too_many_lines)] // bounded channel collector + terminate path stay collocated
pub fn read_until(session: &PtySession, max_ms: u64) -> Result<String, String> {
    let read_result = (|| -> Result<String, String> {
        match &session.kind {
            SessionKindInner::Pipe { output } => {
                let mut g = output.lock().map_err(|e| e.to_string())?;
                let mut s = g.take().unwrap_or_default();
                if s.len() > READ_UNTIL_MAX_BYTES {
                    s.truncate(READ_UNTIL_MAX_BYTES);
                }
                Ok(s)
            }
            SessionKindInner::Pty { reader, child, .. } => {
                let max = if max_ms == 0 { 5_000 } else { max_ms };
                let mut reader_opt = reader.lock().map_err(|e| e.to_string())?;
                let Some(mut rdr) = reader_opt.take() else {
                    return Ok(String::new());
                };
                // Bounded channel of fixed chunks — backpressure stalls the reader
                // instead of retaining hundreds of MiB of intermediate clones.
                let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(READ_UNTIL_CHANNEL_CHUNKS);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    let mut total = 0usize;
                    loop {
                        if total >= READ_UNTIL_MAX_BYTES {
                            break;
                        }
                        match rdr.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let take = n.min(READ_UNTIL_MAX_BYTES - total);
                                if take == 0 {
                                    break;
                                }
                                total = total.saturating_add(take);
                                // Blocking send applies backpressure under a stalled collector.
                                if tx.send(buf[..take].to_vec()).is_err() {
                                    break;
                                }
                                if take < n {
                                    break; // hit aggregate cap mid-read
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    // Dropping tx closes the channel.
                });

                let deadline = std::time::Instant::now() + Duration::from_millis(max);
                let mut acc = Vec::with_capacity(4096);
                loop {
                    if acc.len() >= READ_UNTIL_MAX_BYTES {
                        break;
                    }
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        break;
                    }
                    match rx.recv_timeout(Duration::from_millis(50).min(remaining)) {
                        Ok(chunk) => {
                            let room = READ_UNTIL_MAX_BYTES.saturating_sub(acc.len());
                            if room == 0 {
                                break;
                            }
                            let take = chunk.len().min(room);
                            acc.extend_from_slice(&chunk[..take]);
                        }
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if let Ok(mut ch) = child.lock() {
                                if let Ok(Some(_)) = ch.try_wait() {
                                    // Drain any remaining queued chunks briefly.
                                    while acc.len() < READ_UNTIL_MAX_BYTES {
                                        match rx.recv_timeout(Duration::from_millis(50)) {
                                            Ok(chunk) => {
                                                let room =
                                                    READ_UNTIL_MAX_BYTES.saturating_sub(acc.len());
                                                let take = chunk.len().min(room);
                                                acc.extend_from_slice(&chunk[..take]);
                                                if take < chunk.len() {
                                                    break;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    }
                    if !acc.is_empty() {
                        if let Ok(mut ch) = child.lock() {
                            if let Ok(Some(_)) = ch.try_wait() {
                                break;
                            }
                        }
                    }
                }
                Ok(String::from_utf8_lossy(&acc).into_owned())
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

    #[cfg(target_os = "macos")]
    #[test]
    fn darwin_ps_exit_flag_is_not_classified_as_live() {
        assert!(matches!(
            classify_macos_process_state("?<Es".to_owned()),
            MacosProcessState::Exiting(state) if state == "?<Es"
        ));
        assert!(matches!(
            classify_macos_process_state("Z+".to_owned()),
            MacosProcessState::Zombie
        ));
        assert!(matches!(
            classify_macos_process_state("S+".to_owned()),
            MacosProcessState::Live(state) if state == "S+"
        ));
    }

    /// P1-C review: the default interactive shell is resolved through the
    /// shared executable resolver before a spawner sees it. On Windows a bare
    /// `cmd.exe` would let `CreateProcess` search the current directory for a
    /// shadowing `cmd.exe` (a workspace/cwd file could impersonate the pinned
    /// system shell); after resolution the program is the absolute system
    /// path. On Unix the resolved `$SHELL`/`/bin/sh` is an absolute
    /// launchable file, so default session launch agrees with command
    /// execution, profile detection and review pinning — there is no
    /// detect-ready-then-spawn-bare-name disagreement.
    #[test]
    fn default_shell_command_resolves_to_an_absolute_launchable_program() {
        let cmd = default_shell_command();
        let path = std::path::Path::new(&cmd.program);
        assert!(
            path.is_absolute(),
            "default shell must resolve to an absolute path, got `{}`",
            cmd.program
        );
        assert!(
            ownmesh_exec::is_launchable_file(path),
            "default shell must be a launchable file, got `{}`",
            cmd.program
        );
        #[cfg(windows)]
        assert!(
            cmd.program.to_ascii_lowercase().ends_with("cmd.exe"),
            "Windows default shell must resolve to the system cmd.exe, got `{}`",
            cmd.program
        );
    }

    /// v1.2.13 review (fail-closed): `default_shell_command` must NEVER
    /// preserve the caller-supplied program when resolution fails. On Windows
    /// a bare `cmd.exe` would let `CreateProcess` search the working directory
    /// for a shadowing `cmd.exe`/`cmd.com` (Microsoft CreateProcess
    /// documentation); on Unix a bare `$SHELL` would be re-searched by the
    /// spawner's PATH, which may disagree with the resolver that profile
    /// detection and command execution use. The pure core is exercised with an
    /// unresolvable `$SHELL` (absolute and bare forms) and must return the
    /// platform's absolute launchable default instead.
    #[cfg(not(windows))]
    #[test]
    fn default_shell_falls_back_to_absolute_default_when_shell_unresolvable() {
        let broken = default_shell_command_with(Some("/nonexistent/ownmesh-shell-probe"), None);
        let path = std::path::Path::new(&broken.program);
        assert!(
            path.is_absolute(),
            "fallback shell must be absolute, got `{}`",
            broken.program
        );
        assert!(
            ownmesh_exec::is_launchable_file(path),
            "fallback shell must be a launchable file, got `{}`",
            broken.program
        );
        assert_ne!(
            broken.program, "/nonexistent/ownmesh-shell-probe",
            "an unresolvable $SHELL must never be preserved for a spawner"
        );
        // A bare (non-absolute) $SHELL that PATH cannot resolve must also fall
        // back instead of being handed to the spawner as a bare name.
        let bare = default_shell_command_with(Some("ownmesh-shell-bare-probe"), None);
        let bare_path = std::path::Path::new(&bare.program);
        assert!(
            bare_path.is_absolute(),
            "bare $SHELL fallback must be absolute"
        );
        assert!(ownmesh_exec::is_launchable_file(bare_path));
    }

    /// v1.2.13 review: on Windows the default shell is the pinned absolute
    /// `%SystemRoot%\System32\cmd.exe` from the start — never a bare
    /// `cmd.exe` that `CreateProcess` would resolve with the current
    /// directory first in its search order.
    #[cfg(windows)]
    #[test]
    fn default_shell_uses_absolute_system_cmd_exe() {
        let cmd = default_shell_command_with(None, Some("C:\\Windows"));
        assert_eq!(cmd.program, "C:\\Windows\\System32\\cmd.exe");
        assert!(std::path::Path::new(&cmd.program).is_absolute());
        let via_env = default_shell_command();
        assert!(via_env.program.to_ascii_lowercase().ends_with("cmd.exe"));
        assert!(std::path::Path::new(&via_env.program).is_absolute());
    }

    /// v1.2.13 review (defense-in-depth): `LiveHost::spawn` resolves through
    /// the shared launchable resolver and fails closed with the exact reason;
    /// an unresolvable program must never reach the spawner as a bare name
    /// (a shadowing cwd `cmd.exe` on Windows, or a PATH re-search on Unix).
    #[test]
    fn live_host_spawn_fails_closed_on_unresolvable_program() {
        let cmd = PtyCommand {
            program: "ownmesh-test-no-such-binary-xyz".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };
        let err = LiveHost::spawn(&cmd, PtySize::default())
            .err()
            .expect("an unresolvable program must fail closed, never spawn a bare name");
        assert!(
            err.contains("resolve session program"),
            "the failure must name the unresolved program, got: {err}"
        );
    }

    /// P0-A review: `terminate_child_tree` must never report success before
    /// the child confirms exit. The supervisor untracks a host only on `Ok`
    /// and daemon transition recovery treats "not tracked" as authoritative
    /// proof of death, so an unreaped child reported as terminated could let
    /// an expired transition record be cleared while its sidecar is still
    /// alive. These tests pin the honest result contract with a fake child:
    /// already-exited returns `Ok` immediately, a child that exits after
    /// `kill` returns `Ok`, and a child that never confirms exit returns
    /// `Err` — keeping the host tracked for the next sweep.
    #[derive(Debug)]
    enum FakeChildState {
        AlreadyExited,
        ExitsAfterKill,
        NeverExits,
    }

    #[derive(Debug)]
    struct FakeChild {
        state: FakeChildState,
        kill_called: bool,
        kill_fails: bool,
    }

    impl portable_pty::ChildKiller for FakeChild {
        fn kill(&mut self) -> std::io::Result<()> {
            if self.kill_fails {
                return Err(std::io::Error::other("kill refused"));
            }
            self.kill_called = true;
            Ok(())
        }
        fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
            Box::new(FakeChild {
                state: FakeChildState::NeverExits,
                kill_called: false,
                kill_fails: self.kill_fails,
            })
        }
    }

    impl portable_pty::Child for FakeChild {
        fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
            match &self.state {
                FakeChildState::AlreadyExited => {
                    Ok(Some(portable_pty::ExitStatus::with_exit_code(0)))
                }
                FakeChildState::ExitsAfterKill => {
                    if self.kill_called {
                        Ok(Some(portable_pty::ExitStatus::with_exit_code(1)))
                    } else {
                        Ok(None)
                    }
                }
                FakeChildState::NeverExits => Ok(None),
            }
        }
        fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
            Ok(portable_pty::ExitStatus::with_exit_code(1))
        }
        fn process_id(&self) -> Option<u32> {
            None
        }
        #[cfg(windows)]
        fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            None
        }
    }

    #[test]
    fn terminate_child_tree_confirms_exit_before_ok() {
        // Already exited: no kill needed, Ok immediately.
        let mut exited = FakeChild {
            state: FakeChildState::AlreadyExited,
            kill_called: false,
            kill_fails: false,
        };
        assert!(terminate_child_tree(&mut exited, None).is_ok());

        // Exits after the kill signal: Ok only once try_wait confirms.
        let mut after_kill = FakeChild {
            state: FakeChildState::ExitsAfterKill,
            kill_called: false,
            kill_fails: false,
        };
        assert!(terminate_child_tree(&mut after_kill, None).is_ok());
        assert!(after_kill.kill_called, "the child must have been signalled");
    }

    #[test]
    fn terminate_child_tree_errors_when_exit_is_not_confirmed() {
        // Kill refused and the child still running: explicit Err naming the
        // cause — never a best-effort Ok.
        let mut refused = FakeChild {
            state: FakeChildState::NeverExits,
            kill_called: false,
            kill_fails: true,
        };
        let err = terminate_child_tree(&mut refused, None).unwrap_err();
        assert!(
            err.contains("child is still running"),
            "unconfirmed child must fail honestly: {err}"
        );

        // Kill succeeded but the child never confirms exit within the bounded
        // poll window: Err, so the supervisor keeps the host tracked.
        let mut never = FakeChild {
            state: FakeChildState::NeverExits,
            kill_called: false,
            kill_fails: false,
        };
        let err = terminate_child_tree(&mut never, None).unwrap_err();
        assert!(
            err.contains("did not confirm exit"),
            "bounded-poll timeout must fail honestly: {err}"
        );
    }

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
            // This unattended command deliberately has no terminal emulator
            // replying to cursor-position queries. A ConPTY backend that uses
            // PSEUDOCONSOLE_INHERIT_CURSOR stalls here after emitting ESC[6n.
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
        let marker_s = marker.to_string_lossy().replace('\\', "/");
        // Keep the write window past Darwin's bounded teardown confirmation
        // (up to five seconds). A 1s child vs 1.3s wait races on loaded GHA
        // macOS runners: Drop can still be signalling while sleep 1 finishes.
        let command = PtyCommand {
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                format!("sleep 8; printf survived > '{marker_s}'"),
            ],
            cwd: None,
            env: vec![],
        };

        let session = spawn_portable(&command, PtySize::default()).expect("spawn PTY child");
        drop(session);
        std::thread::sleep(Duration::from_millis(9_000));

        assert!(
            !marker.exists(),
            "child continued running after session drop"
        );
    }

    #[test]
    fn structured_pipes_keep_stdout_and_stderr_separate_and_bound_frames() {
        let cmd = if cfg!(windows) {
            PtyCommand {
                program: "cmd.exe".into(),
                args: vec!["/C".into(), "echo out & echo err 1>&2".into()],
                cwd: None,
                env: vec![],
            }
        } else {
            PtyCommand {
                program: "/bin/sh".into(),
                args: vec!["-c".into(), "printf out; printf err >&2".into()],
                cwd: None,
                env: vec![],
            }
        };
        let mut host = StructuredProcessHost::spawn(&cmd, PtySize::default()).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        let out = host.drain_stdout(64).unwrap().0;
        let err = host.drain_stderr(64).unwrap().0;
        assert!(String::from_utf8_lossy(&out).contains("out"));
        assert!(String::from_utf8_lossy(&err).contains("err"));
        assert!(host.write_frame(b"x").is_err());
        assert!(host.write_frame(&vec![b'x'; 64 * 1024 + 1]).is_err());
        host.terminate().unwrap();
    }
}
