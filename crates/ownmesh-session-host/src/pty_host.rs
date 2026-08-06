//! Portable PTY/ConPTY spawn + read helpers.
//!
//! Uses `portable-pty` which selects ConPTY on Windows and openpty on POSIX.
//! Docs: https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session

use ownmesh_session::{PtyBackend, PtyCommand, PtySize, SessionHostHandle};
use portable_pty::{native_pty_system, CommandBuilder, PtySize as PortableSize};
use std::io::{Read, Write};
use std::sync::mpsc;
use std::sync::Mutex;
use std::time::Duration;

/// Live PTY session (or pipe fallback).
pub struct PtySession {
    pub handle: SessionHostHandle,
    kind: SessionKindInner,
}

enum SessionKindInner {
    Pty {
        reader: Mutex<Option<Box<dyn Read + Send>>>,
        writer: Mutex<Option<Box<dyn Write + Send>>>,
        child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
        _master: Box<dyn portable_pty::MasterPty + Send>,
    },
    Pipe {
        output: Mutex<Option<String>>,
    },
}

impl PtySession {
    pub fn writer_for_test(&self) -> Option<WriterRef<'_>> {
        match &self.kind {
            SessionKindInner::Pty { writer, .. } => Some(WriterRef { writer }),
            SessionKindInner::Pipe { .. } => None,
        }
    }
}

pub struct WriterRef<'a> {
    writer: &'a Mutex<Option<Box<dyn Write + Send>>>,
}

impl Write for WriterRef<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = self.writer.lock().map_err(lock_err)?;
        match g.as_mut() {
            Some(w) => w.write(buf),
            None => Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "no writer",
            )),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let mut g = self.writer.lock().map_err(lock_err)?;
        match g.as_mut() {
            Some(w) => w.flush(),
            None => Ok(()),
        }
    }
}

fn lock_err(e: std::sync::PoisonError<impl Sized>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
}

/// Spawn a PTY-backed process (pipe fallback on failure).
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

    let child = pair
        .slave
        .spawn_command(builder)
        .map_err(|e| format!("spawn: {e}"))?;
    // Drop slave so child I/O is only via master.
    drop(pair.slave);

    let pid = child.process_id();

    let reader = pair
        .master
        .try_clone_reader()
        .map_err(|e| format!("reader: {e}"))?;
    let writer = pair
        .master
        .take_writer()
        .map_err(|e| format!("writer: {e}"))?;

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

fn spawn_pipe_fallback(
    cmd: &PtyCommand,
    size: PtySize,
    pty_err: &str,
) -> Result<PtySession, String> {
    use std::process::{Command, Stdio};
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
    let output = c
        .output()
        .map_err(|e| format!("pty failed ({pty_err}); pipe fallback failed: {e}"))?;
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.stderr.is_empty() {
        text.push_str(&String::from_utf8_lossy(&output.stderr));
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

/// Read PTY output until child exits or `max_ms` elapses (0 = 5s default for safety).
pub fn read_until(session: &PtySession, max_ms: u64) -> Result<String, String> {
    match &session.kind {
        SessionKindInner::Pipe { output } => {
            let mut g = output.lock().map_err(|e| e.to_string())?;
            Ok(g.take().unwrap_or_default())
        }
        SessionKindInner::Pty {
            reader, child, ..
        } => {
            let max = if max_ms == 0 { 5_000 } else { max_ms };
            // Take reader into a background thread so blocking reads cannot hang the caller.
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
                            // Opportunistic send of progress
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
                        // Check child exit
                        if let Ok(mut ch) = child.lock() {
                            if let Ok(Some(_)) = ch.try_wait() {
                                // brief drain
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
                    // If child already exited and we have data, stop early.
                    if let Ok(mut ch) = child.lock() {
                        if let Ok(Some(_)) = ch.try_wait() {
                            break;
                        }
                    }
                }
            }
            // Best-effort kill if still running (test cleanup).
            if let Ok(mut ch) = child.lock() {
                if let Ok(None) = ch.try_wait() {
                    let _ = ch.kill();
                    let _ = ch.wait();
                }
            }
            Ok(String::from_utf8_lossy(&last).into_owned())
        }
    }
}
