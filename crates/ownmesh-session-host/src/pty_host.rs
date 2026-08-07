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

    /// Stop and reap the child. `Drop` repeats this as a backstop on every error path.
    pub fn terminate_and_wait(&self) -> Result<(), String> {
        let SessionKindInner::Pty { child, .. } = &self.kind else {
            return Ok(());
        };
        let mut child = child
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        terminate_child(child.as_mut())
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        if let SessionKindInner::Pty { child, .. } = &mut self.kind {
            let child = child
                .get_mut()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let _ = terminate_child(child.as_mut());
        }
    }
}

fn write_stdin_line(writer: &mut dyn Write, line: &str) -> std::io::Result<()> {
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    writer.flush()
}

fn terminate_child(child: &mut (dyn portable_pty::Child + Send + Sync)) -> Result<(), String> {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return Ok(());
    }

    if let Err(kill_err) = child.kill() {
        // A kill may race with natural exit. Recheck before reporting failure, but
        // never block forever in wait when the kill itself did not succeed.
        return match child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => Err(format!("kill child: {kill_err}; child is still running")),
            Err(wait_err) => Err(format!(
                "kill child: {kill_err}; query child after kill failure: {wait_err}"
            )),
        };
    }

    child
        .wait()
        .map(|_| ())
        .map_err(|err| format!("wait for child: {err}"))
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

    // Set up all fallible host-side I/O before spawn so no post-spawn setup error can
    // lose ownership of a running child.
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
    // Drop slave so child I/O is only via master.
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
