//! Terminal-lifecycle smoke tests for the interactive TUI.
//!
//! These spawn the real `ownmesh-tui` binary and verify terminal-state
//! contracts that unit tests cannot reach:
//!
//! - Ctrl+C exits promptly from the dashboard with a successful status and a
//!   restored terminal (issue #136: raw mode swallows the usual SIGINT
//!   gesture).
//! - Non-interactive invocations without stdin/stdout TTYs fail closed with
//!   usage guidance instead of starting the UI (issue #137).
//! - On Windows/ConPTY, closing the controlling pseudoconsole terminates the
//!   loop promptly (issue #137 read-error branch). This is POSIX-skipped:
//!   there the kernel raises SIGHUP on master close, which terminates the
//!   child regardless of application handling, so the assertion cannot
//!   distinguish the controlled-exit path; the duplicated reader fd also
//!   keeps the pty alive in this harness.
//!
//! The platform pins mirror `ownmesh-session-host`: Darwin teardown needs
//! portable-pty 0.9, Windows stays on 0.8.1 (`ConPTY` cursor handshake).

#![forbid(unsafe_code)]

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);
/// Alternate-screen enter sequence: proves raw mode is already active, so a
/// following Ctrl+C is delivered as a key event rather than SIGINT.
const ALTERNATE_SCREEN_MARKER: &[u8] = b"\x1b[?1049h";
/// Alternate-screen leave sequence: proves the clean-quit path restored the
/// user's terminal before exiting (#137 restore contract).
const RESTORE_SCREEN_MARKER: &[u8] = b"\x1b[?1049l";

struct TuiProcess {
    child: Box<dyn Child + Send + Sync>,
    master: Option<Box<dyn MasterPty + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    output: Arc<Mutex<Vec<u8>>>,
}

impl Drop for TuiProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn isolated_env(command: &mut CommandBuilder, base: &std::path::Path) {
    for (name, subdir) in [
        ("OWNMESH_CONFIG_DIR", "config"),
        ("OWNMESH_STATE_DIR", "state"),
        ("OWNMESH_RUNTIME_DIR", "runtime"),
        ("OWNMESH_CACHE_DIR", "cache"),
    ] {
        let dir = base.join(subdir);
        std::fs::create_dir_all(&dir).expect("create isolated dir");
        command.env(name, dir.as_os_str());
    }
}

fn spawn_tui(base: &std::path::Path) -> TuiProcess {
    let pair = native_pty_system()
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("open pty");

    let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_ownmesh-tui"));
    command.cwd(base);
    isolated_env(&mut command, base);

    let child = pair.slave.spawn_command(command).expect("spawn tui");
    let reader = pair.master.try_clone_reader().expect("clone reader");
    let writer = pair.master.take_writer().expect("take writer");

    let output: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&output);
    std::thread::spawn(move || {
        let mut reader = reader;
        let mut chunk = [0u8; 4096];
        loop {
            match reader.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .expect("output lock")
                    .extend_from_slice(&chunk[..n]),
            }
        }
    });

    TuiProcess {
        child,
        master: Some(pair.master),
        writer: Some(writer),
        output,
    }
}

/// Block until `marker` appears in the TUI's terminal output.
fn wait_for_marker(tui: &TuiProcess, marker: &[u8], what: &str) {
    let started = Instant::now();
    loop {
        let contains = {
            let guard = tui.output.lock().expect("output lock");
            guard.windows(marker.len()).any(|w| w == marker)
        };
        if contains {
            return;
        }
        assert!(
            started.elapsed() < STARTUP_TIMEOUT,
            "TUI did not {what} in time; output:\n{}",
            dump_output(tui)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_until_drawn(tui: &TuiProcess) {
    wait_for_marker(tui, ALTERNATE_SCREEN_MARKER, "enter the alternate screen");
}

fn wait_for_exit(tui: &mut TuiProcess) -> Option<portable_pty::ExitStatus> {
    let started = Instant::now();
    loop {
        match tui.child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) => {}
            Err(err) => panic!("try_wait failed: {err}; output:\n{}", dump_output(tui)),
        }
        if started.elapsed() >= EXIT_TIMEOUT {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn send_ctrl_c(tui: &mut TuiProcess) {
    let writer = tui.writer.as_mut().expect("writer");
    writer.write_all(b"\x03").expect("write ctrl+c");
    writer.flush().expect("flush ctrl+c");
}

fn dump_output(tui: &TuiProcess) -> String {
    let guard = tui.output.lock().expect("output lock");
    String::from_utf8_lossy(&guard).to_string()
}

#[test]
fn ctrl_c_exits_promptly_from_the_dashboard() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut tui = spawn_tui(dir.path());
    wait_until_drawn(&tui);
    send_ctrl_c(&mut tui);

    let status = wait_for_exit(&mut tui).unwrap_or_else(|| {
        panic!(
            "Ctrl+C did not terminate the TUI; output:\n{}",
            dump_output(&tui)
        )
    });
    assert!(
        status.success(),
        "Ctrl+C must be a clean quit (exit 0), got: {status}"
    );
    // The clean-quit path must restore the terminal, not just exit.
    wait_for_marker(&tui, RESTORE_SCREEN_MARKER, "restore the alternate screen");
}

#[test]
fn non_tty_invocation_fails_closed_with_usage_guidance() {
    // stdin/stdout are pipes here, not terminals: the TUI must refuse to
    // start instead of entering raw mode against a dead surface (#137).
    let output = Command::new(env!("CARGO_BIN_EXE_ownmesh-tui"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("spawn ownmesh-tui with piped stdio");
    assert_eq!(
        output.status.code(),
        Some(2),
        "expected UsageConfig refusal; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("requires an interactive terminal"),
        "refusal must explain the TTY requirement: {stderr}"
    );
}

#[cfg(windows)]
#[test]
fn closing_the_controlling_conpty_terminates_the_loop() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut tui = spawn_tui(dir.path());
    wait_until_drawn(&tui);

    // Drop the input side and then the master: the console session ends and
    // poll/read fail, so the interactive loop must end instead of spinning
    // forever (#137). Exit status is intentionally not asserted: teardown may
    // surface as either a clean error exit or console-host termination.
    tui.writer.take();
    drop(tui.master.take());

    let exited = wait_for_exit(&mut tui).is_some();
    assert!(
        exited,
        "losing the terminal must terminate the TUI; output:\n{}",
        dump_output(&tui)
    );
}
