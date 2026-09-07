//! The non-TTY preflight must run before path creation or daemon access.

#![forbid(unsafe_code)]

use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn piped_startup_does_not_create_any_layout_directories() {
    let base = tempfile::tempdir().expect("isolated paths");
    let mut command = Command::new(env!("CARGO_BIN_EXE_ownmesh-tui"));
    for (key, directory) in [
        ("OWNMESH_CONFIG_DIR", "config"),
        ("OWNMESH_STATE_DIR", "state"),
        ("OWNMESH_RUNTIME_DIR", "runtime"),
        ("OWNMESH_CACHE_DIR", "cache"),
    ] {
        command.env(key, base.path().join(directory));
    }
    let mut child = command
        .env_remove(ownmesh_ipc::CLIENT_CREDENTIAL_ENV)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn isolated TUI");
    let started = Instant::now();
    loop {
        if child.try_wait().expect("poll TUI").is_some() {
            break;
        }
        if started.elapsed() >= Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("non-TTY preflight did not exit within its deadline");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let output = child.wait_with_output().expect("collect TUI output");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("requires an interactive terminal"), "{stderr}");
    assert!(stderr.contains("ownmesh-tui --status"), "{stderr}");
    assert!(output.stdout.is_empty());
    assert_eq!(std::fs::read_dir(base.path()).expect("read fixture").count(), 0);
}
