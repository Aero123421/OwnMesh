#![cfg(windows)]

use ownmesh_exec::{
    pin_executable, prepare_executable, prepare_executable_with_interpreter,
    run_prepared_command_cancellable, windows_system_cmd_exe, CommandKind, RunRequest,
};
use std::collections::HashMap;
use std::path::Path;

fn compile_multicall_fixture(output: &Path) {
    let source =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../test-fixtures/executable-multicall.rs");
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let status = std::process::Command::new(rustc)
        .arg("--edition=2021")
        .arg("-C")
        .arg("debuginfo=0")
        .arg(source)
        .arg("-o")
        .arg(output)
        .status()
        .expect("launch rustc for deterministic multicall fixture");
    assert!(status.success(), "compile deterministic multicall fixture");
}

fn request(program: &Path, arg: &str) -> RunRequest {
    RunRequest {
        kind: CommandKind::Structured,
        program: program.to_string_lossy().into_owned(),
        args: vec![arg.to_owned()],
        cwd: None,
        env: HashMap::new(),
        stdin: None,
        timeout_ms: Some(5_000),
        max_output_bytes: 64 * 1024,
        idempotency_key: None,
    }
}

#[tokio::test]
async fn prepared_handle_blocks_replace_write_and_parent_rename_until_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("approved-parent");
    std::fs::create_dir(&parent).unwrap();
    let approved = parent.join("echo.exe");
    compile_multicall_fixture(&approved);
    let pin = pin_executable(&approved, CommandKind::Structured).unwrap();
    let prepared = prepare_executable(&approved, &pin, &pin, Some(temp.path())).unwrap();

    assert!(
        std::fs::remove_file(&approved).is_err(),
        "prepared image must deny atomic replacement"
    );
    assert!(
        std::fs::OpenOptions::new()
            .write(true)
            .open(&approved)
            .is_err(),
        "prepared image must deny in-place writes"
    );
    assert!(
        std::fs::rename(&parent, temp.path().join("moved-parent")).is_err(),
        "prepared ancestry must deny namespace replacement"
    );

    let result = run_prepared_command_cancellable(
        &request(&approved, "windows-lock-ok"),
        prepared,
        None,
        None,
    )
    .await
    .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, "windows-lock-ok\n");
}

#[tokio::test]
async fn prepared_batch_holds_script_and_cmd_interpreter_through_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("approved.cmd");
    std::fs::write(&script, b"@echo off\r\necho batch-%1\r\n").unwrap();
    let script_pin = pin_executable(&script, CommandKind::RawShell).unwrap();
    let cmd = std::path::PathBuf::from(windows_system_cmd_exe(
        std::env::var("SystemRoot").ok().as_deref(),
    ));
    let cmd_pin = pin_executable(&cmd, CommandKind::RawShell).unwrap();
    let prepared = prepare_executable_with_interpreter(
        &script,
        &script_pin,
        &script_pin,
        Some(&cmd_pin),
        Some(temp.path()),
    )
    .unwrap();

    assert!(
        std::fs::remove_file(&script).is_err(),
        "prepared batch script must deny replacement"
    );
    let result = run_prepared_command_cancellable(&request(&script, "ok"), prepared, None, None)
        .await
        .unwrap();
    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("batch-ok"), "{}", result.stdout);
}

#[test]
fn replaced_windows_image_is_refused_before_preparation() {
    let temp = tempfile::tempdir().unwrap();
    let approved = temp.path().join("echo.exe");
    let replacement = temp.path().join("replacement.exe");
    compile_multicall_fixture(&approved);
    compile_multicall_fixture(&replacement);
    let pin = pin_executable(&approved, CommandKind::Structured).unwrap();

    std::fs::remove_file(&approved).unwrap();
    std::fs::rename(&replacement, &approved).unwrap();
    assert!(prepare_executable(&approved, &pin, &pin, Some(temp.path())).is_err());
}

#[test]
fn retargeted_windows_junction_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let first = temp.path().join("first");
    let second = temp.path().join("second");
    std::fs::create_dir(&first).unwrap();
    std::fs::create_dir(&second).unwrap();
    compile_multicall_fixture(&first.join("echo.exe"));
    compile_multicall_fixture(&second.join("echo.exe"));
    let junction = temp.path().join("tool-root");
    create_junction(&junction, &first);
    let invocation = junction.join("echo.exe");
    let invocation_pin = pin_executable(&invocation, CommandKind::Structured).unwrap();
    let backing_path = std::fs::canonicalize(&invocation).unwrap();
    let backing_pin = pin_executable(&backing_path, CommandKind::Structured).unwrap();

    std::fs::remove_dir(&junction).unwrap();
    create_junction(&junction, &second);
    assert!(prepare_executable(
        &invocation,
        &invocation_pin,
        &backing_pin,
        Some(temp.path()),
    )
    .is_err());
}

fn create_junction(link: &Path, target: &Path) {
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/s", "/c", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .status()
        .expect("launch mklink");
    assert!(status.success(), "create Windows junction");
}
