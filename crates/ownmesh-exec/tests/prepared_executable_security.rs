#![cfg(unix)]

use ownmesh_exec::{
    pin_executable, prepare_executable, run_prepared_command_cancellable, CommandKind,
    ExecutablePin, RunRequest,
};
use std::collections::HashMap;
use std::io::Write;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

const PREPARED_HELPER_MARKER_ENV: &str = "OWNMESH_PREPARED_HELPER_MARKER";

fn proxy_pins(path: &Path, kind: CommandKind) -> (ExecutablePin, ExecutablePin) {
    let invocation = pin_executable(path, kind).expect("pin invocation");
    let backing_path = std::fs::canonicalize(path).expect("canonical backing");
    let backing = pin_executable(&backing_path, kind).expect("pin backing");
    (invocation, backing)
}

fn request(program: &Path, args: &[&str]) -> RunRequest {
    RunRequest {
        kind: CommandKind::Structured,
        program: program.to_string_lossy().into_owned(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        cwd: None,
        env: HashMap::new(),
        stdin: None,
        timeout_ms: Some(5_000),
        max_output_bytes: 64 * 1024,
        idempotency_key: None,
    }
}

fn false_program() -> &'static Path {
    let bin = Path::new("/bin/false");
    if bin.is_file() {
        bin
    } else {
        Path::new("/usr/bin/false")
    }
}

fn copy_prepared_helper(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::copy(
        std::env::current_exe().expect("current integration-test executable"),
        path,
    )
    .expect("copy integration-test helper");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("make integration-test helper executable");
}

fn write_failing_replacement(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, b"#!/bin/sh\nexit 91\n").expect("write replacement executable");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
        .expect("make replacement executable");
}

fn prepared_helper_request(program: &Path, marker: &str) -> RunRequest {
    let mut req = request(
        program,
        &["--exact", "prepared_executable_test_helper", "--nocapture"],
    );
    req.env
        .insert(PREPARED_HELPER_MARKER_ENV.into(), marker.into());
    req
}

#[test]
fn prepared_executable_test_helper() {
    if let Ok(marker) = std::env::var(PREPARED_HELPER_MARKER_ENV) {
        std::io::stdout()
            .write_all(marker.as_bytes())
            .expect("write prepared helper marker");
    }
}

fn assert_prepare_refused(
    path: &Path,
    invocation: &ExecutablePin,
    backing: &ExecutablePin,
    staging_root: &Path,
) {
    let error = prepare_executable(path, invocation, backing, Some(staging_root))
        .err()
        .expect("changed invocation must be refused");
    let message = error.to_string();
    assert!(
        message.contains("identity")
            || message.contains("target")
            || message.contains("revalidation"),
        "unexpected preparation error: {message}"
    );
}

#[tokio::test]
async fn prepared_proxy_preserves_the_exact_approved_argv0() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("dispatch-by-this-name");
    symlink("/bin/sh", &alias).unwrap();
    let (invocation, backing) = proxy_pins(&alias, CommandKind::RawShell);
    let prepared = prepare_executable(&alias, &invocation, &backing, Some(temp.path())).unwrap();
    let req = request(&alias, &["-c", "printf '%s' \"$0\""]);

    let result = run_prepared_command_cancellable(&req, prepared, None, None)
        .await
        .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, alias.to_string_lossy());
}

#[tokio::test]
async fn replacement_after_preparation_cannot_change_the_executed_image() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("approved-image");
    let replacement = temp.path().join("replacement-image");
    copy_prepared_helper(&target);
    write_failing_replacement(&replacement);
    let alias = temp.path().join("approved-proxy");
    symlink(&target, &alias).unwrap();
    let (invocation, backing) = proxy_pins(&alias, CommandKind::Structured);
    let prepared = prepare_executable(&alias, &invocation, &backing, Some(temp.path())).unwrap();

    // This is the verify-to-exec window from OM-SEC-02. Linux executes the
    // retained descriptor and macOS executes the already-copied private image.
    std::fs::rename(&replacement, &target).unwrap();
    let req = prepared_helper_request(&alias, "prepared-image-ran");
    let result = run_prepared_command_cancellable(&req, prepared, None, None)
        .await
        .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("prepared-image-ran"));
}

#[tokio::test]
async fn in_place_write_after_preparation_cannot_change_the_executed_image() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("approved-image");
    copy_prepared_helper(&target);
    let (invocation, backing) = proxy_pins(&target, CommandKind::Structured);
    let prepared = prepare_executable(&target, &invocation, &backing, Some(temp.path())).unwrap();

    // An open descriptor to the original inode is not enough on Unix: another
    // writer can mutate that inode. The prepared Linux memfd is sealed and the
    // macOS private snapshot is already independent before this write.
    write_failing_replacement(&target);
    let result = run_prepared_command_cancellable(
        &prepared_helper_request(&target, "immutable-image-ran"),
        prepared,
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("immutable-image-ran"));
}

#[tokio::test]
async fn approved_shebang_script_keeps_its_prepared_contents() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let script = temp.path().join("approved-script");
    std::fs::write(&script, b"#!/bin/sh\nprintf approved-script-ran\n").unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (invocation, backing) = proxy_pins(&script, CommandKind::RawShell);
    let prepared = prepare_executable(&script, &invocation, &backing, Some(temp.path())).unwrap();

    std::fs::write(&script, b"#!/bin/sh\nprintf replaced-script-ran\n").unwrap();
    let result = run_prepared_command_cancellable(&request(&script, &[]), prepared, None, None)
        .await
        .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout, "approved-script-ran");
}

#[tokio::test]
async fn parent_directory_replacement_after_preparation_is_harmless() {
    let temp = tempfile::tempdir().unwrap();
    let parent = temp.path().join("approved-parent");
    std::fs::create_dir(&parent).unwrap();
    let target = parent.join("approved-image");
    copy_prepared_helper(&target);
    let (invocation, backing) = proxy_pins(&target, CommandKind::Structured);
    let prepared = prepare_executable(&target, &invocation, &backing, Some(temp.path())).unwrap();

    std::fs::rename(&parent, temp.path().join("moved-approved-parent")).unwrap();
    std::fs::create_dir(&parent).unwrap();
    write_failing_replacement(&target);
    let result = run_prepared_command_cancellable(
        &prepared_helper_request(&target, "parent-custody-ran"),
        prepared,
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert!(result.stdout.contains("parent-custody-ran"));
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn restricted_macos_platform_binary_executes_from_verified_backing() {
    let temp = tempfile::tempdir().unwrap();
    let program = Path::new("/bin/echo");
    let (invocation, backing) = proxy_pins(program, CommandKind::Structured);
    let prepared = prepare_executable(program, &invocation, &backing, Some(temp.path())).unwrap();

    let result = run_prepared_command_cancellable(
        &request(program, &["macos-platform-binary-ran"]),
        prepared,
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout.trim(), "macos-platform-binary-ran");
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn restricted_macos_proxy_retarget_after_preparation_is_harmless() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("restricted-platform-proxy");
    symlink("/bin/echo", &alias).unwrap();
    let (invocation, backing) = proxy_pins(&alias, CommandKind::Structured);
    let prepared = prepare_executable(&alias, &invocation, &backing, Some(temp.path())).unwrap();

    std::fs::remove_file(&alias).unwrap();
    symlink(false_program(), &alias).unwrap();
    let result = run_prepared_command_cancellable(
        &request(&alias, &["retarget-could-not-run"]),
        prepared,
        None,
        None,
    )
    .await
    .unwrap();

    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.stdout.trim(), "retarget-could-not-run");
}

#[test]
fn deleted_proxy_is_refused_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("deleted-proxy");
    symlink("/bin/echo", &alias).unwrap();
    let (invocation, backing) = proxy_pins(&alias, CommandKind::Structured);

    std::fs::remove_file(&alias).unwrap();
    assert_prepare_refused(&alias, &invocation, &backing, temp.path());
}

#[test]
fn retargeted_proxy_is_refused_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("retargeted-proxy");
    symlink("/bin/echo", &alias).unwrap();
    let (invocation, backing) = proxy_pins(&alias, CommandKind::Structured);

    std::fs::remove_file(&alias).unwrap();
    symlink(false_program(), &alias).unwrap();
    assert_prepare_refused(&alias, &invocation, &backing, temp.path());
}

#[test]
fn recreated_proxy_to_the_same_target_is_refused_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("recreated-proxy");
    symlink("/bin/echo", &alias).unwrap();
    let (invocation, backing) = proxy_pins(&alias, CommandKind::Structured);

    let recreated = temp.path().join("recreated-proxy-new-entry");
    symlink("/bin/echo", &recreated).unwrap();
    std::fs::rename(&recreated, &alias).unwrap();
    assert_prepare_refused(&alias, &invocation, &backing, temp.path());
}

#[test]
fn replaced_backing_is_refused_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("mutable-backing");
    let replacement = temp.path().join("other-backing");
    std::fs::copy("/bin/echo", &target).unwrap();
    std::fs::copy(false_program(), &replacement).unwrap();
    let (invocation, backing) = proxy_pins(&target, CommandKind::Structured);

    std::fs::rename(&replacement, &target).unwrap();
    assert_prepare_refused(&target, &invocation, &backing, temp.path());
}

#[test]
fn proxy_pin_serialization_binds_entry_identity_and_target() {
    let temp = tempfile::tempdir().unwrap();
    let alias = temp.path().join("serialized-proxy");
    symlink(PathBuf::from("/bin/echo"), &alias).unwrap();
    let (invocation, _) = proxy_pins(&alias, CommandKind::Structured);

    let value = serde_json::to_value(invocation).unwrap();
    assert!(value["path_device"].is_u64());
    assert!(value["path_inode"].is_u64());
    assert_eq!(value["link_target"], "/bin/echo");
}
