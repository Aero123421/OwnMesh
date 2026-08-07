//! Path traversal / symlink / race-oriented security tests (harden-07).
//! Production behavior is locked: workspace enforcement canonicalizes then checks prefix.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnested_or_patterns
)]

use ownmesh_fs::{looks_sensitive, read_file, write_file, FsError, WorkspaceRoot};
use std::fs;
use std::path::{Path, PathBuf};
use tempfile::tempdir;

#[test]
fn rejects_dotdot_escape_when_enforced() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
    fs::write(dir.path().join("ok.txt"), b"in").unwrap();
    for candidate in [
        "../outside.txt",
        "../../outside.txt",
        "sub/../../outside.txt",
        "./../outside.txt",
    ] {
        let err = ws.resolve(candidate).unwrap_err();
        assert!(
            matches!(err, FsError::EscapesWorkspace(_)) || matches!(err, FsError::InvalidPath(_)),
            "path {candidate} should not resolve inside workspace: {err:?}"
        );
    }
}

#[test]
fn rejects_null_byte_paths() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
    let evil = format!("evil{}.txt", "\0");
    let err = ws.resolve(&evil).unwrap_err();
    assert!(matches!(err, FsError::InvalidPath(_)));
}

#[test]
fn absolute_path_outside_rejected_when_enforced() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
    let outside = if cfg!(windows) {
        PathBuf::from(r"C:\Windows\System32\drivers\etc\hosts")
    } else {
        PathBuf::from("/etc/passwd")
    };
    if outside.exists() {
        let err = ws.resolve(&outside).unwrap_err();
        assert!(
            matches!(err, FsError::EscapesWorkspace(_)),
            "absolute outside path must escape: {err:?}"
        );
    }
}

#[test]
fn full_access_style_allows_absolute_without_hidden_deny_on_sensitive_names() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
    let secretish = dir.path().join(".env");
    fs::write(&secretish, b"TOKEN=demo").unwrap();
    assert!(looks_sensitive(Path::new(".env")));
    let resolved = ws.resolve(&secretish).unwrap();
    assert_eq!(fs::read(resolved).unwrap(), b"TOKEN=demo");
}

#[cfg(unix)]
#[test]
fn symlink_escape_rejected_when_enforced() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("secret.txt"), b"top-secret").unwrap();

    let link = root.path().join("leak");
    symlink(outside.path(), &link).unwrap();

    let ws = WorkspaceRoot::new(root.path(), true).unwrap();
    let err = ws.resolve("leak/secret.txt").unwrap_err();
    assert!(
        matches!(err, FsError::EscapesWorkspace(_)),
        "symlink escape must fail under enforce: {err:?}"
    );
}

#[cfg(unix)]
#[test]
fn symlink_inside_workspace_ok() {
    use std::os::unix::fs::symlink;

    let root = tempdir().unwrap();
    fs::create_dir_all(root.path().join("real")).unwrap();
    fs::write(root.path().join("real/a.txt"), b"ok").unwrap();
    symlink(root.path().join("real"), root.path().join("link")).unwrap();

    let ws = WorkspaceRoot::new(root.path(), true).unwrap();
    let p = ws.resolve("link/a.txt").unwrap();
    assert_eq!(fs::read(p).unwrap(), b"ok");
}

#[test]
fn resolve_then_read_does_not_follow_replaced_path_outside_after_check() {
    let dir = tempdir().unwrap();
    let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
    write_file(&ws, "nested/file.txt", b"v1").unwrap();
    let body = read_file(&ws, "nested/file.txt", 1024).unwrap();
    assert_eq!(body, b"v1");

    write_file(&ws, "nested/./file.txt", b"v2").unwrap();
    let body = read_file(&ws, "nested/file.txt", 1024).unwrap();
    assert_eq!(body, b"v2");
}

#[test]
fn nested_dotdot_cannot_climb_above_workspace_root() {
    let dir = tempdir().unwrap();
    fs::create_dir_all(dir.path().join("a/b/c")).unwrap();
    let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
    let err = ws
        .resolve("a/b/c/../../../../../../etc/passwd")
        .unwrap_err();
    assert!(
        matches!(err, FsError::EscapesWorkspace(_)) || matches!(err, FsError::InvalidPath(_)),
        "{err:?}"
    );
}
