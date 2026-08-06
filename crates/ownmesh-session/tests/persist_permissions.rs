//! Permission hardening and error propagation for session persistence (sec-05 / req 7).

use ownmesh_session::{load_manager, save_manager, PersistError, SessionManager};
use std::fs;
use tempfile::tempdir;

#[test]
fn save_roundtrip_ok() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("sessions.json");
    let mgr = SessionManager::new();
    save_manager(&path, &mgr).expect("save");
    let loaded = load_manager(&path).expect("load");
    assert_eq!(
        serde_json::to_string(&mgr).unwrap(),
        serde_json::to_string(&loaded).unwrap()
    );
}

#[test]
fn load_missing_file_yields_empty_manager() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("does-not-exist.json");
    let loaded = load_manager(&path).expect("missing is ok");
    let empty = SessionManager::new();
    assert_eq!(
        serde_json::to_string(&loaded).unwrap(),
        serde_json::to_string(&empty).unwrap()
    );
}

#[test]
fn load_corrupt_json_returns_serde_error() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("broken.json");
    fs::write(&path, "{not-valid-json").unwrap();
    let err = load_manager(&path).expect_err("corrupt must not become empty");
    match err {
        PersistError::Serde(msg) => assert!(!msg.is_empty(), "serde message present"),
        other => panic!("expected PersistError::Serde, got {other:?}"),
    }
}

#[test]
fn load_unreadable_path_returns_io_error() {
    // Point at a directory so read_to_string fails with an IO error.
    let dir = tempdir().unwrap();
    let err = load_manager(dir.path()).expect_err("directory is not a session file");
    match err {
        PersistError::Io(msg) => assert!(!msg.is_empty(), "io message present"),
        other => panic!("expected PersistError::Io, got {other:?}"),
    }
}

#[test]
fn save_to_unwritable_parent_returns_io_error() {
    let dir = tempdir().unwrap();
    // Nested under a path component that is a regular file → create_dir_all fails.
    let blocker = dir.path().join("not-a-dir");
    fs::write(&blocker, b"x").unwrap();
    let path = blocker.join("sessions.json");
    let mgr = SessionManager::new();
    let err = save_manager(&path, &mgr).expect_err("must propagate IO failure");
    match err {
        PersistError::Io(msg) => assert!(!msg.is_empty(), "io message present"),
        other => panic!("expected PersistError::Io, got {other:?}"),
    }
}

#[cfg(unix)]
mod unix_permissions {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn save_sets_file_0600_and_parent_dir_0700() {
        let dir = tempdir().unwrap();
        // Use a nested parent so we own the directory we chmod.
        let parent = dir.path().join("state");
        let path = parent.join("sessions.json");
        let mgr = SessionManager::new();
        save_manager(&path, &mgr).expect("save");

        assert!(path.is_file());
        assert_eq!(mode_of(&path), 0o600, "session file must be 0600");
        assert_eq!(mode_of(&parent), 0o700, "parent dir must be 0700");

        // tmp sibling must not remain after successful rename.
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), "tmp file must be renamed away");
    }

    #[test]
    fn save_reapplies_0600_over_preexisting_loose_file() {
        let dir = tempdir().unwrap();
        let parent = dir.path().join("state");
        fs::create_dir_all(&parent).unwrap();
        let path = parent.join("sessions.json");

        // Pre-create a world-readable file that save will replace via rename.
        fs::write(&path, b"{}").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(mode_of(&path), 0o644);

        let mgr = SessionManager::new();
        save_manager(&path, &mgr).expect("save");
        assert_eq!(
            mode_of(&path),
            0o600,
            "final file must be tightened to 0600"
        );
    }

    #[test]
    fn tmp_is_0600_before_rename_when_rename_target_blocked() {
        // Exercise restrict_file_mode on the tmp path: write tmp, then make the
        // destination a directory so rename fails; tmp must already be 0600 and
        // the error must propagate (not swallowed).
        let dir = tempdir().unwrap();
        let parent = dir.path().join("state");
        fs::create_dir_all(&parent).unwrap();
        // Destination path exists as a directory → rename(file → dir) fails on Unix.
        let path = parent.join("sessions.json");
        fs::create_dir(&path).unwrap();

        let mgr = SessionManager::new();
        let err = save_manager(&path, &mgr).expect_err("rename must fail");
        match err {
            PersistError::Io(msg) => assert!(!msg.is_empty()),
            other => panic!("expected PersistError::Io, got {other:?}"),
        }

        let tmp = path.with_extension("tmp");
        assert!(tmp.is_file(), "tmp should remain after failed rename");
        assert_eq!(
            mode_of(&tmp),
            0o600,
            "tmp must be 0600 even when rename fails"
        );
    }
}
