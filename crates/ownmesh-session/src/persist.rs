//! Detached session persistence (JSON on disk).
//!
//! # Permissions
//!
//! - **Unix:** parent directory mode `0700`; session file and its tmp sibling mode
//!   `0600`. Failures from `chmod`/`set_permissions` propagate as [`PersistError::Io`].
//! - **Windows:** no POSIX mode bits. Files inherit the creating user's profile ACL
//!   (typically user-only under the per-user app-data path). We do **not** rewrite a
//!   custom DACL here; callers should keep session state under a per-user directory.
//!   This is best-effort parity with Unix owner-only access.

use crate::{SessionManager, MAX_SESSIONS_FILE_BYTES};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PersistError {
    #[error("io: {0}")]
    Io(String),
    #[error("serde: {0}")]
    Serde(String),
}

/// Restrict directory to owner-only (`0700`) on Unix.
///
/// On Windows this is a documented no-op (profile ACL inheritance).
fn restrict_dir_mode(path: &Path) -> Result<(), PersistError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o700);
        std::fs::set_permissions(path, perms).map_err(|e| PersistError::Io(e.to_string()))?;
    }
    #[cfg(windows)]
    {
        // Best-effort: rely on user-profile inherited ACL (no chmod equivalent).
        let _ = path;
    }
    Ok(())
}

/// Restrict file to owner-only (`0600`) on Unix.
///
/// On Windows this is a documented no-op (profile ACL inheritance).
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn restrict_file_mode(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        // Best-effort: rely on user-profile inherited ACL (no chmod equivalent).
        let _ = file;
    }
    Ok(())
}

/// Save manager snapshot.
///
/// Creates the parent directory if needed and applies restrictive permissions
/// (Unix: dir `0700`, tmp + final file `0600`). IO and serde failures are always
/// returned as [`PersistError`] — never swallowed or replaced with a silent no-op.
pub fn save_manager(path: &Path, mgr: &SessionManager) -> Result<(), PersistError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|e| PersistError::Io(e.to_string()))?;
            restrict_dir_mode(parent)?;
        }
    }
    let raw = serde_json::to_string_pretty(mgr).map_err(|e| PersistError::Serde(e.to_string()))?;
    if raw.len() as u64 > MAX_SESSIONS_FILE_BYTES {
        return Err(PersistError::Io(format!(
            "sessions snapshot exceeds {MAX_SESSIONS_FILE_BYTES} byte budget ({})",
            raw.len()
        )));
    }
    // Permissions are applied to the sibling temp before its contents are
    // written. Any chmod/write/sync error therefore occurs before commit.
    // The pinned Rust 1.92 Windows rename replaces in one operation; the
    // destination is never pre-deleted.
    ownmesh_persist::write_atomically_with(path, raw.as_bytes(), restrict_file_mode)
        .map_err(|e| PersistError::Io(e.to_string()))
}

/// Load manager; missing file yields an empty manager.
///
/// Corrupt JSON or unreadable content returns [`PersistError`] — never silently
/// replaced with an empty manager. Oversized files fail closed before allocation.
pub fn load_manager(path: &Path) -> Result<SessionManager, PersistError> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SessionManager::new());
        }
        Err(err) => return Err(PersistError::Io(err.to_string())),
    };
    if meta.len() > MAX_SESSIONS_FILE_BYTES {
        return Err(PersistError::Io(format!(
            "sessions file exceeds {MAX_SESSIONS_FILE_BYTES} byte budget ({})",
            meta.len()
        )));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| PersistError::Io(e.to_string()))?;
    let mut mgr: SessionManager =
        serde_json::from_str(&raw).map_err(|e| PersistError::Serde(e.to_string()))?;
    mgr.enforce_loaded_budgets();
    Ok(mgr)
}
