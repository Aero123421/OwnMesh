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

use crate::SessionManager;
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
fn restrict_file_mode(path: &Path) -> Result<(), PersistError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| PersistError::Io(e.to_string()))?;
    }
    #[cfg(windows)]
    {
        // Best-effort: rely on user-profile inherited ACL (no chmod equivalent).
        let _ = path;
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
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, raw.as_bytes()).map_err(|e| PersistError::Io(e.to_string()))?;
    restrict_file_mode(&tmp)?;
    std::fs::rename(&tmp, path).map_err(|e| PersistError::Io(e.to_string()))?;
    // Re-apply on the final path so a pre-existing looser mode cannot linger
    // across platforms/filesystems where rename preserves destination metadata.
    restrict_file_mode(path)?;
    Ok(())
}

/// Load manager; missing file yields an empty manager.
///
/// Corrupt JSON or unreadable content returns [`PersistError`] — never silently
/// replaced with an empty manager.
pub fn load_manager(path: &Path) -> Result<SessionManager, PersistError> {
    if !path.exists() {
        return Ok(SessionManager::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| PersistError::Io(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| PersistError::Serde(e.to_string()))
}
