//! Detached session persistence (JSON on disk).

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

/// Save a manager snapshot.
///
/// # Errors
///
/// Returns [`PersistError::Serde`] if serialization fails, or
/// [`PersistError::Io`] if creating directories, writing, or renaming fails.
pub fn save_manager(path: &Path, mgr: &SessionManager) -> Result<(), PersistError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| PersistError::Io(e.to_string()))?;
    }
    let raw = serde_json::to_string_pretty(mgr).map_err(|e| PersistError::Serde(e.to_string()))?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, raw).map_err(|e| PersistError::Io(e.to_string()))?;
    std::fs::rename(&tmp, path).map_err(|e| PersistError::Io(e.to_string()))?;
    Ok(())
}

/// Load a manager; a missing file yields an empty manager.
///
/// # Errors
///
/// Returns [`PersistError::Io`] if reading fails, or [`PersistError::Serde`]
/// if the snapshot is not valid JSON for a session manager.
pub fn load_manager(path: &Path) -> Result<SessionManager, PersistError> {
    if !path.exists() {
        return Ok(SessionManager::new());
    }
    let raw = std::fs::read_to_string(path).map_err(|e| PersistError::Io(e.to_string()))?;
    serde_json::from_str(&raw).map_err(|e| PersistError::Serde(e.to_string()))
}
