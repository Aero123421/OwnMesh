//! OS-specific config / state / runtime path resolution.

use crate::error::{ConfigError, ConfigResult};
use std::env;
use std::path::PathBuf;

/// Resolved OwnMesh filesystem layout for the current user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnMeshPaths {
    /// Human-editable configuration directory (`config.toml`, `policy.toml`).
    pub config_dir: PathBuf,
    /// Durable local state (`state.db`, keystore fallback, backups).
    pub state_dir: PathBuf,
    /// Ephemeral runtime files (IPC sockets, daemon token).
    pub runtime_dir: PathBuf,
    /// Optional data/cache directory.
    pub cache_dir: PathBuf,
}

impl OwnMeshPaths {
    /// Resolve default paths for the current platform and environment.
    ///
    /// Environment overrides:
    /// - `OWNMESH_CONFIG_DIR`
    /// - `OWNMESH_STATE_DIR`
    /// - `OWNMESH_RUNTIME_DIR`
    /// - `OWNMESH_CACHE_DIR`
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] when the home / profile directory cannot be determined.
    pub fn discover() -> ConfigResult<Self> {
        let config_dir = env_path("OWNMESH_CONFIG_DIR").unwrap_or(default_config_dir()?);
        let state_dir = env_path("OWNMESH_STATE_DIR").unwrap_or(default_state_dir()?);
        let runtime_dir = env_path("OWNMESH_RUNTIME_DIR").unwrap_or(default_runtime_dir()?);
        let cache_dir = env_path("OWNMESH_CACHE_DIR").unwrap_or(default_cache_dir()?);
        Ok(Self {
            config_dir,
            state_dir,
            runtime_dir,
            cache_dir,
        })
    }

    /// Construct paths rooted under a single base (tests / portable mode).
    #[must_use]
    pub fn for_base(base: impl Into<PathBuf>) -> Self {
        let base = base.into();
        Self {
            config_dir: base.join("config"),
            state_dir: base.join("state"),
            runtime_dir: base.join("runtime"),
            cache_dir: base.join("cache"),
        }
    }

    /// Path to `config.toml`.
    #[must_use]
    pub fn config_file(&self) -> PathBuf {
        self.config_dir.join("config.toml")
    }

    /// Path to `policy.toml`.
    #[must_use]
    pub fn policy_file(&self) -> PathBuf {
        self.config_dir.join("policy.toml")
    }

    /// Path to local SQLite state database.
    #[must_use]
    pub fn state_db(&self) -> PathBuf {
        self.state_dir.join("state.db")
    }

    /// Directory for encrypted keystore fallback files.
    #[must_use]
    pub fn keystore_dir(&self) -> PathBuf {
        self.state_dir.join("keystore")
    }

    /// Ensure config/state/runtime/cache directories exist.
    ///
    /// # Errors
    ///
    /// Returns IO errors from `create_dir_all`.
    pub fn ensure_layout(&self) -> ConfigResult<()> {
        for dir in [
            &self.config_dir,
            &self.state_dir,
            &self.runtime_dir,
            &self.cache_dir,
            &self.keystore_dir(),
        ] {
            std::fs::create_dir_all(dir).map_err(|source| ConfigError::Io {
                path: Some(dir.clone()),
                source,
            })?;
        }
        Ok(())
    }
}

fn env_path(key: &str) -> Option<PathBuf> {
    env::var_os(key)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
}

fn home_dir() -> ConfigResult<PathBuf> {
    if let Some(h) = env::var_os("HOME").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(h));
    }
    if let Some(h) = env::var_os("USERPROFILE").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(h));
    }
    Err(ConfigError::Other(
        "unable to resolve user home directory".into(),
    ))
}

fn default_config_dir() -> ConfigResult<PathBuf> {
    #[cfg(windows)]
    {
        if let Some(base) = env::var_os("APPDATA").filter(|v| !v.is_empty()) {
            return Ok(PathBuf::from(base).join("OwnMesh"));
        }
        // Rare environments without APPDATA — fall back to profile\AppData\Roaming.
        Ok(home_dir()?.join("AppData").join("Roaming").join("OwnMesh"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home_dir()?.join("Library/Application Support/OwnMesh"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            Ok(PathBuf::from(xdg).join("ownmesh"))
        } else {
            Ok(home_dir()?.join(".config/ownmesh"))
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(home_dir()?.join("ownmesh/config"))
    }
}

fn default_state_dir() -> ConfigResult<PathBuf> {
    #[cfg(windows)]
    {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| ConfigError::Other("%LOCALAPPDATA% is not set".into()))?;
        Ok(base.join("OwnMesh"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home_dir()?.join("Library/Application Support/OwnMesh/state"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_STATE_HOME").filter(|v| !v.is_empty()) {
            Ok(PathBuf::from(xdg).join("ownmesh"))
        } else {
            Ok(home_dir()?.join(".local/state/ownmesh"))
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(home_dir()?.join("ownmesh/state"))
    }
}

fn default_runtime_dir() -> ConfigResult<PathBuf> {
    #[cfg(windows)]
    {
        // Prefer LOCALAPPDATA\OwnMesh\run for named-pipe token files.
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| ConfigError::Other("%LOCALAPPDATA% is not set".into()))?;
        Ok(base.join("OwnMesh").join("run"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home_dir()?.join("Library/Caches/OwnMesh/run"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
            Ok(PathBuf::from(xdg).join("ownmesh"))
        } else {
            Ok(default_state_dir()?.join("run"))
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(home_dir()?.join("ownmesh/run"))
    }
}

fn default_cache_dir() -> ConfigResult<PathBuf> {
    #[cfg(windows)]
    {
        let base = env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| ConfigError::Other("%LOCALAPPDATA% is not set".into()))?;
        Ok(base.join("OwnMesh").join("cache"))
    }
    #[cfg(target_os = "macos")]
    {
        Ok(home_dir()?.join("Library/Caches/OwnMesh"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if let Some(xdg) = env::var_os("XDG_CACHE_HOME").filter(|v| !v.is_empty()) {
            Ok(PathBuf::from(xdg).join("ownmesh"))
        } else {
            Ok(home_dir()?.join(".cache/ownmesh"))
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(home_dir()?.join("ownmesh/cache"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn for_base_layout() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        assert!(paths.config_file().starts_with(dir.path()));
        assert!(paths.keystore_dir().exists());
    }
}
