//! OS-specific config / state / runtime path resolution.

use crate::error::{ConfigError, ConfigResult};
use std::env;
use std::path::PathBuf;

/// Resolved `OwnMesh` filesystem layout for the current user.
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

    /// Path to local `SQLite` state database.
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
    /// Directories are created owner-only on Unix so the layout is valid under
    /// any umask; the daemon custody attestation rejects group/world-writable
    /// ancestors.
    ///
    /// # Errors
    ///
    /// Returns IO errors from directory creation.
    pub fn ensure_layout(&self) -> ConfigResult<()> {
        for dir in [
            &self.config_dir,
            &self.state_dir,
            &self.runtime_dir,
            &self.cache_dir,
            &self.keystore_dir(),
        ] {
            create_dir_owner_only(dir).map_err(|source| ConfigError::Io {
                path: Some(dir.clone()),
                source,
            })?;
        }
        Ok(())
    }
}

/// Create a directory tree with owner-only permissions on Unix, independent of
/// the process umask.
///
/// OwnMesh's config/state/runtime/cache directories hold credentials and
/// custody-validated state. The daemon's custody attestation rejects
/// group/world-writable ancestors (`validate_parent_custody` in ownmesh-ipc),
/// so a umask such as `002` that makes `create_dir_all` produce `0775`
/// directories would otherwise prevent the daemon from starting. Creating the
/// tree with mode `0700` keeps the layout correct-by-construction; existing
/// directories are left untouched (their ownership is attested separately).
#[cfg(unix)]
fn create_dir_owner_only(dir: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir)
}

#[cfg(not(unix))]
fn create_dir_owner_only(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)
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
        } else if let Some(runtime) = linux_user_runtime_dir() {
            Ok(runtime)
        } else {
            Ok(default_state_dir()?.join("run"))
        }
    }
    #[cfg(not(any(windows, unix)))]
    {
        Ok(home_dir()?.join("ownmesh/run"))
    }
}

/// Owner-only `/run/user/<uid>` when `XDG_RUNTIME_DIR` is unset but the
/// standard user-runtime directory already exists. Matches the systemd
/// `--user` unit's `OWNMESH_RUNTIME_DIR` without requiring shell-profile
/// edits.
#[cfg(all(unix, not(target_os = "macos")))]
fn linux_user_runtime_dir() -> Option<PathBuf> {
    let uid = rustix::process::geteuid().as_raw();
    let base = PathBuf::from("/run/user").join(uid.to_string());
    if !trusted_linux_runtime_base(&base, uid) {
        return None;
    }
    let ownmesh = base.join("ownmesh");
    // Only switch when the systemd-style dir already exists so a headless
    // install that baked state_dir/run into the unit keeps working.
    ownmesh.is_dir().then_some(ownmesh)
}

#[cfg(all(unix, not(target_os = "macos")))]
fn trusted_linux_runtime_base(path: &std::path::Path, expected_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    meta.file_type().is_dir() && meta.uid() == expected_uid && meta.mode() & 0o077 == 0
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

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn trusted_linux_runtime_base_requires_owner_only_dir() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let mode = |bits| std::fs::Permissions::from_mode(bits);
        std::fs::set_permissions(dir.path(), mode(0o700)).unwrap();
        assert!(trusted_linux_runtime_base(dir.path(), uid));
        std::fs::set_permissions(dir.path(), mode(0o755)).unwrap();
        assert!(!trusted_linux_runtime_base(dir.path(), uid));
        assert!(!trusted_linux_runtime_base(
            &dir.path().join("missing"),
            uid
        ));
        assert!(!trusted_linux_runtime_base(dir.path(), uid.wrapping_add(1)));
        let target = dir.path().join("real");
        std::fs::create_dir(&target).unwrap();
        std::fs::set_permissions(&target, mode(0o700)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            !trusted_linux_runtime_base(&link, uid),
            "a symlink must not count as the trusted runtime base"
        );
    }

    /// Regression: `ensure_layout` must create owner-only directories even
    /// under the most permissive umask (000). The daemon custody attestation
    /// rejects group/world-writable ancestors, so a umask-dependent layout
    /// would prevent startup on systems with umask 002/000.
    #[cfg(unix)]
    #[test]
    fn ensure_layout_is_owner_only_under_permissive_umask() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "OWNMESH_LAYOUT_UMASK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            // Parent: re-run this exact test in a child whose umask is 000 so
            // `create_dir_all` would produce 0777 directories if the layout
            // creation were umask-dependent.
            let exe = std::env::current_exe().expect("current test executable");
            let output = std::process::Command::new("sh")
                .arg("-c")
                .arg(
                    "umask 000; exec \"$0\" --exact \
                     paths::tests::ensure_layout_is_owner_only_under_permissive_umask \
                     --nocapture",
                )
                .arg(exe)
                .env(CHILD, "1")
                .output()
                .expect("run umask-000 child");
            assert!(
                output.status.success(),
                "umask-000 child failed\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        // Child: umask is 000 here.
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        for d in [
            &paths.config_dir,
            &paths.state_dir,
            &paths.runtime_dir,
            &paths.cache_dir,
            &paths.keystore_dir(),
        ] {
            let mode = std::fs::metadata(d).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o077,
                0,
                "{} must be owner-only under umask 000, got mode {:o}",
                d.display(),
                mode
            );
        }
    }
}
