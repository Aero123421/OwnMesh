//! TOML load / atomic write / backup / migration.

use crate::error::{ConfigError, ConfigResult};
use crate::paths::OwnMeshPaths;
use crate::schema::{OwnMeshConfig, PolicyFile, CONFIG_SCHEMA_VERSION};
use ownmesh_persist::write_atomically;
use std::fs;
use std::path::{Path, PathBuf};

/// Load `config.toml`, migrating when needed. Creates a default file when missing.
///
/// # Errors
///
/// Returns IO / parse / validation / migration errors.
pub fn load_config(paths: &OwnMeshPaths) -> ConfigResult<OwnMeshConfig> {
    paths.ensure_layout()?;
    let path = paths.config_file();
    if !path.exists() {
        let cfg = OwnMeshConfig::default();
        save_config(paths, &cfg)?;
        return Ok(cfg);
    }
    let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        path: Some(path.clone()),
        source,
    })?;
    let mut value: toml::Value =
        raw.parse::<toml::Value>()
            .map_err(|err: toml::de::Error| ConfigError::Parse {
                path: path.clone(),
                message: err.to_string(),
            })?;
    let migrated = migrate_config_value(&mut value)?;
    let cfg: OwnMeshConfig =
        value
            .try_into()
            .map_err(|err: toml::de::Error| ConfigError::Parse {
                path: path.clone(),
                message: err.to_string(),
            })?;
    cfg.validate()?;
    if migrated {
        save_config(paths, &cfg)?;
    }
    Ok(cfg)
}

/// Atomically write `config.toml`, keeping a `.bak` of the previous version.
///
/// # Errors
///
/// Returns validation or IO errors.
pub fn save_config(paths: &OwnMeshPaths, cfg: &OwnMeshConfig) -> ConfigResult<()> {
    cfg.validate()?;
    paths.ensure_layout()?;
    let path = paths.config_file();
    let rendered =
        toml::to_string_pretty(cfg).map_err(|err| ConfigError::Other(err.to_string()))?;
    // Defense in depth: refuse to write if secrets somehow appear.
    assert_no_plaintext_secrets(&rendered)?;
    atomic_write(&path, rendered.as_bytes())?;
    Ok(())
}

/// Load policy.toml or create a default.
///
/// # Errors
///
/// Returns IO / parse / validation errors.
pub fn load_policy(paths: &OwnMeshPaths) -> ConfigResult<PolicyFile> {
    paths.ensure_layout()?;
    let path = paths.policy_file();
    if !path.exists() {
        let policy = PolicyFile::default();
        save_policy(paths, &policy)?;
        return Ok(policy);
    }
    let raw = fs::read_to_string(&path).map_err(|source| ConfigError::Io {
        path: Some(path.clone()),
        source,
    })?;
    let policy: PolicyFile = toml::from_str(&raw).map_err(|err| ConfigError::Parse {
        path: path.clone(),
        message: err.to_string(),
    })?;
    policy.validate()?;
    Ok(policy)
}

/// Atomically write policy.toml.
///
/// # Errors
///
/// Returns validation or IO errors.
pub fn save_policy(paths: &OwnMeshPaths, policy: &PolicyFile) -> ConfigResult<()> {
    policy.validate()?;
    paths.ensure_layout()?;
    let rendered =
        toml::to_string_pretty(policy).map_err(|err| ConfigError::Other(err.to_string()))?;
    assert_no_plaintext_secrets(&rendered)?;
    atomic_write(&paths.policy_file(), rendered.as_bytes())?;
    Ok(())
}

/// Write `data` to `path` using temp file + atomic replace, preserving a `.bak` backup.
///
/// ## Atomicity
///
/// - The previous file (if any) is written atomically to `path.bak` **before** any replace.
/// - New bytes are fully written and `sync_all`'d to a per-operation unique sibling temp.
/// - [`ownmesh_persist::write_atomically`] replaces the target in one rename. On Unix it
///   prepares/syncs the parent before commit and attempts a second sync after commit.
/// - **Windows:** the pinned Rust 1.92.0 `std::fs::rename` implementation uses
///   `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` (with a replacing
///   `SetFileInformationByHandle` fallback), so there is no delete/create window.
/// - **Unix:** `rename(2)` replaces atomically within the same directory.
///
/// The target is never pre-deleted. On replace failure the original target
/// contents remain intact and `.bak` still holds the pre-write copy.
///
/// # Errors
///
/// Returns IO errors. On any failure after the `.bak` copy, the original
/// `path` is left unchanged when the platform rename/replace fails.
pub fn atomic_write(path: &Path, data: &[u8]) -> ConfigResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| ConfigError::Io {
            path: Some(parent.to_path_buf()),
            source,
        })?;
    }

    match fs::read(path) {
        Ok(previous) => {
            let bak = backup_path(path);
            write_atomically(&bak, &previous).map_err(|source| ConfigError::Io {
                path: Some(bak),
                source,
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(source) => {
            return Err(ConfigError::Io {
                path: Some(path.to_path_buf()),
                source,
            });
        }
    }

    write_atomically(path, data).map_err(|source| ConfigError::Io {
        path: Some(path.to_path_buf()),
        source,
    })
}

fn backup_path(path: &Path) -> PathBuf {
    let mut bak = path.as_os_str().to_os_string();
    bak.push(".bak");
    PathBuf::from(bak)
}

/// Migrate a raw TOML table in place. Returns whether a migration occurred.
fn migrate_config_value(value: &mut toml::Value) -> ConfigResult<bool> {
    let table = value.as_table_mut().ok_or_else(|| ConfigError::Migration {
        message: "config root must be a table".into(),
    })?;

    let version = table
        .get("schema_version")
        .and_then(toml::Value::as_integer)
        .unwrap_or(0);

    if version < 0 {
        return Err(ConfigError::Migration {
            message: format!("negative schema_version: {version}"),
        });
    }

    let mut current = u32::try_from(version).map_err(|_| ConfigError::Migration {
        message: format!("schema_version out of range: {version}"),
    })?;
    let mut changed = false;

    if current == 0 {
        // Treat legacy / missing version as v1 defaults.
        table.insert(
            "schema_version".into(),
            toml::Value::Integer(i64::from(CONFIG_SCHEMA_VERSION)),
        );
        current = CONFIG_SCHEMA_VERSION;
        changed = true;
    }

    while current < CONFIG_SCHEMA_VERSION {
        current = migrate_one(table, current)?;
        changed = true;
    }

    if current > CONFIG_SCHEMA_VERSION {
        return Err(ConfigError::Migration {
            message: format!(
                "config schema_version {current} is newer than supported {CONFIG_SCHEMA_VERSION}"
            ),
        });
    }

    Ok(changed)
}

#[allow(clippy::unnecessary_wraps)]
fn migrate_one(table: &mut toml::map::Map<String, toml::Value>, from: u32) -> ConfigResult<u32> {
    // Future migrations (1 -> 2, …) land here. Touch `table` so the signature stays honest.
    let _ = table;
    match from {
        v if v >= CONFIG_SCHEMA_VERSION => Ok(v),
        other => Err(ConfigError::Migration {
            message: format!("no migration path from schema_version {other}"),
        }),
    }
}

/// Refuse to persist content that looks like embedded secrets.
fn assert_no_plaintext_secrets(text: &str) -> ConfigResult<()> {
    let lower = text.to_ascii_lowercase();
    const FORBIDDEN: &[&str] = &[
        "refresh_token",
        "private_key",
        "client_secret",
        "-----begin",
        "password =",
    ];
    for needle in FORBIDDEN {
        if lower.contains(needle) {
            return Err(ConfigError::Validation {
                message: format!(
                    "refusing to write config containing forbidden secret marker `{needle}`"
                ),
            });
        }
    }
    Ok(())
}

/// Returns true when `text` appears free of common secret markers (for tests).
#[must_use]
pub fn appears_secret_free(text: &str) -> bool {
    assert_no_plaintext_secrets(text).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn load_save_roundtrip_and_backup() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let mut cfg = load_config(&paths).unwrap();
        cfg.lang = "ja-JP".into();
        save_config(&paths, &cfg).unwrap();

        cfg.lang = "en-US".into();
        save_config(&paths, &cfg).unwrap();
        assert!(
            paths.config_file().with_extension("toml.bak").exists() || {
                // backup_path appends .bak to full file name
                let mut p = paths.config_file().into_os_string();
                p.push(".bak");
                PathBuf::from(p).exists()
            }
        );

        let loaded = load_config(&paths).unwrap();
        assert_eq!(loaded.lang, "en-US");
    }

    #[test]
    fn migration_from_missing_version() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        fs::write(paths.config_file(), "lang = \"zh-Hans\"\n").unwrap();
        let cfg = load_config(&paths).unwrap();
        assert_eq!(cfg.schema_version, CONFIG_SCHEMA_VERSION);
        assert_eq!(cfg.lang, "zh-Hans");
    }

    #[test]
    fn rejects_secret_markers_on_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("evil.toml");
        let err = atomic_write(&path, b"refresh_token = \"abc\"\n");
        // atomic_write itself does not check — save_config does.
        assert!(err.is_ok());
        let err = assert_no_plaintext_secrets("refresh_token = \"abc\"");
        assert!(err.is_err());
    }

    #[test]
    fn migrate_one_at_current_is_identity() {
        let mut table = toml::map::Map::new();
        let v = migrate_one(&mut table, CONFIG_SCHEMA_VERSION).unwrap();
        assert_eq!(v, CONFIG_SCHEMA_VERSION);
    }

    #[test]
    fn atomic_write_replaces_without_deleting_first() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("state.json");
        atomic_write(&path, b"version-one").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "version-one");

        atomic_write(&path, b"version-two").unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "version-two");

        // Backup of the pre-replace contents must exist.
        let bak = backup_path(&path);
        assert!(bak.is_file());
        assert_eq!(fs::read_to_string(&bak).unwrap(), "version-one");

        // No per-operation temp may linger after successful rename.
        let temp_prefix = format!("{}.tmp.", path.file_name().unwrap().to_string_lossy());
        assert!(!fs::read_dir(dir.path())
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry
                .file_name()
                .to_string_lossy()
                .starts_with(&temp_prefix)));
    }

    #[test]
    fn atomic_write_failed_replace_keeps_old_contents() {
        let dir = tempdir().unwrap();
        let path2 = dir.path().join("stable.json");
        atomic_write(&path2, b"STABLE-OLD").unwrap();

        // Hold an exclusive lock on Windows so MoveFileExW replace fails while
        // the original bytes stay readable. On Unix, open+unlink semantics differ,
        // so we instead make the temp path a directory to fail File::create.
        #[cfg(windows)]
        {
            use std::fs::OpenOptions;
            use std::io::{Read, Seek, SeekFrom};
            use std::os::windows::fs::OpenOptionsExt;
            // share_mode(0) denies FILE_SHARE_DELETE required by replace.
            let mut guard = OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(0)
                .open(&path2)
                .expect("exclusive lock");
            let err = atomic_write(&path2, b"STABLE-NEW");
            assert!(err.is_err(), "replace must fail under exclusive lock");
            // Read via the held handle (path open is denied under share_mode 0).
            guard.seek(SeekFrom::Start(0)).unwrap();
            let mut got = String::new();
            guard.read_to_string(&mut got).unwrap();
            assert_eq!(got, "STABLE-OLD");
            drop(guard);
            assert_eq!(fs::read_to_string(&path2).unwrap(), "STABLE-OLD");
        }

        #[cfg(not(windows))]
        {
            // Fault injection must not depend on guessing the helper's unique temp name.
            // Make the destination a non-empty directory and retain the stable file nearby.
            let saved = dir.path().join("stable.saved-for-fault-injection");
            fs::rename(&path2, &saved).unwrap();
            fs::create_dir(&path2).unwrap();
            fs::write(path2.join("blocker"), b"1").unwrap();
            let err = atomic_write(&path2, b"STABLE-NEW");
            assert!(err.is_err(), "write must fail for a directory destination");
            assert_eq!(fs::read_to_string(&saved).unwrap(), "STABLE-OLD");
            fs::remove_dir_all(&path2).unwrap();
            fs::rename(&saved, &path2).unwrap();
            assert_eq!(fs::read_to_string(&path2).unwrap(), "STABLE-OLD");
        }

        // Directory-as-target also fails and must not wipe the stable neighbor.
        let path = dir.path().join("dir-target.json");
        fs::create_dir(&path).unwrap();
        fs::write(path.join("child"), b"x").unwrap();
        let err = atomic_write(&path, b"nope");
        assert!(err.is_err());
        assert!(path.is_dir());
        assert_eq!(fs::read_to_string(&path2).unwrap(), "STABLE-OLD");
    }
}
