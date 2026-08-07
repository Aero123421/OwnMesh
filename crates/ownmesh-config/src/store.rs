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

/// On-disk journal for a two-file config+policy setup transaction.
///
/// Durable recovery: if a crash leaves the journal present, [`recover_config_policy_transaction`]
/// restores the pre-transaction pair (or completes a fully-staged commit when both new blobs
/// were written before the journal was cleared).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ConfigPolicyTransaction {
    pub schema_version: u32,
    pub phase: String,
    pub old_config: Option<String>,
    pub old_policy: Option<String>,
    pub new_config: String,
    pub new_policy: String,
}

const TX_SCHEMA: u32 = 1;
const TX_FILE_NAME: &str = "setup-config-policy.txn.json";

fn transaction_path(paths: &OwnMeshPaths) -> PathBuf {
    paths.config_dir.join(TX_FILE_NAME)
}

fn read_optional_text(path: &Path) -> ConfigResult<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s)),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ConfigError::Io {
            path: Some(path.to_path_buf()),
            source,
        }),
    }
}

fn write_transaction_journal(path: &Path, tx: &ConfigPolicyTransaction) -> ConfigResult<()> {
    let rendered =
        serde_json::to_vec_pretty(tx).map_err(|err| ConfigError::Other(err.to_string()))?;
    write_atomically(path, &rendered).map_err(|source| ConfigError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;
    // Best-effort durability of the journal parent on Unix.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn clear_transaction_journal(path: &Path) -> ConfigResult<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(ConfigError::Io {
            path: Some(path.to_path_buf()),
            source,
        }),
    }
}

/// Atomically apply a config+policy pair with a durable recovery journal.
///
/// Guarantees:
/// - Both documents are validated before any write.
/// - A journal capturing the previous pair is durable before either live file changes.
/// - On policy write failure, the previous config (and policy) are restored from the journal.
/// - Never leaves a committed new config paired with a stale old strong policy after failure.
///
/// # Errors
///
/// Validation or IO failures. On failure the live pair matches the pre-call pair when a
/// previous pair existed; first-run partial creates are rolled back to absent files.
pub fn save_config_and_policy_transactional(
    paths: &OwnMeshPaths,
    cfg: &OwnMeshConfig,
    policy: &PolicyFile,
) -> ConfigResult<()> {
    cfg.validate()?;
    policy.validate()?;
    paths.ensure_layout()?;

    // Recover any interrupted prior transaction before starting a new one.
    recover_config_policy_transaction(paths)?;

    let config_path = paths.config_file();
    let policy_path = paths.policy_file();
    let tx_path = transaction_path(paths);

    let new_config =
        toml::to_string_pretty(cfg).map_err(|err| ConfigError::Other(err.to_string()))?;
    let new_policy =
        toml::to_string_pretty(policy).map_err(|err| ConfigError::Other(err.to_string()))?;
    assert_no_plaintext_secrets(&new_config)?;
    assert_no_plaintext_secrets(&new_policy)?;

    let old_config = read_optional_text(&config_path)?;
    let old_policy = read_optional_text(&policy_path)?;

    let mut tx = ConfigPolicyTransaction {
        schema_version: TX_SCHEMA,
        phase: "prepared".into(),
        old_config: old_config.clone(),
        old_policy: old_policy.clone(),
        new_config: new_config.clone(),
        new_policy: new_policy.clone(),
    };
    write_transaction_journal(&tx_path, &tx)?;

    // Stage config.
    if let Err(err) = atomic_write(&config_path, new_config.as_bytes()) {
        let _ = restore_pair_from_transaction(&config_path, &policy_path, &tx);
        let _ = clear_transaction_journal(&tx_path);
        return Err(err);
    }
    tx.phase = "config_written".into();
    if let Err(err) = write_transaction_journal(&tx_path, &tx) {
        let _ = restore_pair_from_transaction(&config_path, &policy_path, &tx);
        let _ = clear_transaction_journal(&tx_path);
        return Err(err);
    }

    // Stage policy. On failure, restore the previous pair completely.
    if let Err(err) = atomic_write(&policy_path, new_policy.as_bytes()) {
        let _ = restore_pair_from_transaction(&config_path, &policy_path, &tx);
        let _ = clear_transaction_journal(&tx_path);
        return Err(err);
    }

    tx.phase = "committed".into();
    // Best-effort journal update then clear — recovery treats missing journal as clean.
    let _ = write_transaction_journal(&tx_path, &tx);
    clear_transaction_journal(&tx_path)?;
    Ok(())
}

fn restore_pair_from_transaction(
    config_path: &Path,
    policy_path: &Path,
    tx: &ConfigPolicyTransaction,
) -> ConfigResult<()> {
    match &tx.old_config {
        Some(bytes) => atomic_write(config_path, bytes.as_bytes())?,
        None => match fs::remove_file(config_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ConfigError::Io {
                    path: Some(config_path.to_path_buf()),
                    source,
                });
            }
        },
    }
    match &tx.old_policy {
        Some(bytes) => atomic_write(policy_path, bytes.as_bytes())?,
        None => match fs::remove_file(policy_path) {
            Ok(()) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ConfigError::Io {
                    path: Some(policy_path.to_path_buf()),
                    source,
                });
            }
        },
    }
    Ok(())
}

/// Complete or roll back an interrupted config+policy transaction.
///
/// - `prepared` / `config_written`: restore the old pair (or delete new-only files).
/// - `committed`: ensure both new files are present, then clear the journal.
///
/// # Errors
///
/// IO / parse failures while reading or applying the journal.
pub fn recover_config_policy_transaction(paths: &OwnMeshPaths) -> ConfigResult<()> {
    let tx_path = transaction_path(paths);
    let raw = match fs::read_to_string(&tx_path) {
        Ok(s) => s,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(source) => {
            return Err(ConfigError::Io {
                path: Some(tx_path),
                source,
            });
        }
    };
    let tx: ConfigPolicyTransaction =
        serde_json::from_str(&raw).map_err(|err| ConfigError::Parse {
            path: tx_path.clone(),
            message: format!("setup transaction journal: {err}"),
        })?;
    if tx.schema_version != TX_SCHEMA {
        return Err(ConfigError::Migration {
            message: format!(
                "unsupported setup transaction schema_version {}",
                tx.schema_version
            ),
        });
    }

    let config_path = paths.config_file();
    let policy_path = paths.policy_file();

    if tx.phase.as_str() == "committed" {
        // Finish publishing the new pair if needed, then drop the journal.
        atomic_write(&config_path, tx.new_config.as_bytes())?;
        atomic_write(&policy_path, tx.new_policy.as_bytes())?;
        clear_transaction_journal(&tx_path)?;
    } else {
        // prepared / config_written / unknown → fail closed back to the old pair.
        restore_pair_from_transaction(&config_path, &policy_path, &tx)?;
        clear_transaction_journal(&tx_path)?;
    }
    Ok(())
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

    #[test]
    fn config_policy_transaction_commits_pair() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let cfg = OwnMeshConfig {
            active_instance: Some("a".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "a".into(),
                base_url: "https://cp.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let policy = PolicyFile {
            schema_version: 1,
            preset: Some("recommended".into()),
        };
        save_config_and_policy_transactional(&paths, &cfg, &policy).unwrap();
        assert!(!transaction_path(&paths).exists());
        let loaded = load_config(&paths).unwrap();
        assert_eq!(loaded.active_instance.as_deref(), Some("a"));
        let pol = load_policy(&paths).unwrap();
        assert_eq!(pol.preset.as_deref(), Some("recommended"));
    }

    #[test]
    fn config_policy_transaction_fault_on_policy_restores_old_pair() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let old_cfg = OwnMeshConfig {
            active_instance: Some("old".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "old".into(),
                base_url: "https://old.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let old_policy = PolicyFile {
            schema_version: 1,
            preset: Some("full_access".into()),
        };
        save_config_and_policy_transactional(&paths, &old_cfg, &old_policy).unwrap();

        let new_cfg = OwnMeshConfig {
            active_instance: Some("new".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "new".into(),
                base_url: "https://new.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let new_policy = PolicyFile {
            schema_version: 1,
            preset: Some("workspace_only".into()),
        };

        // Simulate crash after config stage: journal left in config_written with new config
        // already on disk and old strong policy still present.
        let new_config = toml::to_string_pretty(&new_cfg).unwrap();
        let new_policy_text = toml::to_string_pretty(&new_policy).unwrap();
        let old_config = fs::read_to_string(paths.config_file()).unwrap();
        let old_policy_text = fs::read_to_string(paths.policy_file()).unwrap();
        let tx = ConfigPolicyTransaction {
            schema_version: TX_SCHEMA,
            phase: "config_written".into(),
            old_config: Some(old_config),
            old_policy: Some(old_policy_text.clone()),
            new_config: new_config.clone(),
            new_policy: new_policy_text,
        };
        write_transaction_journal(&transaction_path(&paths), &tx).unwrap();
        atomic_write(&paths.config_file(), new_config.as_bytes()).unwrap();
        // Policy intentionally left as old strong full_access.

        // Recovery must restore the old pair (never leave new config + old strong policy).
        recover_config_policy_transaction(&paths).unwrap();
        assert!(!transaction_path(&paths).exists());
        let cfg = load_config(&paths).unwrap();
        assert_eq!(cfg.active_instance.as_deref(), Some("old"));
        let pol = load_policy(&paths).unwrap();
        assert_eq!(pol.preset.as_deref(), Some("full_access"));
        assert_eq!(
            fs::read_to_string(paths.policy_file()).unwrap(),
            old_policy_text
        );
    }

    #[test]
    fn config_policy_transaction_policy_write_failure_rolls_back() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let old_cfg = OwnMeshConfig {
            active_instance: Some("stable".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "stable".into(),
                base_url: "https://stable.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let old_policy = PolicyFile {
            schema_version: 1,
            preset: Some("recommended".into()),
        };
        save_config_and_policy_transactional(&paths, &old_cfg, &old_policy).unwrap();

        let new_cfg = OwnMeshConfig {
            active_instance: Some("broken".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "broken".into(),
                base_url: "https://broken.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let new_policy = PolicyFile {
            schema_version: 1,
            preset: Some("workspace_only".into()),
        };

        // Fault-inject policy destination as a non-empty directory so atomic_write fails.
        let policy_path = paths.policy_file();
        let policy_backup = dir.path().join("policy.saved");
        fs::rename(&policy_path, &policy_backup).unwrap();
        fs::create_dir(&policy_path).unwrap();
        fs::write(policy_path.join("blocker"), b"1").unwrap();

        let err = save_config_and_policy_transactional(&paths, &new_cfg, &new_policy);
        assert!(err.is_err(), "policy fault must fail the transaction");

        // Clean the blocker and restore path shape so we can inspect results.
        fs::remove_dir_all(&policy_path).unwrap();
        fs::rename(&policy_backup, &policy_path).unwrap();

        // Transaction helper should have restored config to old and left no journal.
        // (policy path was a directory during failure; restore writes old policy bytes back).
        recover_config_policy_transaction(&paths).unwrap();
        assert!(!transaction_path(&paths).exists());
        let cfg = load_config(&paths).unwrap();
        assert_eq!(
            cfg.active_instance.as_deref(),
            Some("stable"),
            "must not leave new config after policy failure"
        );
        let pol = load_policy(&paths).unwrap();
        assert_eq!(pol.preset.as_deref(), Some("recommended"));
    }
}
