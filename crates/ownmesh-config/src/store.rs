//! TOML load / atomic write / backup / migration.

use crate::error::{ConfigError, ConfigResult};
use crate::paths::OwnMeshPaths;
use crate::schema::{OwnMeshConfig, PolicyFile, CONFIG_SCHEMA_VERSION};
use ownmesh_persist::write_atomically;
use std::fs;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// Load `config.toml`, migrating when needed. Creates a default file when missing.
///
/// Always recovers any interrupted config+policy transaction under the exclusive
/// transaction lock **before** the live pair is read or acted upon. Recovery
/// failures preserve the journal and fail closed.
///
/// # Errors
///
/// Returns IO / parse / validation / migration / recovery errors.
pub fn load_config(paths: &OwnMeshPaths) -> ConfigResult<OwnMeshConfig> {
    paths.ensure_layout()?;
    let _lock = acquire_config_policy_tx_lock(paths)?;
    recover_config_policy_transaction_locked(paths)?;
    load_config_after_recovery(paths)
}

fn load_config_after_recovery(paths: &OwnMeshPaths) -> ConfigResult<OwnMeshConfig> {
    let path = paths.config_file();
    if !path.exists() {
        let cfg = OwnMeshConfig::default();
        save_config_unlocked(paths, &cfg)?;
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
        save_config_unlocked(paths, &cfg)?;
    }
    Ok(cfg)
}

/// Atomically write `config.toml`, keeping a `.bak` of the previous version.
///
/// # Errors
///
/// Returns validation or IO errors.
pub fn save_config(paths: &OwnMeshPaths, cfg: &OwnMeshConfig) -> ConfigResult<()> {
    // Single-file writers also recover first so they never clobber a half-applied pair.
    paths.ensure_layout()?;
    let _lock = acquire_config_policy_tx_lock(paths)?;
    recover_config_policy_transaction_locked(paths)?;
    save_config_unlocked(paths, cfg)
}

fn save_config_unlocked(paths: &OwnMeshPaths, cfg: &OwnMeshConfig) -> ConfigResult<()> {
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
/// Always recovers any interrupted config+policy transaction under the exclusive
/// transaction lock **before** the live policy is read or acted upon. Recovery
/// failures preserve the journal and fail closed.
///
/// # Errors
///
/// Returns IO / parse / validation / recovery errors.
pub fn load_policy(paths: &OwnMeshPaths) -> ConfigResult<PolicyFile> {
    paths.ensure_layout()?;
    let _lock = acquire_config_policy_tx_lock(paths)?;
    recover_config_policy_transaction_locked(paths)?;
    load_policy_after_recovery(paths)
}

fn load_policy_after_recovery(paths: &OwnMeshPaths) -> ConfigResult<PolicyFile> {
    let path = paths.policy_file();
    if !path.exists() {
        let policy = PolicyFile::default();
        save_policy_unlocked(paths, &policy)?;
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
    paths.ensure_layout()?;
    let _lock = acquire_config_policy_tx_lock(paths)?;
    recover_config_policy_transaction_locked(paths)?;
    save_policy_unlocked(paths, policy)
}

fn save_policy_unlocked(paths: &OwnMeshPaths, policy: &PolicyFile) -> ConfigResult<()> {
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
/// were written before the journal was cleared). Recovery is mandatory on every production
/// load path via [`ensure_config_policy_consistent`].
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
/// Exclusive lock held for the full duration of setup write or recovery.
/// Lives under the identity-bound config directory (not a shared tempfile).
const TX_LOCK_FILE_NAME: &str = "setup-config-policy.txn.lock";

/// RAII exclusive lock serializing config+policy setup and recovery.
#[derive(Debug)]
pub struct ConfigPolicyTxLock {
    _file: File,
}

fn transaction_path(paths: &OwnMeshPaths) -> PathBuf {
    paths.config_dir.join(TX_FILE_NAME)
}

fn transaction_lock_path(paths: &OwnMeshPaths) -> PathBuf {
    paths.config_dir.join(TX_LOCK_FILE_NAME)
}

/// Acquire the durable exclusive lock for config+policy transactions.
///
/// The lock file lives in the permission-checked config directory (owner-only on
/// Unix) and is held open for the guard's lifetime. Concurrent setup/recovery
/// callers block until the lock is free.
///
/// # Errors
///
/// Returns IO errors when the lock cannot be created, permission-checked, or acquired.
pub fn acquire_config_policy_tx_lock(paths: &OwnMeshPaths) -> ConfigResult<ConfigPolicyTxLock> {
    paths.ensure_layout()?;
    let path = transaction_lock_path(paths);
    reject_symlink_if_present(&path)?;
    let file = open_tx_lock_file(&path)?;
    validate_tx_lock_file(&file, &path)?;
    lock_exclusive_blocking(&file).map_err(|source| ConfigError::Io {
        path: Some(path.clone()),
        source,
    })?;
    // Re-validate after lock: refuse replaced/symlink races.
    validate_tx_lock_file(&file, &path)?;
    Ok(ConfigPolicyTxLock { _file: file })
}

fn reject_symlink_if_present(path: &Path) -> ConfigResult<()> {
    match fs::symlink_metadata(path) {
        Ok(md) if md.file_type().is_symlink() => Err(ConfigError::Validation {
            message: format!(
                "refusing config+policy transaction lock path that is a symlink: {}",
                path.display()
            ),
        }),
        Ok(_) | Err(_) => Ok(()),
    }
}

fn open_tx_lock_file(path: &Path) -> ConfigResult<File> {
    // Crash-safe journal/lock semantics: create the lock node if missing, but never
    // truncate an existing lock file. Mutual exclusion is the OS advisory/mandatory
    // lock on the open handle; wiping contents is unnecessary and would race with
    // concurrent validators inspecting the same node.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(path)
            .map_err(|source| ConfigError::Io {
                path: Some(path.to_path_buf()),
                source,
            })
    }
    #[cfg(windows)]
    {
        // share_mode(0): exclusive open — no concurrent reader/writer/deleter.
        // Retry sharing violations so concurrent setup/recovery serializes instead of racing.
        use std::os::windows::fs::OpenOptionsExt;
        use std::thread;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .share_mode(0)
                .open(path)
            {
                Ok(file) => return Ok(file),
                Err(source) => {
                    // ERROR_SHARING_VIOLATION = 32, ERROR_LOCK_VIOLATION = 33
                    let sharing = matches!(source.raw_os_error(), Some(32 | 33));
                    if sharing && Instant::now() < deadline {
                        thread::sleep(Duration::from_millis(20));
                        continue;
                    }
                    return Err(ConfigError::Io {
                        path: Some(path.to_path_buf()),
                        source,
                    });
                }
            }
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|source| ConfigError::Io {
                path: Some(path.to_path_buf()),
                source,
            })
    }
}

fn validate_tx_lock_file(file: &File, path: &Path) -> ConfigResult<()> {
    let md = file.metadata().map_err(|source| ConfigError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;
    if !md.is_file() {
        return Err(ConfigError::Validation {
            message: format!(
                "config+policy transaction lock is not a regular file: {}",
                path.display()
            ),
        });
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Tighten residual umask bits, then require owner-only.
        let mut perms = md.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms).map_err(|source| ConfigError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        let md = file.metadata().map_err(|source| ConfigError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        let mode = md.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            return Err(ConfigError::Validation {
                message: format!(
                    "config+policy transaction lock must be owner-only (mode {mode:04o}): {}",
                    path.display()
                ),
            });
        }
    }
    Ok(())
}

#[cfg(unix)]
fn lock_exclusive_blocking(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsFd;
    rustix::fs::flock(file.as_fd(), rustix::fs::FlockOperation::LockExclusive)
        .map_err(std::io::Error::from)
}

#[cfg(windows)]
#[allow(clippy::unnecessary_wraps)] // signature matches Unix flock path
fn lock_exclusive_blocking(file: &File) -> std::io::Result<()> {
    // Exclusive open via share_mode(0) already serializes openers. No extra FFI lock.
    let _ = file;
    Ok(())
}

#[cfg(not(any(unix, windows)))]
fn lock_exclusive_blocking(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "config+policy transaction lock is unsupported on this platform",
    ))
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
        if let Ok(dir) = File::open(parent) {
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

/// Roll back a failed in-flight write. On restore failure the journal is preserved
/// and a composite error is returned (fail closed — never silent `let _ =`).
fn rollback_or_preserve_journal(
    config_path: &Path,
    policy_path: &Path,
    tx_path: &Path,
    tx: &ConfigPolicyTransaction,
    primary: ConfigError,
) -> ConfigError {
    match restore_pair_from_transaction(config_path, policy_path, tx) {
        Ok(()) => match clear_transaction_journal(tx_path) {
            Ok(()) => primary,
            Err(clear_err) => ConfigError::Other(format!(
                "{primary}; pair restored but journal clear failed ({clear_err}); journal may remain"
            )),
        },
        Err(restore_err) => ConfigError::Other(format!(
            "{primary}; rollback failed ({restore_err}); journal preserved at {}",
            tx_path.display()
        )),
    }
}

/// Atomically apply a config+policy pair with a durable recovery journal.
///
/// Guarantees:
/// - Exclusive transaction lock serializes concurrent setup/recovery.
/// - Both documents are validated before any write.
/// - A journal capturing the previous pair is durable before either live file changes.
/// - On policy write failure, the previous config (and policy) are restored from the journal.
/// - Rollback failure preserves the journal and returns an error (fail closed).
/// - Never leaves a committed new config paired with a stale old strong policy after success path.
///
/// # Errors
///
/// Validation or IO failures. On failure the live pair matches the pre-call pair when restore
/// succeeds; if restore fails the journal remains for the next recovery attempt.
pub fn save_config_and_policy_transactional(
    paths: &OwnMeshPaths,
    cfg: &OwnMeshConfig,
    policy: &PolicyFile,
) -> ConfigResult<()> {
    cfg.validate()?;
    policy.validate()?;
    paths.ensure_layout()?;

    let _lock = acquire_config_policy_tx_lock(paths)?;
    // Recover any interrupted prior transaction before starting a new one.
    recover_config_policy_transaction_locked(paths)?;

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
        return Err(rollback_or_preserve_journal(
            &config_path,
            &policy_path,
            &tx_path,
            &tx,
            err,
        ));
    }
    tx.phase = "config_written".into();
    if let Err(err) = write_transaction_journal(&tx_path, &tx) {
        return Err(rollback_or_preserve_journal(
            &config_path,
            &policy_path,
            &tx_path,
            &tx,
            err,
        ));
    }

    // Stage policy. On failure, restore the previous pair completely.
    if let Err(err) = atomic_write(&policy_path, new_policy.as_bytes()) {
        return Err(rollback_or_preserve_journal(
            &config_path,
            &policy_path,
            &tx_path,
            &tx,
            err,
        ));
    }

    tx.phase = "committed".into();
    // Durable committed marker then clear. If clear fails after both files are the new pair,
    // recovery of a `committed` journal is idempotent (rewrites the same new pair).
    write_transaction_journal(&tx_path, &tx)?;
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

/// Recover any interrupted config+policy transaction under the exclusive lock.
///
/// Mandatory before every production daemon/CLI path that consumes config or policy.
/// On recovery failure the journal is preserved and the error is returned (fail closed).
///
/// # Errors
///
/// Lock, IO, or parse failures while recovering.
pub fn ensure_config_policy_consistent(paths: &OwnMeshPaths) -> ConfigResult<()> {
    let _lock = acquire_config_policy_tx_lock(paths)?;
    recover_config_policy_transaction_locked(paths)
}

/// Complete or roll back an interrupted config+policy transaction.
///
/// Acquires the exclusive transaction lock. Prefer [`ensure_config_policy_consistent`]
/// at load boundaries; this entry point remains for setup and tests.
///
/// - `prepared` / `config_written`: restore the old pair (or delete new-only files).
/// - `committed`: ensure both new files are present, then clear the journal.
/// - On any restore/apply failure the journal is **preserved** and an error is returned.
///
/// # Errors
///
/// IO / parse failures while reading or applying the journal.
pub fn recover_config_policy_transaction(paths: &OwnMeshPaths) -> ConfigResult<()> {
    let _lock = acquire_config_policy_tx_lock(paths)?;
    recover_config_policy_transaction_locked(paths)
}

fn recover_config_policy_transaction_locked(paths: &OwnMeshPaths) -> ConfigResult<()> {
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
                "unsupported setup transaction schema_version {} (journal preserved)",
                tx.schema_version
            ),
        });
    }

    let config_path = paths.config_file();
    let policy_path = paths.policy_file();

    if tx.phase.as_str() == "committed" {
        // Finish publishing the new pair if needed, then drop the journal.
        // Any failure leaves the journal in place for a later attempt.
        atomic_write(&config_path, tx.new_config.as_bytes()).map_err(|err| {
            ConfigError::Other(format!(
                "committed recovery failed writing config ({err}); journal preserved at {}",
                tx_path.display()
            ))
        })?;
        atomic_write(&policy_path, tx.new_policy.as_bytes()).map_err(|err| {
            ConfigError::Other(format!(
                "committed recovery failed writing policy ({err}); journal preserved at {}",
                tx_path.display()
            ))
        })?;
        clear_transaction_journal(&tx_path)?;
    } else {
        // prepared / config_written / unknown → fail closed back to the old pair.
        restore_pair_from_transaction(&config_path, &policy_path, &tx).map_err(|err| {
            ConfigError::Other(format!(
                "recovery rollback failed ({err}); journal preserved at {}",
                tx_path.display()
            ))
        })?;
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
            delegate_remote_mcp: false,
            rules: Vec::new(),
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
            delegate_remote_mcp: false,
            rules: Vec::new(),
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
            delegate_remote_mcp: false,
            rules: Vec::new(),
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

        // load_config must recover before consuming the pair (mandatory on every read path).
        let cfg = load_config(&paths).unwrap();
        assert!(!transaction_path(&paths).exists());
        assert_eq!(cfg.active_instance.as_deref(), Some("old"));
        let pol = load_policy(&paths).unwrap();
        assert_eq!(pol.preset.as_deref(), Some("full_access"));
        assert_eq!(
            fs::read_to_string(paths.policy_file()).unwrap(),
            old_policy_text
        );
    }

    #[test]
    fn load_paths_recover_config_written_before_policy_use() {
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
            preset: Some("full_access".into()),
            delegate_remote_mcp: false,
            rules: Vec::new(),
        };
        save_config_and_policy_transactional(&paths, &old_cfg, &old_policy).unwrap();

        let new_cfg = OwnMeshConfig {
            active_instance: Some("half".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "half".into(),
                base_url: "https://half.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let new_policy = PolicyFile {
            schema_version: 1,
            preset: Some("workspace_only".into()),
            delegate_remote_mcp: false,
            rules: Vec::new(),
        };
        let new_config = toml::to_string_pretty(&new_cfg).unwrap();
        let new_policy_text = toml::to_string_pretty(&new_policy).unwrap();
        let old_config = fs::read_to_string(paths.config_file()).unwrap();
        let old_policy_text = fs::read_to_string(paths.policy_file()).unwrap();
        let tx = ConfigPolicyTransaction {
            schema_version: TX_SCHEMA,
            phase: "config_written".into(),
            old_config: Some(old_config),
            old_policy: Some(old_policy_text),
            new_config: new_config.clone(),
            new_policy: new_policy_text,
        };
        write_transaction_journal(&transaction_path(&paths), &tx).unwrap();
        atomic_write(&paths.config_file(), new_config.as_bytes()).unwrap();

        // Policy load (daemon path) must recover first — never observe new cfg + old full_access.
        let pol = load_policy(&paths).unwrap();
        assert_eq!(pol.preset.as_deref(), Some("full_access"));
        assert!(!transaction_path(&paths).exists());
        let cfg = load_config(&paths).unwrap();
        assert_eq!(cfg.active_instance.as_deref(), Some("stable"));
    }

    #[test]
    fn recovery_failure_preserves_journal_and_fails_closed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();

        let old_cfg_text = "schema_version = 1\nlang = \"en-US\"\n";
        let old_pol_text = "schema_version = 1\npreset = \"full_access\"\n";
        let new_cfg_text = "schema_version = 1\nlang = \"ja-JP\"\n";
        let new_pol_text = "schema_version = 1\npreset = \"recommended\"\n";
        atomic_write(&paths.config_file(), new_cfg_text.as_bytes()).unwrap();
        atomic_write(&paths.policy_file(), old_pol_text.as_bytes()).unwrap();

        let tx = ConfigPolicyTransaction {
            schema_version: TX_SCHEMA,
            phase: "config_written".into(),
            old_config: Some(old_cfg_text.into()),
            old_policy: Some(old_pol_text.into()),
            new_config: new_cfg_text.into(),
            new_policy: new_pol_text.into(),
        };
        let tx_path = transaction_path(&paths);
        write_transaction_journal(&tx_path, &tx).unwrap();

        // Fault-inject: make config path a non-empty directory so restore cannot rewrite it.
        fs::remove_file(paths.config_file()).unwrap();
        fs::create_dir(paths.config_file()).unwrap();
        fs::write(paths.config_file().join("blocker"), b"1").unwrap();

        let err = recover_config_policy_transaction(&paths).expect_err("must fail closed");
        let msg = err.to_string();
        assert!(
            msg.contains("journal preserved") || msg.contains("rollback failed"),
            "{msg}"
        );
        assert!(
            tx_path.is_file(),
            "journal must remain on disk after recovery failure"
        );

        // Production load paths must also refuse rather than consume the broken pair.
        let load_err = load_config(&paths).expect_err("load must fail closed");
        assert!(
            load_err.to_string().contains("journal preserved")
                || load_err.to_string().contains("rollback failed")
                || load_err.to_string().contains("Is a directory")
                || load_err.to_string().contains("directory"),
            "{load_err}"
        );
        assert!(
            tx_path.is_file(),
            "journal still preserved after load attempt"
        );
    }

    #[test]
    fn concurrent_setup_is_serialized() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let dir = tempdir().unwrap();
        let base = dir.path().to_path_buf();
        let paths = OwnMeshPaths::for_base(&base);
        let initial = OwnMeshConfig {
            active_instance: Some("seed".into()),
            instances: vec![crate::schema::InstanceConfig {
                id: "seed".into(),
                base_url: "https://seed.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        let policy = PolicyFile {
            schema_version: 1,
            preset: Some("recommended".into()),
            delegate_remote_mcp: false,
            rules: Vec::new(),
        };
        save_config_and_policy_transactional(&paths, &initial, &policy).unwrap();

        const N: usize = 8;
        let barrier = Arc::new(Barrier::new(N));
        let mut handles = Vec::new();
        for i in 0..N {
            let base = base.clone();
            let barrier = Arc::clone(&barrier);
            handles.push(thread::spawn(move || {
                let paths = OwnMeshPaths::for_base(&base);
                let cfg = OwnMeshConfig {
                    active_instance: Some(format!("w{i}")),
                    instances: vec![crate::schema::InstanceConfig {
                        id: format!("w{i}"),
                        base_url: format!("https://w{i}.example.test"),
                        display_name: None,
                    }],
                    ..OwnMeshConfig::default()
                };
                let pol = PolicyFile {
                    schema_version: 1,
                    preset: Some(if i % 2 == 0 {
                        "recommended".into()
                    } else {
                        "workspace_only".into()
                    }),
                    delegate_remote_mcp: false,
                    rules: Vec::new(),
                };
                barrier.wait();
                save_config_and_policy_transactional(&paths, &cfg, &pol).expect("serialized setup");
            }));
        }
        for h in handles {
            h.join().expect("thread");
        }
        assert!(!transaction_path(&paths).exists());
        let cfg = load_config(&paths).unwrap();
        let id = cfg.active_instance.expect("active");
        assert!(id.starts_with('w'), "{id}");
        let pol = load_policy(&paths).unwrap();
        assert!(pol.preset.is_some());
        // Pair must be internally consistent: instance id matches a configured instance.
        assert!(cfg.instances.iter().any(|i| i.id == id));
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
            delegate_remote_mcp: false,
            rules: Vec::new(),
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
            delegate_remote_mcp: false,
            rules: Vec::new(),
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

    #[test]
    fn tx_lock_open_creates_without_truncating_existing_contents() {
        // Lock files use create + explicit truncate(false): an existing lock node
        // must keep its bytes (crash-safe journal lock semantics).
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let lock_path = transaction_lock_path(&paths);
        const MARKER: &[u8] = b"lock-marker-keep-me";
        fs::write(&lock_path, MARKER).unwrap();

        let guard = acquire_config_policy_tx_lock(&paths).unwrap();
        // On Windows the lock is opened with share_mode(0), so peer path reads are
        // denied while held; release first, then attest bytes were not truncated.
        drop(guard);
        assert_eq!(
            fs::read(&lock_path).unwrap(),
            MARKER,
            "open_tx_lock_file must not truncate existing lock contents"
        );

        // Second acquire/release still preserves the marker (create+truncate(false)).
        let guard = acquire_config_policy_tx_lock(&paths).unwrap();
        drop(guard);
        assert_eq!(fs::read(&lock_path).unwrap(), MARKER);
    }
}
