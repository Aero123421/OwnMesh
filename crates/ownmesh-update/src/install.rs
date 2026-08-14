//! Staging, atomic multi-binary install, backup, and rollback.

use crate::error::{UpdateError, UpdateResult};
use crate::platform::{binary_file_name, REQUIRED_BINARIES};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const APPLY_JOURNAL_SCHEMA: u32 = 1;
const APPLY_JOURNAL_NAME: &str = ".ownmesh-update-journal.json";

#[derive(Debug, Serialize, Deserialize)]
struct ApplyJournal {
    schema_version: u32,
    staging_name: String,
    backup_name: String,
    backup_sha256: BTreeMap<String, String>,
}

/// Result of a successful apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Install directory that received the binaries.
    pub install_dir: PathBuf,
    /// Durable backup directory retained until explicit finalize or rollback.
    /// It may be empty for a first install, but still anchors crash recovery.
    pub backup_dir: Option<PathBuf>,
    /// Names of binaries written.
    pub written: Vec<String>,
    /// Retained for wire compatibility. Self-update callers now run from a
    /// private worker copy, so no pending Windows replacement is scheduled.
    pub pending_windows_replace: bool,
}

/// Detect Homebrew-managed OwnMesh installs.
#[must_use]
pub fn is_homebrew_install(install_dir: &Path) -> bool {
    if env::var_os("OWNMESH_HOMEBREW").is_some() {
        return true;
    }
    let text = install_dir.to_string_lossy().replace('\\', "/");
    let lower = text.to_ascii_lowercase();
    lower.contains("/cellar/ownmesh")
        || (lower.contains("/ownmesh") && lower.contains("homebrew"))
        || lower.contains("/opt/homebrew/")
        || lower.contains("/usr/local/cellar/ownmesh")
        || lower.contains("/home/linuxbrew/.linuxbrew")
}

/// Resolve the directory that holds the running `ownmesh` binary.
///
/// # Errors
///
/// Returns [`UpdateError::Install`] when the executable path cannot be resolved.
pub fn current_install_dir() -> UpdateResult<PathBuf> {
    let exe = env::current_exe()
        .map_err(|err| UpdateError::Install(format!("cannot resolve current executable: {err}")))?;
    let exe = fs::canonicalize(&exe).unwrap_or(exe);
    exe.parent()
        .map(Path::to_path_buf)
        .ok_or_else(|| UpdateError::Install("executable has no parent directory".into()))
}

/// Atomically replace all required binaries in `install_dir`.
///
/// Partial multi-binary updates are refused: either every required binary is
/// staged and swapped, or the previous tree is restored.
///
/// # Errors
///
/// Returns install / homebrew / IO failures.
pub fn apply_binaries(
    install_dir: &Path,
    binaries: &std::collections::BTreeMap<String, Vec<u8>>,
    version_label: &str,
) -> UpdateResult<ApplyReport> {
    if is_homebrew_install(install_dir) {
        return Err(UpdateError::HomebrewManaged);
    }

    // Refuse partial sets before touching the filesystem.
    let mut required_names = Vec::new();
    for base in REQUIRED_BINARIES {
        let name = binary_file_name(base);
        if !binaries.contains_key(&name) {
            return Err(UpdateError::Install(format!(
                "partial update refused: missing {name}"
            )));
        }
        required_names.push(name);
    }

    fs::create_dir_all(install_dir).map_err(|err| {
        UpdateError::Install(format!(
            "create install dir {}: {err}",
            install_dir.display()
        ))
    })?;

    validate_version_label(version_label)?;
    let transaction_suffix = format!("{version_label}-{}", std::process::id());
    let staging = install_dir.join(format!(".ownmesh-staging-{transaction_suffix}"));
    let backup = install_dir.join(format!(".ownmesh-backup-{transaction_suffix}"));
    let _ = fs::remove_dir_all(&staging);
    let _ = fs::remove_dir_all(&backup);
    fs::create_dir_all(&staging).map_err(|err| {
        UpdateError::Install(format!("create staging {}: {err}", staging.display()))
    })?;

    // Stage every binary first.
    for name in &required_names {
        let bytes = binaries.get(name).expect("checked");
        let staged = staging.join(name);
        write_binary_atomic_temp(&staged, bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o755);
            fs::set_permissions(&staged, perms).map_err(|err| {
                UpdateError::Install(format!("chmod {}: {err}", staged.display()))
            })?;
        }
    }

    fs::create_dir_all(&backup).map_err(|err| {
        UpdateError::Install(format!("create backup {}: {err}", backup.display()))
    })?;

    // Backup existing binaries and bind every copy to a digest before swap.
    let mut backup_sha256 = BTreeMap::new();
    for name in &required_names {
        let current = install_dir.join(name);
        if current.exists() {
            let dest = backup.join(name);
            fs::copy(&current, &dest).map_err(|err| {
                UpdateError::Install(format!(
                    "backup {} -> {}: {err}",
                    current.display(),
                    dest.display()
                ))
            })?;
            backup_sha256.insert(name.clone(), sha256_file(&dest)?);
        }
    }

    let pending_windows_replace = false;
    let mut replaced = Vec::new();

    write_apply_journal(
        install_dir,
        &ApplyJournal {
            schema_version: APPLY_JOURNAL_SCHEMA,
            staging_name: staging
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| UpdateError::Install("invalid staging directory name".into()))?
                .to_owned(),
            backup_name: backup
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or_else(|| UpdateError::Install("invalid backup directory name".into()))?
                .to_owned(),
            backup_sha256: backup_sha256.clone(),
        },
    )?;

    // Swap staged → final. On failure, rollback from backup.
    let swap_result = (|| -> UpdateResult<()> {
        for name in &required_names {
            let staged = staging.join(name);
            let final_path = install_dir.join(name);
            match replace_file(&staged, &final_path) {
                Ok(()) => replaced.push(name.clone()),
                Err(err) => {
                    return Err(UpdateError::Install(format!(
                        "replace {} failed: {err}",
                        final_path.display(),
                    )));
                }
            }
        }
        Ok(())
    })();

    if let Err(err) = swap_result {
        let _ = fs::remove_dir_all(&staging);
        return match rollback_with_verification(
            install_dir,
            &backup,
            &required_names,
            &backup_sha256,
        ) {
            Ok(()) => {
                let _ = fs::remove_dir_all(&backup);
                let _ = fs::remove_file(apply_journal_path(install_dir));
                Err(err)
            }
            Err(rollback_error) => Err(UpdateError::Install(format!(
                "{err}; rollback failed and recovery journal was retained: {rollback_error}"
            ))),
        };
    }

    let _ = fs::remove_dir_all(&staging);

    Ok(ApplyReport {
        install_dir: install_dir.to_path_buf(),
        backup_dir: Some(backup),
        written: replaced,
        pending_windows_replace,
    })
}

/// Restore every binary captured in a successful apply report.
///
/// This is used when the new CLI starts but post-install daemon health checks
/// fail. The caller must stop OwnMesh services before invoking it.
///
/// # Errors
///
/// Returns an install error when a backup is missing or cannot be restored.
pub fn rollback_apply(report: &ApplyReport) -> UpdateResult<()> {
    let backup = report.backup_dir.as_ref().ok_or_else(|| {
        UpdateError::Install("cannot rollback update without a backup directory".into())
    })?;
    let journal = read_apply_journal(&report.install_dir)?;
    validate_apply_journal(&journal)?;
    if backup.file_name().and_then(|name| name.to_str()) != Some(journal.backup_name.as_str()) {
        return Err(UpdateError::Install(
            "rollback report does not match the durable journal".into(),
        ));
    }
    rollback_with_verification(
        &report.install_dir,
        backup,
        &report.written,
        &journal.backup_sha256,
    )?;
    fs::remove_dir_all(backup).map_err(|err| {
        UpdateError::Install(format!(
            "remove rollback backup {}: {err}",
            backup.display()
        ))
    })?;
    remove_apply_journal(&report.install_dir)
}

/// Delete the retained backup after version and daemon health verification.
///
/// # Errors
///
/// Returns an install error when the backup cannot be removed.
pub fn finalize_apply(report: &ApplyReport) -> UpdateResult<()> {
    // Removing the journal is the durable commit point. Once post-install
    // health has passed, a later cleanup failure must never make a subsequent
    // invocation roll a healthy release back.
    remove_apply_journal(&report.install_dir)?;
    if let Some(backup) = &report.backup_dir {
        fs::remove_dir_all(backup).map_err(|err| {
            UpdateError::Install(format!(
                "remove verified backup {}: {err}",
                backup.display()
            ))
        })?;
    }
    Ok(())
}

/// Restore an interrupted multi-binary swap from its durable journal.
///
/// Callers must first prove that the process owning the update transaction is
/// no longer alive. A missing journal means no swap had begun.
///
/// # Errors
///
/// Returns an install error for malformed journals or failed restoration.
pub fn recover_interrupted_apply(install_dir: &Path) -> UpdateResult<bool> {
    let Some(journal) = read_apply_journal_optional(install_dir)? else {
        return Ok(false);
    };
    validate_apply_journal(&journal)?;
    let staging = install_dir.join(&journal.staging_name);
    let backup = install_dir.join(&journal.backup_name);
    let names = REQUIRED_BINARIES
        .iter()
        .map(|base| binary_file_name(base))
        .collect::<Vec<_>>();
    rollback_with_verification(install_dir, &backup, &names, &journal.backup_sha256)?;
    let _ = fs::remove_dir_all(&staging);
    fs::remove_dir_all(&backup).map_err(|err| {
        UpdateError::Install(format!(
            "remove recovered backup {}: {err}",
            backup.display()
        ))
    })?;
    remove_apply_journal(install_dir)?;
    Ok(true)
}

fn read_apply_journal_optional(install_dir: &Path) -> UpdateResult<Option<ApplyJournal>> {
    let path = apply_journal_path(install_dir);
    let raw = match fs::read(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(UpdateError::Install(format!(
                "read interrupted update journal {}: {err}",
                path.display()
            )))
        }
    };
    let journal: ApplyJournal = serde_json::from_slice(&raw)
        .map_err(|err| UpdateError::Install(format!("parse interrupted update journal: {err}")))?;
    Ok(Some(journal))
}

fn read_apply_journal(install_dir: &Path) -> UpdateResult<ApplyJournal> {
    read_apply_journal_optional(install_dir)?.ok_or_else(|| {
        UpdateError::Install("cannot rollback update without its durable journal".into())
    })
}

fn apply_journal_path(install_dir: &Path) -> PathBuf {
    install_dir.join(APPLY_JOURNAL_NAME)
}

fn write_apply_journal(install_dir: &Path, journal: &ApplyJournal) -> UpdateResult<()> {
    let bytes = serde_json::to_vec(journal)
        .map_err(|err| UpdateError::Install(format!("serialize update journal: {err}")))?;
    ownmesh_persist::write_atomically(&apply_journal_path(install_dir), &bytes)
        .map_err(|err| UpdateError::Install(format!("persist update journal: {err}")))
}

fn remove_apply_journal(install_dir: &Path) -> UpdateResult<()> {
    match fs::remove_file(apply_journal_path(install_dir)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(UpdateError::Install(format!(
            "remove update journal: {err}"
        ))),
    }
}

fn validate_apply_journal(journal: &ApplyJournal) -> UpdateResult<()> {
    let safe_leaf = |value: &str, prefix: &str| {
        !value.is_empty()
            && value.len() <= 160
            && value.starts_with(prefix)
            && !value.contains(['/', '\\'])
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    };
    if journal.schema_version != APPLY_JOURNAL_SCHEMA
        || !safe_leaf(&journal.staging_name, ".ownmesh-staging-")
        || !safe_leaf(&journal.backup_name, ".ownmesh-backup-")
        || journal.backup_sha256.len() > REQUIRED_BINARIES.len()
        || journal.backup_sha256.iter().any(|(name, digest)| {
            !REQUIRED_BINARIES
                .iter()
                .any(|base| binary_file_name(base) == *name)
                || digest.len() != 64
                || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        })
    {
        return Err(UpdateError::Install(
            "unsafe interrupted update journal refused".into(),
        ));
    }
    Ok(())
}

fn validate_backup_hashes(
    backup: &Path,
    names: &[String],
    expected: &BTreeMap<String, String>,
) -> UpdateResult<()> {
    for name in names {
        let path = backup.join(name);
        let Some(expected_digest) = expected.get(name) else {
            if path.exists() {
                return Err(UpdateError::Install(format!(
                    "untrusted rollback backup metadata for {name}"
                )));
            }
            continue;
        };
        let actual = sha256_file(&path)?;
        if !actual.eq_ignore_ascii_case(expected_digest) {
            return Err(UpdateError::Install(format!(
                "rollback backup checksum mismatch for {name}"
            )));
        }
    }
    Ok(())
}

fn rollback_with_verification(
    install_dir: &Path,
    backup: &Path,
    names: &[String],
    expected: &BTreeMap<String, String>,
) -> UpdateResult<()> {
    validate_backup_hashes(backup, names, expected)?;
    rollback_from_backup(install_dir, backup, names)?;
    for name in names {
        let path = install_dir.join(name);
        match expected.get(name) {
            Some(expected_digest) => {
                let actual = sha256_file(&path)?;
                if !actual.eq_ignore_ascii_case(expected_digest) {
                    return Err(UpdateError::Install(format!(
                        "restored binary checksum mismatch for {name}"
                    )));
                }
            }
            None if path.exists() => {
                return Err(UpdateError::Install(format!(
                    "rollback did not remove newly installed {name}"
                )))
            }
            None => {}
        }
    }
    Ok(())
}

fn sha256_file(path: &Path) -> UpdateResult<String> {
    let mut file = fs::File::open(path)
        .map_err(|err| UpdateError::Install(format!("open backup {}: {err}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer).map_err(|err| {
            UpdateError::Install(format!("hash backup {}: {err}", path.display()))
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn validate_version_label(version_label: &str) -> UpdateResult<()> {
    if version_label.is_empty()
        || version_label.len() > 64
        || !version_label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(UpdateError::Install(
            "unsafe update version label refused".into(),
        ));
    }
    Ok(())
}

fn write_binary_atomic_temp(path: &Path, bytes: &[u8]) -> UpdateResult<()> {
    let parent = path
        .parent()
        .ok_or_else(|| UpdateError::Install(format!("path has no parent: {}", path.display())))?;
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|err| UpdateError::Install(format!("temp file in {}: {err}", parent.display())))?;
    temp.write_all(bytes)
        .map_err(|err| UpdateError::Install(format!("write temp: {err}")))?;
    temp.flush()
        .map_err(|err| UpdateError::Install(format!("flush temp: {err}")))?;
    temp.persist(path)
        .map_err(|err| UpdateError::Install(format!("persist {}: {err}", path.display())))?;
    Ok(())
}

fn replace_file(staged: &Path, final_path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        let mut last_error = None;
        for attempt in 0..25 {
            match replace_file_once(staged, final_path) {
                Ok(()) => return Ok(()),
                Err(error) if windows_replace_retryable(&error) && attempt < 24 => {
                    last_error = Some(error);
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                Err(error) => return Err(error),
            }
        }
        Err(last_error.expect("replace retry loop records an error"))
    }

    #[cfg(not(windows))]
    replace_file_once(staged, final_path)
}

fn replace_file_once(staged: &Path, final_path: &Path) -> std::io::Result<()> {
    if final_path.exists() {
        if let Err(err) = fs::remove_file(final_path) {
            // On Windows, deleting a running image may fail; try rename aside.
            let aside = final_path.with_extension("old");
            let _ = fs::remove_file(&aside);
            fs::rename(final_path, &aside)?;
            let _ = err;
        }
    }
    fs::rename(staged, final_path)
}

#[cfg(windows)]
fn windows_replace_retryable(error: &std::io::Error) -> bool {
    matches!(error.raw_os_error(), Some(5 | 32 | 33 | 183))
        || error.kind() == std::io::ErrorKind::PermissionDenied
}

fn rollback_from_backup(install_dir: &Path, backup: &Path, names: &[String]) -> UpdateResult<()> {
    for name in names {
        let src = backup.join(name);
        let dest = install_dir.join(name);
        if !src.exists() {
            match fs::remove_file(&dest) {
                Ok(()) => continue,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(UpdateError::Install(format!(
                        "rollback remove {} failed: {err}",
                        dest.display()
                    )));
                }
            }
        }
        let restore = install_dir.join(format!(".{name}.rollback-{}", std::process::id()));
        fs::copy(&src, &restore).map_err(|err| {
            UpdateError::Install(format!("stage rollback {} failed: {err}", dest.display()))
        })?;
        replace_file(&restore, &dest).map_err(|err| {
            let _ = fs::remove_file(&restore);
            UpdateError::Install(format!("rollback {} failed: {err}", dest.display()))
        })?;
    }
    Ok(())
}
