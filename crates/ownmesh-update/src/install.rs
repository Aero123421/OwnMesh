//! Staging, atomic multi-binary install, backup, and rollback.

use crate::error::{UpdateError, UpdateResult};
use crate::platform::{binary_file_name, REQUIRED_BINARIES};
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// Result of a successful apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplyReport {
    /// Install directory that received the binaries.
    pub install_dir: PathBuf,
    /// Backup directory retaining the previous binaries (if any existed).
    pub backup_dir: Option<PathBuf>,
    /// Names of binaries written.
    pub written: Vec<String>,
    /// True when a Windows pending-replace helper was scheduled.
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

    let staging = install_dir.join(format!(".ownmesh-staging-{version_label}"));
    let backup = install_dir.join(format!(".ownmesh-backup-{version_label}"));
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

    // Backup existing binaries (best-effort copy).
    let mut backed_up = Vec::new();
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
            backed_up.push(name.clone());
        }
    }

    #[cfg(windows)]
    let mut pending_windows_replace = false;
    #[cfg(not(windows))]
    let pending_windows_replace = false;
    let mut replaced = Vec::new();

    // Swap staged → final. On failure, rollback from backup.
    let swap_result = (|| -> UpdateResult<()> {
        for name in &required_names {
            let staged = staging.join(name);
            let final_path = install_dir.join(name);
            match replace_file(&staged, &final_path) {
                Ok(()) => replaced.push(name.clone()),
                Err(err) => {
                    #[cfg(windows)]
                    {
                        if is_sharing_violation(&err) && name == "ownmesh.exe" {
                            // Leave staged file and write a helper; other binaries already swapped stay.
                            // But requirement forbids partial multi-binary update — so if any non-self
                            // binary remains, we still rollback everything except schedule self-replace
                            // only when this is the sole remaining failure after others succeeded.
                            // Simpler rule: if *any* replace fails with sharing violation on Windows,
                            // attempt helper only when all other binaries already replaced and only
                            // ownmesh.exe remains locked.
                            if name.as_str() == binary_file_name("ownmesh")
                                && replaced.len() + 1 == required_names.len()
                            {
                                write_windows_replace_helper(install_dir, &staged, &final_path)?;
                                pending_windows_replace = true;
                                replaced.push(name.clone());
                                continue;
                            }
                        }
                    }
                    let _ = err;
                    return Err(UpdateError::Install(format!(
                        "replace {} failed",
                        final_path.display()
                    )));
                }
            }
        }
        Ok(())
    })();

    if let Err(err) = swap_result {
        let _ = rollback_from_backup(install_dir, &backup, &required_names);
        let _ = fs::remove_dir_all(&staging);
        return Err(err);
    }

    let _ = fs::remove_dir_all(&staging);
    let backup_dir = if backed_up.is_empty() {
        let _ = fs::remove_dir_all(&backup);
        None
    } else {
        Some(backup)
    };

    Ok(ApplyReport {
        install_dir: install_dir.to_path_buf(),
        backup_dir,
        written: replaced,
        pending_windows_replace,
    })
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

fn rollback_from_backup(install_dir: &Path, backup: &Path, names: &[String]) -> UpdateResult<()> {
    for name in names {
        let src = backup.join(name);
        if !src.exists() {
            continue;
        }
        let dest = install_dir.join(name);
        fs::copy(&src, &dest).map_err(|err| {
            UpdateError::Install(format!("rollback {} failed: {err}", dest.display()))
        })?;
    }
    Ok(())
}

#[cfg(windows)]
fn is_sharing_violation(err: &std::io::Error) -> bool {
    err.raw_os_error() == Some(32) || err.kind() == std::io::ErrorKind::PermissionDenied
}

#[cfg(windows)]
fn write_windows_replace_helper(
    install_dir: &Path,
    staged: &Path,
    final_path: &Path,
) -> UpdateResult<()> {
    let helper = install_dir.join("ownmesh-update-helper.cmd");
    let staged_name = staged
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("ownmesh.exe.new");
    // Keep staged next to helper under a stable name.
    let pending = install_dir.join("ownmesh.exe.pending");
    fs::copy(staged, &pending)
        .map_err(|err| UpdateError::Install(format!("stage pending replace: {err}")))?;
    let script = format!(
        "@echo off\r\n\
         setlocal\r\n\
         rem OwnMesh pending self-replace helper — do not edit.\r\n\
         :wait\r\n\
         ping -n 2 127.0.0.1 >nul\r\n\
         del /f /q \"{final}\" 2>nul\r\n\
         if exist \"{final}\" goto wait\r\n\
         move /y \"{pending}\" \"{final}\" >nul\r\n\
         del /f /q \"%~f0\" >nul 2>nul\r\n\
         exit /b 0\r\n",
        final = final_path.display(),
        pending = pending.display(),
    );
    let _ = staged_name;
    fs::write(&helper, script)
        .map_err(|err| UpdateError::Install(format!("write replace helper: {err}")))?;
    Ok(())
}
