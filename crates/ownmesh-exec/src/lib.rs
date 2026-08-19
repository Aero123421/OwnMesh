//! `OwnMesh` structured command and process execution.
//!
//! Provides shell-free structured commands, optional raw shell, timeouts,
//! process-tree kill best-effort, bounded output, and an idempotency journal.

#![allow(
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_borrows_for_generic_args
)]

mod prepared;

pub use prepared::{prepare_executable, prepare_executable_with_interpreter, PreparedExecutable};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::watch;

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Crate version string from Cargo package metadata.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Execution errors.
#[derive(Debug, Error)]
pub enum ExecError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("command timed out after {0:?}")]
    Timeout(Duration),
    #[error("empty program")]
    EmptyProgram,
    #[error("idempotency conflict for key {0}")]
    IdempotencyConflict(String),
    #[error("journal error: {0}")]
    Journal(String),
    #[error("resource limit: {0}")]
    ResourceLimit(String),
    #[error("cancelled")]
    Cancelled,
    /// Process spawn failed. The message carries an actionable Windows hint
    /// when the failure is Win32 error 193 (invalid executable format), which
    /// npm-style extensionless shims trigger before the resolver fix.
    #[error("{0}")]
    Spawn(String),
}

/// Result alias.
pub type ExecResult<T> = Result<T, ExecError>;

/// How the program is invoked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandKind {
    /// `program` + argv, no shell.
    Structured,
    /// Platform shell (`cmd.exe /C` or `sh -c`).
    RawShell,
}

impl CommandKind {
    /// Stable policy / facts string (`structured` | `raw_shell`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Structured => "structured",
            Self::RawShell => "raw_shell",
        }
    }

    /// Parse a client-supplied kind string (unknown → structured).
    #[must_use]
    pub fn parse_requested(raw: Option<&str>) -> Self {
        match raw.map(str::trim) {
            Some(s) if s.eq_ignore_ascii_case("raw_shell") || s.eq_ignore_ascii_case("raw") => {
                Self::RawShell
            }
            _ => Self::Structured,
        }
    }
}

/// Known shell program stems (matched case-insensitively; Windows `.exe` stripped).
const SHELL_BINARIES: &[&str] = &[
    "sh",
    "bash",
    "dash",
    "zsh",
    "ksh",
    "csh",
    "tcsh",
    "fish",
    "cmd",
    "powershell",
    "pwsh",
];

/// Interpreter / script-host stems always classified as raw (conservative).
const INTERPRETER_BINARIES: &[&str] = &[
    "python",
    "python2",
    "python3",
    "py",
    "node",
    "nodejs",
    "deno",
    "bun",
    "ruby",
    "perl",
    "php",
    "lua",
    "tclsh",
    "wish",
    "osascript",
    "wscript",
    "cscript",
    "mshta",
    "csi",
    "pwsh-preview",
];

/// Script-like extensions that must never be treated as pinned native binaries.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "bat", "cmd", "ps1", "psm1", "psd1", "vbs", "vbe", "js", "jse", "wsf", "wsh", "msc", "sh",
    "bash", "zsh", "ksh", "csh", "fish", "py", "rb", "pl", "php", "lua", "tcl", "command", "cgi",
];

/// Filesystem identity + content digest pinned at classification / approval time.
///
/// Re-checked immediately before spawn so a path-preserving binary/script swap
/// cannot execute a different payload after human approval.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutablePin {
    /// Exact absolute invocation or backing path that was inspected.
    pub path: String,
    /// Hex SHA-256 of the full file contents at pin time.
    pub content_sha256: String,
    /// Byte length at pin time (fast reject before hashing).
    pub len: u64,
    /// Platform volume/device identity (Unix `st_dev`; Windows volume serial).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    /// Platform file identity (Unix inode; Windows file index).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
    /// Identity of the invocation directory entry before symlink/reparse
    /// traversal. These fields bind proxy semantics as well as the target
    /// image, so deleting and recreating an otherwise identical proxy still
    /// requires re-authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_device: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_inode: Option<u64>,
    /// Exact symlink/reparse target recorded for proxy invocations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_target: Option<String>,
    /// Policy classification recorded with the pin (`structured` / `raw_shell`).
    pub policy_kind: String,
}

/// Flags that turn a shell binary into an arbitrary command interpreter.
/// Kept for diagnostics / callers; classification no longer depends on them.
const SHELL_EXEC_FLAGS: &[&str] = &["-c", "/c", "/k", "-command", "-encodedcommand", "-enc"];

/// Basename of a program path (`/bin/bash`, `C:\\Windows\\System32\\cmd.exe` → `bash` / `cmd.exe`).
#[must_use]
pub fn program_basename(program: &str) -> &str {
    let trimmed = program.trim().trim_matches('"').trim_matches('\'');
    let bytes = trimmed.as_bytes();
    let mut last = 0usize;
    for (i, b) in bytes.iter().copied().enumerate() {
        if b == b'/' || b == b'\\' {
            last = i + 1;
        }
    }
    &trimmed[last..]
}

/// Strip a trailing Windows executable extension (`.exe`, `.bat`, `.cmd`, `.com`).
fn strip_windows_executable_ext(name: &str) -> &str {
    const EXTS: &[&str] = &[".exe", ".bat", ".cmd", ".com"];
    for ext in EXTS {
        if name.len() > ext.len() && name[name.len() - ext.len()..].eq_ignore_ascii_case(ext) {
            return &name[..name.len() - ext.len()];
        }
    }
    name
}

fn known_shell_name(program: &str) -> bool {
    let base = program_basename(program);
    if base.is_empty() {
        return false;
    }
    let stem = strip_windows_executable_ext(base);
    !stem.is_empty()
        && SHELL_BINARIES
            .iter()
            .any(|name| stem.eq_ignore_ascii_case(name))
}

fn known_interpreter_name(program: &str) -> bool {
    let base = program_basename(program);
    if base.is_empty() {
        return false;
    }
    let stem = strip_windows_executable_ext(base);
    !stem.is_empty()
        && INTERPRETER_BINARIES
            .iter()
            .any(|name| stem.eq_ignore_ascii_case(name))
}

fn script_extension(program: &str) -> bool {
    let base = program_basename(program);
    let Some(dot) = base.rfind('.') else {
        return false;
    };
    let ext = &base[dot + 1..];
    !ext.is_empty()
        && SCRIPT_EXTENSIONS
            .iter()
            .any(|candidate| ext.eq_ignore_ascii_case(candidate))
}

fn path_has_shebang(path: &Path) -> bool {
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    use std::io::Read;
    let mut magic = [0u8; 2];
    matches!(file.read(&mut magic), Ok(2) if &magic == b"#!")
}

fn is_script_or_interpreter_in_dir(program: &str, cwd: Option<&Path>) -> bool {
    // Script-like payloads (`.sh`/`.py`/`.cmd`/`.bat`/`.ps1`/…) and known
    // interpreters are always classified raw on every platform: the payload
    // is shell or script-host content, so a policy denying `raw_shell` must
    // deny it too. This deliberately includes Windows batch shims
    // (`.cmd`/`.bat`): `cmd.exe` interprets their file content with full
    // shell semantics even when the argv is passed literally, so classifying
    // them as structured would let a raw_shell-denying policy authorize shell
    // execution. Resolution (PATHEXT ordering) is a separate concern from
    // policy classification.
    let script_like = |s: &str| known_interpreter_name(s) || script_extension(s);
    if script_like(program) {
        return true;
    }
    let resolved = resolve_executable_path(program, cwd);
    let Some(path) = resolved.as_deref() else {
        return false;
    };
    if path.to_str().is_some_and(script_like) {
        return true;
    }
    path_has_shebang(path)
}

/// Hard ceiling for structured executable pin/revalidation hashing.
/// Prevents a remote full-access structured command from forcing unbounded
/// `read()` of a huge regular file before policy execution.
pub const MAX_EXECUTABLE_PIN_BYTES: u64 = ownmesh_domain::MAX_STRUCTURED_EXECUTABLE_BYTES;

/// Hard ceiling for the on-disk idempotency journal file.
pub const MAX_JOURNAL_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Stream SHA-256 of a regular file up to `max_bytes` without unbounded allocation.
fn hash_open_file_bounded(
    file: &mut File,
    display_path: &Path,
    expected_len: u64,
    max_bytes: u64,
) -> ExecResult<String> {
    if expected_len > max_bytes {
        return Err(ExecError::ResourceLimit(format!(
            "executable exceeds {max_bytes} byte pin budget: {} ({expected_len} bytes)",
            display_path.display()
        )));
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > max_bytes {
            return Err(ExecError::ResourceLimit(format!(
                "executable exceeded {max_bytes} byte pin budget while hashing: {}",
                display_path.display()
            )));
        }
        hasher.update(&buf[..n]);
    }
    if total != expected_len {
        return Err(ExecError::Journal(format!(
            "executable length changed while hashing ({expected_len} -> {total})"
        )));
    }
    Ok(hex::encode(hasher.finalize()))
}

fn file_has_shebang(file: &mut File) -> ExecResult<bool> {
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0_u8; 2];
    let read = file.read(&mut magic)?;
    file.seek(SeekFrom::Start(0))?;
    Ok(read == 2 && magic == *b"#!")
}

#[cfg(unix)]
fn path_entry_identity(path: &Path) -> ExecResult<(Option<u64>, Option<u64>)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path)?;
    Ok((Some(metadata.dev()), Some(metadata.ino())))
}

#[cfg(windows)]
fn windows_handle_identity(file: &File) -> ExecResult<(Option<u64>, Option<u64>)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut information: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: `file` owns a valid handle for the duration of the call and the
    // output structure is fully initialized before it is read.
    if unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle().cast(),
            std::ptr::from_mut(&mut information),
        )
    } == 0
    {
        return Err(ExecError::Io(std::io::Error::last_os_error()));
    }
    let index =
        (u64::from(information.nFileIndexHigh) << 32) | u64::from(information.nFileIndexLow);
    Ok((
        Some(u64::from(information.dwVolumeSerialNumber)),
        Some(index),
    ))
}

#[cfg(windows)]
fn path_entry_identity(path: &Path) -> ExecResult<(Option<u64>, Option<u64>)> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    let file = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)?;
    windows_handle_identity(&file)
}

#[cfg(not(any(unix, windows)))]
fn path_entry_identity(_path: &Path) -> ExecResult<(Option<u64>, Option<u64>)> {
    Ok((None, None))
}

#[cfg(unix)]
fn open_file_identity(file: &File) -> ExecResult<(Option<u64>, Option<u64>)> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((Some(metadata.dev()), Some(metadata.ino())))
}

#[cfg(windows)]
fn open_file_identity(file: &File) -> ExecResult<(Option<u64>, Option<u64>)> {
    windows_handle_identity(file)
}

#[cfg(not(any(unix, windows)))]
fn open_file_identity(_file: &File) -> ExecResult<(Option<u64>, Option<u64>)> {
    Ok((None, None))
}

fn current_link_target(path: &Path) -> ExecResult<Option<String>> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Ok(Some(
            std::fs::read_link(path)?.to_string_lossy().into_owned(),
        ));
    }
    Ok(None)
}

/// Capture device/inode/content digest for a structured executable path.
///
/// # Errors
///
/// Returns an error when the path cannot be read or is not a regular file.
pub fn pin_executable(path: &Path, policy_kind: CommandKind) -> ExecResult<ExecutablePin> {
    let (path_device, path_inode) = path_entry_identity(path)?;
    let link_target = current_link_target(path)?;
    let mut file = File::open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(ExecError::Journal(format!(
            "executable pin requires a regular file: {}",
            path.display()
        )));
    }
    let content_sha256 =
        hash_open_file_bounded(&mut file, path, meta.len(), MAX_EXECUTABLE_PIN_BYTES)?;
    let (device, inode) = open_file_identity(&file)?;
    if path_entry_identity(path)? != (path_device, path_inode)
        || current_link_target(path)? != link_target
    {
        return Err(ExecError::Journal(
            "executable invocation entry changed while pinning; retry authorization".into(),
        ));
    }
    Ok(ExecutablePin {
        path: path.to_string_lossy().into_owned(),
        content_sha256,
        len: meta.len(),
        device,
        inode,
        path_device,
        path_inode,
        link_target,
        policy_kind: policy_kind.as_str().to_owned(),
    })
}

/// Re-read `path` and ensure it still matches `pin` (fail closed on any drift).
///
/// # Errors
///
/// Returns [`ExecError::Journal`] describing the mismatch / IO failure.
pub fn verify_executable_pin(path: &Path, pin: &ExecutablePin) -> ExecResult<()> {
    verify_path_entry_pin(path, pin)?;
    let mut file = File::open(path).map_err(|e| {
        ExecError::Journal(format!(
            "executable pin revalidation failed for {}: {e}",
            path.display()
        ))
    })?;
    verify_open_file_pin(&mut file, path, pin)?;
    verify_path_entry_pin(path, pin)?;
    Ok(())
}

fn verify_path_entry_pin(path: &Path, pin: &ExecutablePin) -> ExecResult<()> {
    let actual_link = current_link_target(path).map_err(|error| {
        ExecError::Journal(format!(
            "executable invocation entry revalidation failed for {}: {error}",
            path.display()
        ))
    })?;
    #[cfg(any(unix, windows))]
    if pin.path_device.is_none() || pin.path_inode.is_none() {
        return Err(ExecError::Journal(
            "legacy executable pin lacks invocation entry identity; request must be re-authorized"
                .into(),
        ));
    }
    let actual_identity = path_entry_identity(path).map_err(|error| {
        ExecError::Journal(format!(
            "executable invocation identity revalidation failed for {}: {error}",
            path.display()
        ))
    })?;
    if (pin.path_device.is_some() || pin.path_inode.is_some())
        && actual_identity != (pin.path_device, pin.path_inode)
    {
        return Err(ExecError::Journal(
            "executable invocation entry identity drifted; request must be re-authorized".into(),
        ));
    }
    if actual_link != pin.link_target {
        return Err(ExecError::Journal(
            "executable invocation link target drifted; request must be re-authorized".into(),
        ));
    }
    Ok(())
}

fn verify_open_file_pin(file: &mut File, path: &Path, pin: &ExecutablePin) -> ExecResult<()> {
    let meta = file.metadata().map_err(|e| {
        ExecError::Journal(format!(
            "executable handle revalidation failed for {}: {e}",
            path.display()
        ))
    })?;
    if !meta.is_file() {
        return Err(ExecError::Journal(format!(
            "executable is no longer a regular file: {}",
            path.display()
        )));
    }
    if meta.len() != pin.len {
        return Err(ExecError::Journal(format!(
            "executable length drifted before execution ({} -> {})",
            pin.len,
            meta.len()
        )));
    }
    let (device, inode) = open_file_identity(file)?;
    if (pin.device.is_some() || pin.inode.is_some()) && (device != pin.device || inode != pin.inode)
    {
        return Err(ExecError::Journal(
            "executable device/inode drifted before execution; request must be re-authorized"
                .into(),
        ));
    }
    let digest =
        hash_open_file_bounded(file, path, meta.len(), MAX_EXECUTABLE_PIN_BYTES).map_err(|e| {
            ExecError::Journal(format!(
                "executable content revalidation failed for {}: {e}",
                path.display()
            ))
        })?;
    if digest != pin.content_sha256 {
        return Err(ExecError::Journal(
            "executable content digest drifted before execution; request must be re-authorized"
                .into(),
        ));
    }
    if pin.policy_kind == CommandKind::Structured.as_str()
        && (file_has_shebang(file)? || path.to_str().is_some_and(script_extension))
    {
        // A structured pin must never point at a shell/script payload —
        // including a Windows batch shim (`.cmd`/`.bat`), whose file content
        // `cmd.exe` interprets with full shell semantics. Such a file must be
        // re-authorized as raw_shell before execution.
        return Err(ExecError::Journal(
            "executable became a script/shebang payload before execution; request must be re-authorized"
                .into(),
        ));
    }
    Ok(())
}

/// Windows no-extension candidate ordering following `PATHEXT` semantics.
///
/// The default `PATHEXT` is `.COM;.EXE;.BAT;.CMD`.  Only extensions that the
/// platform can actually invoke directly (`exe`, `com`, `cmd`, `bat`) are kept:
/// `.ps1`/`.sh` siblings are *not* invocable by `CreateProcess` and must never
/// win over a real shim (npm ships an extensionless POSIX shim next to
/// `name.cmd`/`name.ps1`; selecting the extensionless sibling fails with Win32
/// error 193).  The bare name is always *last* so a genuine extensionless
/// native binary stays reachable when no invocable sibling exists.
///
/// Pure so the ordering can be unit-tested on any platform.
#[must_use]
pub fn windows_pathext_candidates(raw: &str, pathext: Option<&str>) -> Vec<String> {
    const INVOCABLE: [&str; 4] = ["exe", "com", "cmd", "bat"];
    const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";
    // A caller-supplied extension (e.g. `pi.cmd`) is used verbatim and never
    // goes through PATHEXT ordering.
    if Path::new(raw).extension().is_some() {
        return vec![raw.to_string()];
    }
    let mut seen = Vec::new();
    let mut out = Vec::new();
    for entry in pathext.unwrap_or(DEFAULT_PATHEXT).split(';') {
        let ext = entry.trim().trim_start_matches('.');
        if ext.is_empty() {
            continue;
        }
        let lower = ext.to_ascii_lowercase();
        if !INVOCABLE.contains(&lower.as_str()) || seen.contains(&lower) {
            continue;
        }
        seen.push(lower);
        out.push(format!("{raw}.{ext}"));
    }
    out.push(raw.to_string());
    out
}

/// Ordered per-directory candidate paths for a program name.
///
/// With `windows_style` (Windows only) and a caller-supplied name without an
/// extension, the `PATHEXT` invocable siblings come first; otherwise the bare
/// name is the only candidate (Unix semantics unchanged).
#[must_use]
pub fn executable_candidates_in_directory(
    directory: &Path,
    raw: &str,
    windows_style: bool,
    pathext: Option<&str>,
) -> Vec<PathBuf> {
    if windows_style && Path::new(raw).extension().is_none() {
        windows_pathext_candidates(raw, pathext)
            .into_iter()
            .map(|name| directory.join(name))
            .collect()
    } else {
        vec![directory.join(raw)]
    }
}

/// Deterministic, shell-free user-local CLI search directories (Unix).
///
/// Mirrors the common login-shell `PATH` additions (`~/.local/bin`, Cargo,
/// Nix, npm-global and NVM node-version bins) without loading any shell
/// startup file.  The daemon service inherits a system-only `PATH`, so these
/// directories make user-installed developer CLIs discoverable with the exact
/// same per-directory candidate logic used for process invocation — there is
/// no detect-ready-then-spawn-bare-name gap.  Windows returns no extra
/// directories because user bins are already reachable through the user PATH.
#[must_use]
pub fn user_cli_search_dirs(home: Option<&Path>) -> Vec<PathBuf> {
    #[cfg(windows)]
    {
        let _ = home;
        Vec::new()
    }
    #[cfg(not(windows))]
    {
        fn push_unique(dirs: &mut Vec<PathBuf>, dir: PathBuf) {
            if !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
        let mut dirs: Vec<PathBuf> = Vec::new();
        if let Some(home) = home {
            for sub in [
                ".local/bin",
                ".cargo/bin",
                ".nix-profile/bin",
                ".npm-global/bin",
            ] {
                push_unique(&mut dirs, home.join(sub));
            }
            // NVM layouts: ~/.nvm/versions/node/<version>/bin. Only version-like
            // directories (e.g. `v22.14.1`) are searched; symlinks such as
            // `current` are skipped so the order is deterministic and duplicate
            // bins are not searched twice.
            let nvm_node = home.join(".nvm").join("versions").join("node");
            if let Ok(entries) = std::fs::read_dir(&nvm_node) {
                let mut versions: Vec<String> = entries
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
                    .filter_map(|entry| entry.file_name().into_string().ok())
                    .filter(|name| {
                        name.len() > 1
                            && name.starts_with('v')
                            && name[1..].chars().all(|c| c.is_ascii_digit() || c == '.')
                    })
                    .collect();
                versions.sort();
                for version in versions {
                    push_unique(&mut dirs, nvm_node.join(version).join("bin"));
                }
            }
        }
        push_unique(
            &mut dirs,
            PathBuf::from("/nix/var/nix/profiles/default/bin"),
        );
        dirs
    }
}

/// True when `path` is a regular file the platform can actually spawn.
///
/// On Unix this additionally requires at least one execute bit, so a
/// non-executable sibling (e.g. a leftover npm extensionless shim without
/// its shebang bit) can never be reported "installed" while spawning it
/// would fail with `EACCES`.  Windows has no exec bits: the PATHEXT
/// extension ordering carries invocability, so the file attribute alone is
/// the correct check there.
#[must_use]
pub fn is_launchable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// Resolve a bare program name across explicit search directories using the
/// same candidate ordering as [`resolve_executable_invocation_path`].
///
/// `dirs` are searched in order; relative entries are resolved against `cwd`.
/// `windows_style` enables `PATHEXT` candidate ordering (callers pass
/// `cfg!(windows)`), and `pathext` supplies the extension list (callers pass
/// `std::env::var("PATHEXT")`); both are parameters so the Windows ordering
/// can be unit-tested on any platform without mutating process env.  This is
/// the pure core shared by the daemon, profile detection, review pinning and
/// session launch so all four consumers agree about resolution.
#[must_use]
pub fn resolve_executable_in_dirs(
    program: &str,
    dirs: &[PathBuf],
    cwd: Option<&Path>,
    windows_style: bool,
    pathext: Option<&str>,
) -> Option<PathBuf> {
    let raw = program.trim().trim_matches('"').trim_matches('\'');
    if raw.is_empty() {
        return None;
    }
    for directory in dirs {
        let directory = if directory.is_absolute() {
            directory.clone()
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(directory)
        };
        for candidate in executable_candidates_in_directory(&directory, raw, windows_style, pathext)
        {
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

/// Like [`resolve_executable_in_dirs`] but skips candidates that are not
/// actually launchable ([`is_launchable_file`]).  Profile detection uses this
/// so a non-executable Unix file can never be reported "installed" while the
/// launch path it yields would fail at spawn.
#[must_use]
pub fn resolve_launchable_executable_in_dirs(
    program: &str,
    dirs: &[PathBuf],
    cwd: Option<&Path>,
    windows_style: bool,
    pathext: Option<&str>,
) -> Option<PathBuf> {
    let raw = program.trim().trim_matches('"').trim_matches('\'');
    if raw.is_empty() {
        return None;
    }
    for directory in dirs {
        let directory = if directory.is_absolute() {
            directory.clone()
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(directory)
        };
        for candidate in executable_candidates_in_directory(&directory, raw, windows_style, pathext)
        {
            if is_launchable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

/// Why a launch argv could not be produced from a requested program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpawnResolveError {
    /// The program could not be resolved to a launchable executable (not on
    /// PATH/user-local dirs, or not a launchable file).
    NotFound,
    /// Windows batch launch: a script path or argument contains characters
    /// that `cmd.exe /c` would reinterpret (embedded quotes, `%`/`!`
    /// expansion, control characters, or cmd metacharacters that cannot be
    /// quoted by the PTY spawner). Launching would change the requested argv,
    /// so the request fails closed.
    CmdUnsafeArgument,
}

impl std::fmt::Display for SpawnResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SpawnResolveError::NotFound => write!(f, "executable could not be resolved"),
            SpawnResolveError::CmdUnsafeArgument => write!(
                f,
                "argument cannot be passed through cmd.exe safely (quotes, %, !, or unquoted cmd metacharacters)"
            ),
        }
    }
}

/// True when `token` would be mangled by `cmd.exe /c` parsing no matter how
/// it is quoted: embedded quotes (the PTY spawner re-escapes them in a way
/// cmd does not understand), `%` (always expanded), `!` (delayed expansion
/// cannot be guaranteed off for every child), and control characters.
fn cmd_always_unsafe(token: &str) -> bool {
    token
        .chars()
        .any(|c| matches!(c, '"' | '%' | '!') || c.is_control())
}

/// True when `token` contains a character cmd interprets *unquoted* on a
/// command line: command separator/redirection/grouping/escape.
fn cmd_bare_unsafe(token: &str) -> bool {
    token
        .chars()
        .any(|c| matches!(c, '&' | '|' | '<' | '>' | '(' | ')' | '^'))
}

/// True when `token` can be passed as one *separate* argv entry to a spawner
/// that quotes tokens containing whitespace (portable-pty `append_quoted`).
/// Quoted cmd metacharacters are literal, so a token with whitespace (and
/// therefore quoted) may safely contain `& | < > ( ) ^`; a bare token with
/// those characters cannot.
fn cmd_token_safe(token: &str) -> bool {
    if cmd_always_unsafe(token) {
        return false;
    }
    if token.contains(char::is_whitespace) {
        return true;
    }
    !cmd_bare_unsafe(token)
}

/// Resolve a launch argv (program + args) into something the platform can
/// actually spawn, using the shared resolution semantics (PATH + user-local
/// dirs, PATHEXT ordering on Windows).
///
/// - Unix: `argv[0]` is replaced with the resolved absolute path; resolution
///   failure returns an error so the caller never hands a bare name to a
///   spawner that would guess differently.
/// - Windows: `argv[0]` is replaced with the resolved invocable path.  When
///   the resolved target is a `.cmd`/`.bat` batch script, the argv is
///   rewritten to the documented `cmd.exe /e:ON /v:OFF /d /s /c call ...`
///   form because `CreateProcess` cannot execute batch files directly (Win32
///   error 193) — see the [CreateProcess documentation].  Tokens that cannot
///   be represented safely fail closed with
///   [`SpawnResolveError::CmdUnsafeArgument`] instead of producing a command
///   line that differs from the requested argv.
///
/// [CreateProcess documentation]: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessa
pub fn resolve_spawn_argv(
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
) -> Result<Vec<String>, SpawnResolveError> {
    // `dirs` is only extended on Unix (user-local CLI discovery); Windows
    // keeps the inherited user PATH, so the `mut` is unused there. An unset
    // `PATH` is treated as empty (never a hard failure) so the deterministic
    // user-local dirs are still searched — matching profile discovery, which
    // must not disagree with spawn resolution (P1-D).
    #[cfg_attr(windows, allow(unused_mut))]
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        dirs.extend(user_cli_search_dirs(home.as_deref()));
    }
    resolve_spawn_argv_in_dirs(
        program,
        args,
        &dirs,
        cwd,
        cfg!(windows),
        std::env::var("PATHEXT").ok().as_deref(),
    )
}

/// Pure core of [`resolve_spawn_argv`]; parameters keep the Windows rewrite
/// unit-testable on any platform.
pub fn resolve_spawn_argv_in_dirs(
    program: &str,
    args: &[String],
    dirs: &[PathBuf],
    cwd: Option<&Path>,
    windows_style: bool,
    pathext: Option<&str>,
) -> Result<Vec<String>, SpawnResolveError> {
    let raw = program.trim().trim_matches('"').trim_matches('\'');
    if raw.is_empty() {
        return Err(SpawnResolveError::NotFound);
    }
    let path = Path::new(raw);
    // Absolute paths (and explicit relative paths) are launchable only if the
    // exact file is a launchable regular file — never re-searched through dirs.
    // On Windows, when the caller supplied no extension, PATHEXT semantics
    // still apply: an invocable `.exe/.com/.cmd/.bat` sibling wins over an
    // extensionless file (npm-style POSIX shims fail with Win32 error 193).
    let resolved = if path.is_absolute() || raw.contains('/') || raw.contains('\\') {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(path)
        };
        if windows_style && Path::new(raw).extension().is_none() {
            let parent = candidate.parent().unwrap_or_else(|| Path::new("."));
            let name = candidate
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let mut found = None;
            for cand in executable_candidates_in_directory(parent, &name, true, pathext) {
                if is_launchable_file(&cand) {
                    found = Some(cand);
                    break;
                }
            }
            if let Some(found) = found {
                found
            } else if is_launchable_file(&candidate) {
                candidate
            } else {
                return Err(SpawnResolveError::NotFound);
            }
        } else if !is_launchable_file(&candidate) {
            return Err(SpawnResolveError::NotFound);
        } else {
            candidate
        }
    } else {
        resolve_launchable_executable_in_dirs(raw, dirs, cwd, windows_style, pathext)
            .ok_or(SpawnResolveError::NotFound)?
    };
    if windows_style {
        let ext = resolved
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase());
        if matches!(ext.as_deref(), Some("cmd" | "bat")) {
            // CreateProcess cannot exec batch files (Win32 error 193). Run
            // them through the documented cmd.exe form. Tokens are separate
            // argv entries so the spawner's own quoting applies to each; the
            // leading `call` keyword keeps cmd's /s quote-stripping rule from
            // ever seeing a leading quote (the line is used verbatim).
            return windows_batch_argv(&resolved, args);
        }
    }
    let mut out = Vec::with_capacity(args.len() + 1);
    out.push(resolved.to_string_lossy().into_owned());
    out.extend(args.iter().cloned());
    Ok(out)
}

/// Absolute path of `cmd.exe` used to launch Windows batch shims and raw
/// shell strings.
///
/// `CreateProcess` resolves a bare `cmd.exe` by searching the parent
/// executable's directory and the *current directory* before system
/// directories, so an attacker-controllable working directory could shadow
/// the real interpreter. A fully qualified `%SystemRoot%\System32\cmd.exe`
/// is immune to that hijack. Pure so the Windows behavior is unit-testable
/// on any platform; `system_root` is `%SystemRoot%` (fallback `C:\Windows`).
#[must_use]
pub fn windows_system_cmd_exe(system_root: Option<&str>) -> String {
    let root = system_root
        .map(str::trim)
        .filter(|root| !root.is_empty())
        .unwrap_or("C:\\Windows");
    format!("{}\\System32\\cmd.exe", root.trim_end_matches(['/', '\\']))
}

/// Build a `cmd.exe` argv that launches a `.cmd`/`.bat` script while
/// preserving argv semantics (P1-C).
///
/// `cmd.exe /e:ON /v:OFF /d /s /c call <script> <args...>` — each token is a
/// separate argv entry, so a spawner (portable-pty) quotes tokens containing
/// whitespace and cmd receives a verbatim line (the strip rule only fires on
/// a leading quote, and the line starts with `call`).  Tokens that cmd would
/// reinterpret — embedded quotes, `%`/`!` expansion, control characters, or
/// cmd metacharacters that would appear unquoted — fail closed with
/// [`SpawnResolveError::CmdUnsafeArgument`]: launching with a different argv
/// than the caller requested is never an option.
///
/// `argv[0]` is the pinned absolute `%SystemRoot%\System32\cmd.exe` (never a
/// bare name), so Windows process resolution cannot search the current
/// directory for a shadowing `cmd.exe`/`cmd.com`.
fn windows_batch_argv(script: &Path, args: &[String]) -> Result<Vec<String>, SpawnResolveError> {
    let script_s = script.to_string_lossy();
    if !cmd_token_safe(&script_s) {
        return Err(SpawnResolveError::CmdUnsafeArgument);
    }
    for arg in args {
        if !cmd_token_safe(arg) {
            return Err(SpawnResolveError::CmdUnsafeArgument);
        }
    }
    let mut out = Vec::with_capacity(args.len() + 7);
    out.push(windows_system_cmd_exe(
        std::env::var("SystemRoot").ok().as_deref(),
    ));
    out.push("/e:ON".into());
    out.push("/v:OFF".into());
    out.push("/d".into());
    out.push("/s".into());
    out.push("/c".into());
    out.push("call".into());
    out.push(script_s.into_owned());
    out.extend(args.iter().cloned());
    Ok(out)
}

/// Actionable spawn-error description (P2-H).
///
/// Win32 error 193 (invalid executable format) gets a specific hint about
/// extensionless npm-style POSIX shims; everything else keeps the raw OS
/// message so the underlying cause is never swallowed.
#[must_use]
pub fn describe_spawn_error(program: &str, source: &std::io::Error) -> String {
    if source.raw_os_error() == Some(193) {
        format!(
            "failed to start `{program}`: not a valid Win32 application (error 193). \
This usually means an extensionless POSIX shim was selected instead of its invocable \
`{program}.exe/.cmd/.bat` sibling; rerun after upgrading, or use an explicit executable \
extension so the invocable sibling wins"
        )
    } else {
        format!("failed to start `{program}`: {source}")
    }
}

/// Resolve the executable path used for process invocation without dereferencing
/// a symlink.  Some native proxy executables use their own filename to select
/// behavior (for example Rustup's `cargo.exe` proxy), so callers that need
/// those semantics must retain this path separately from the canonical backing
/// executable used for identity pinning.
///
/// Resolution uses the same launchable-file semantics as profile detection
/// (Unix: at least one execute bit; Windows: PATHEXT invocable-sibling
/// ordering), so command execution, review pinning, session launch and profile
/// discovery never disagree about which file is invocable: a non-executable
/// first PATH match is skipped exactly as discovery skips it, and an unset
/// `PATH` still searches the deterministic user-local dirs (P1-D).
#[must_use]
pub fn resolve_executable_invocation_path(program: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let absolute = |path: PathBuf| {
        if path.is_absolute() {
            Some(path)
        } else {
            std::env::current_dir().ok().map(|base| base.join(path))
        }
    };
    let raw = program.trim().trim_matches('"').trim_matches('\'');
    if raw.is_empty() {
        return None;
    }
    let path = Path::new(raw);
    if path.is_absolute() || raw.contains('/') || raw.contains('\\') {
        let candidate = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(path)
        };
        // Windows/PATHEXT semantics for explicit paths without an extension:
        // an invocable `.exe/.com/.cmd/.bat` sibling wins over an extensionless
        // file (npm-style POSIX shims fail with Win32 error 193). This keeps
        // profile detection, command execution, review pinning and session
        // launch agreeing about resolution (P1-C).
        if cfg!(windows) && Path::new(raw).extension().is_none() {
            let parent = candidate.parent().unwrap_or_else(|| Path::new("."));
            let name = candidate
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            for cand in executable_candidates_in_directory(
                parent,
                &name,
                true,
                std::env::var("PATHEXT").ok().as_deref(),
            ) {
                if is_launchable_file(&cand) {
                    return absolute(cand);
                }
            }
        }
        return is_launchable_file(&candidate)
            .then(|| absolute(candidate))
            .flatten();
    }

    // `dirs` is only extended on Unix (user-local CLI discovery); Windows
    // keeps the inherited user PATH, so the `mut` is unused there. An unset
    // `PATH` is treated as empty (never a hard failure) so the deterministic
    // user-local dirs are still searched — matching profile discovery, which
    // must not disagree with invocation resolution (P1-D).
    #[cfg_attr(windows, allow(unused_mut))]
    let mut dirs: Vec<PathBuf> =
        std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()).collect();
    // User-local CLI discovery (Unix).  The systemd user service inherits a
    // system-only PATH; appending deterministic user dirs keeps installed
    // developer CLIs resolvable without loading any shell startup file.
    #[cfg(not(windows))]
    {
        let home = std::env::var_os("HOME").map(PathBuf::from);
        dirs.extend(user_cli_search_dirs(home.as_deref()));
    }
    resolve_launchable_executable_in_dirs(
        raw,
        &dirs,
        cwd,
        cfg!(windows),
        std::env::var("PATHEXT").ok().as_deref(),
    )
    .and_then(absolute)
}

/// Resolve an executable through an explicit path or the current PATH.
///
/// The returned canonical backing path is suitable for executable identity
/// pinning.  If the invocation name itself carries semantics, retain
/// [`resolve_executable_invocation_path`] as well and revalidate both before
/// spawning.
#[must_use]
pub fn resolve_executable_path(program: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    std::fs::canonicalize(resolve_executable_invocation_path(program, cwd)?).ok()
}

fn is_shell_binary_in_dir(program: &str, cwd: Option<&Path>) -> bool {
    if known_shell_name(program) {
        return true;
    }
    resolve_executable_path(program, cwd)
        .as_deref()
        .and_then(Path::to_str)
        .is_some_and(known_shell_name)
}

fn program_is_env(program: &str, cwd: Option<&Path>) -> bool {
    let is_env_name = |name: &str| {
        strip_windows_executable_ext(program_basename(name)).eq_ignore_ascii_case("env")
    };
    is_env_name(program)
        || resolve_executable_path(program, cwd)
            .as_deref()
            .and_then(Path::to_str)
            .is_some_and(is_env_name)
}

/// True when `program` is a known shell binary, including a filesystem/PATH
/// symlink whose resolved target is a shell (path/basename/ext, case-insensitive).
///
/// Shell binaries are always policy-classified as [`CommandKind::RawShell`]
/// regardless of argv (including clustered flags like `-lc`).
#[must_use]
pub fn is_shell_binary(program: &str) -> bool {
    is_shell_binary_in_dir(program, None)
}

fn flag_basename(flag: &str) -> &str {
    // PowerShell accepts `-Command:value` and `/Command` forms.
    let f = flag.trim().trim_start_matches(['-', '/']);
    f.split_once([':', '=']).map(|(h, _)| h).unwrap_or(f)
}

/// True when a single argv token embeds a shell exec short-flag letter
/// (e.g. `-lc`, `-ic`, `-c`, `/c`, `/k`). Long options are handled separately.
fn clustered_short_flag_has_exec(raw: &str) -> bool {
    // Only pure short-flag clusters: leading - or / then only ASCII letters.
    let body = if let Some(b) = raw.strip_prefix('-').or_else(|| raw.strip_prefix('/')) {
        b
    } else {
        return false;
    };
    if body.is_empty() || !body.bytes().all(|b| b.is_ascii_alphabetic()) {
        return false;
    }
    // Single-letter long-form names already covered; detect c/k anywhere in cluster.
    // Avoid treating PowerShell `-Command` etc. as short clusters (length > 1 words
    // with mixed case long names fail the alphabetic-only short rule only when they
    // contain non-letters; "Command" is alphabetic — exclude known long names).
    if body.eq_ignore_ascii_case("command")
        || body.eq_ignore_ascii_case("encodedcommand")
        || body.eq_ignore_ascii_case("enc")
    {
        return true;
    }
    // Short-flag cluster: any `c` or `k` letter counts (bash `-lc`, `-ic`, …).
    // Long all-alpha tokens that are not known exec names are ignored here.
    if body.len() == 1 {
        return body.eq_ignore_ascii_case("c") || body.eq_ignore_ascii_case("k");
    }
    // Multi-letter: only treat as short cluster when all lowercase or typical
    // shell short-flag style (no long option shape). Heuristic: length <= 4 and
    // contains c or k (covers -lc/-ic/-ce/-ck without matching -Command via case).
    if body.len() <= 4
        && body
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_uppercase())
    {
        // If it looks like a long option word (contains a vowel run spelling a word),
        // require exact known exec names (already handled). "lc"/"ic"/"cl" are fine.
        let lower = body.to_ascii_lowercase();
        if lower == "command" || lower == "encodedcommand" || lower == "enc" {
            return true;
        }
        // Reject obvious long-option stems that happen to include c/k.
        const LONG_NON_EXEC: &[&str] = &[
            "login",
            "interactive",
            "noprofile",
            "nologo",
            "file",
            "help",
        ];
        if LONG_NON_EXEC.iter().any(|w| lower == *w) {
            return false;
        }
        return lower.bytes().any(|b| b == b'c' || b == b'k');
    }
    false
}

/// True when argv contains a shell command-execution flag (`-c`, `/C`, `-Command`, `-lc`, …).
///
/// Note: [`classify_command_kind`] treats **all** shell binaries as raw regardless of
/// flags; this helper remains for diagnostics and defense-in-depth checks.
#[must_use]
pub fn args_have_shell_exec_flag(args: &[String]) -> bool {
    args.iter().any(|arg| {
        let raw = arg.trim();
        if raw.is_empty() {
            return false;
        }
        // Exact forms first (preserve leading - or / for short flags).
        if SHELL_EXEC_FLAGS.iter().any(|f| raw.eq_ignore_ascii_case(f)) {
            return true;
        }
        // `-Command`, `-EncodedCommand`, `/C`, and joined forms like `-Command:Get-Process`.
        if !(raw.starts_with('-') || raw.starts_with('/')) {
            return false;
        }
        // Value-joined long/short forms: `-Command:Get-Process`, `/c:dir`, `-EncodedCommand:QQ==`.
        let name = flag_basename(raw);
        if name.eq_ignore_ascii_case("c")
            || name.eq_ignore_ascii_case("k")
            || name.eq_ignore_ascii_case("command")
            || name.eq_ignore_ascii_case("encodedcommand")
            || name.eq_ignore_ascii_case("enc")
        {
            return true;
        }
        // Clustered short flags: `-lc`, `-ic`, `-ce`, …
        clustered_short_flag_has_exec(raw)
    })
}

/// Server-side classification: never trust client `kind` alone.
///
/// **Any** invocation of a known shell binary is always
/// [`CommandKind::RawShell`], even when the client claims `structured` and even
/// when argv has no obvious `-c` / `-Command` flag (clustered `-lc`, bare
/// `bash script.sh`, version probes, etc. must not downgrade policy).
#[must_use]
pub fn classify_command_kind(
    requested: CommandKind,
    program: &str,
    args: &[String],
) -> CommandKind {
    classify_command_kind_in_dir(requested, program, args, None)
}

/// Server-side classification with the command's effective working directory.
/// This is required to resolve relative executable symlinks exactly as spawn will.
#[must_use]
pub fn classify_command_kind_in_dir(
    requested: CommandKind,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
) -> CommandKind {
    classify_command_kind_in_dir_with_style(requested, program, args, cwd)
}

/// Pure core of [`classify_command_kind_in_dir`].
///
/// Classification is platform-independent: a `.cmd`/`.bat` batch shim is
/// shell content on Windows exactly as a `.sh` script is on Unix, so it is
/// always `RawShell`. PATHEXT resolution (which sibling file wins) is a
/// separate concern handled by the resolver; it never downgrades policy.
fn classify_command_kind_in_dir_with_style(
    requested: CommandKind,
    program: &str,
    _args: &[String],
    cwd: Option<&Path>,
) -> CommandKind {
    // Classify every `env` invocation raw. This deliberately avoids duplicating
    // platform-specific `env -S` parsing/expansion rules (including nested env,
    // PATH reassignment, and GNU `\\_`/`${VAR}` expansion) in a security boundary.
    if matches!(requested, CommandKind::RawShell)
        || is_shell_binary_in_dir(program, cwd)
        || program_is_env(program, cwd)
        || is_script_or_interpreter_in_dir(program, cwd)
    {
        return CommandKind::RawShell;
    }
    CommandKind::Structured
}

/// Classify from the optional client-supplied kind string + argv.
#[must_use]
pub fn classify_from_request(kind: Option<&str>, program: &str, args: &[String]) -> CommandKind {
    classify_from_request_in_dir(kind, program, args, None)
}

/// Classify a request using its effective working directory for symlink resolution.
#[must_use]
pub fn classify_from_request_in_dir(
    kind: Option<&str>,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
) -> CommandKind {
    classify_command_kind_in_dir(CommandKind::parse_requested(kind), program, args, cwd)
}

/// Request to run a command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunRequest {
    pub kind: CommandKind,
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub stdin: Option<String>,
    /// Wall-clock timeout. `None` = no timeout.
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    /// Max combined captured bytes for stdout+stderr.
    #[serde(default = "default_max_output")]
    pub max_output_bytes: usize,
    /// Client-supplied idempotency key (optional).
    #[serde(default)]
    pub idempotency_key: Option<String>,
}

fn default_max_output() -> usize {
    256 * 1024
}

/// Absolute ceiling for captured stdout+stderr (bytes).
pub const HARD_MAX_OUTPUT_BYTES: usize = 1_000_000;
/// Absolute ceiling for wall-clock timeout (ms). Matches control-plane
/// `MCP_MAX_TIMEOUT_MS_HARD_CEILING` so an operator-raised Worker clamp can
/// still be enforced fail-closed on the device.
pub const HARD_MAX_TIMEOUT_MS: u64 = 3_600_000;

/// Captured command result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    /// Non-UTF-8 decoder used for stdout, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stdout_decoding: Option<OutputDecoding>,
    /// Non-UTF-8 decoder used for stderr, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stderr_decoding: Option<OutputDecoding>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub truncated: bool,
    /// OS process id observed after spawn (absent on journal replay).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    /// True when served from the idempotency journal.
    #[serde(default)]
    pub replayed: bool,
}

/// Durable state for one idempotency key.
///
/// `Complete` is untagged on disk for compatibility with journals written by
/// older OwnMesh versions. The reserved marker is written before a process is
/// spawned so a crash or failed completion write can never make the key
/// retriable.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
enum JournalEntry {
    InProgress(JournalMarker),
    Complete(RunResult),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalMarker {
    #[serde(rename = "__ownmesh_idempotency_state")]
    state: String,
}

impl JournalEntry {
    fn in_progress() -> Self {
        Self::InProgress(JournalMarker {
            state: "in_progress".into(),
        })
    }
}

/// Simple file-backed idempotency journal.
#[derive(Debug, Default)]
pub struct IdempotencyJournal {
    path: PathBuf,
    entries: HashMap<String, JournalEntry>,
}

impl IdempotencyJournal {
    /// Open or create a journal at `path`.
    pub fn open(path: impl Into<PathBuf>) -> ExecResult<Self> {
        let path = path.into();
        let entries = if path.exists() {
            let meta = std::fs::metadata(&path)?;
            if meta.len() > MAX_JOURNAL_FILE_BYTES {
                return Err(ExecError::Journal(format!(
                    "idempotency journal exceeds {MAX_JOURNAL_FILE_BYTES} byte budget ({})",
                    meta.len()
                )));
            }
            // Cap allocation to the pre-checked size (never unbounded read_to_string).
            use std::io::Read;
            let file = std::fs::File::open(&path)?;
            let mut raw = String::new();
            let limit = usize::try_from(meta.len().saturating_add(1))
                .unwrap_or(usize::MAX)
                .min(
                    usize::try_from(MAX_JOURNAL_FILE_BYTES.saturating_add(1)).unwrap_or(usize::MAX),
                );
            let mut take = file.take(u64::try_from(limit).unwrap_or(u64::MAX));
            take.read_to_string(&mut raw)?;
            if raw.len() as u64 > MAX_JOURNAL_FILE_BYTES {
                return Err(ExecError::Journal(format!(
                    "idempotency journal exceeds {MAX_JOURNAL_FILE_BYTES} byte budget"
                )));
            }
            serde_json::from_str(&raw).map_err(|e| ExecError::Journal(e.to_string()))?
        } else {
            HashMap::new()
        };
        Ok(Self { path, entries })
    }

    /// Lookup a previous completed result.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&RunResult> {
        match self.entries.get(key) {
            Some(JournalEntry::Complete(result)) => Some(result),
            _ => None,
        }
    }

    /// Whether execution started without a durably recorded completion.
    #[must_use]
    pub fn is_in_progress(&self, key: &str) -> bool {
        matches!(self.entries.get(key), Some(JournalEntry::InProgress(_)))
    }

    /// Durably reserve a key before starting its external side effect.
    fn begin(&mut self, key: String) -> ExecResult<()> {
        if self.entries.contains_key(&key) {
            return Err(ExecError::IdempotencyConflict(key));
        }
        let mut updated = self.entries.clone();
        updated.insert(key, JournalEntry::in_progress());
        self.flush(&updated)?;
        self.entries = updated;
        Ok(())
    }

    /// Record a result.
    ///
    /// The updated snapshot is persisted before it becomes visible in memory. If
    /// persistence fails, every existing entry remains exactly as it was. In
    /// particular, a failed completion write retains an existing in-progress
    /// marker and therefore rejects destructive retries.
    pub fn put(&mut self, key: String, result: RunResult) -> ExecResult<()> {
        let mut updated = self.entries.clone();
        updated.insert(key, JournalEntry::Complete(result));
        self.flush(&updated)?;
        self.entries = updated;
        Ok(())
    }

    /// Drop an in-progress reservation after cancel so a later authorized retry
    /// may re-run. Completed entries are never removed.
    pub fn clear_in_progress(&mut self, key: &str) -> ExecResult<()> {
        if !matches!(self.entries.get(key), Some(JournalEntry::InProgress(_))) {
            return Ok(());
        }
        let mut updated = self.entries.clone();
        updated.remove(key);
        self.flush(&updated)?;
        self.entries = updated;
        Ok(())
    }

    fn flush(&self, entries: &HashMap<String, JournalEntry>) -> ExecResult<()> {
        let raw =
            serde_json::to_string_pretty(entries).map_err(|e| ExecError::Journal(e.to_string()))?;
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        ownmesh_persist::write_atomically(&self.path, raw.as_bytes()).map_err(|e| {
            ExecError::Journal(format!(
                "failed to persist journal {}: {e}",
                self.path.display()
            ))
        })
    }
}

/// Hash request facts for journal keys when caller omits one.
#[must_use]
pub fn request_fingerprint(req: &RunRequest) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{:?}", req.kind).as_bytes());
    hasher.update(req.program.as_bytes());
    for a in &req.args {
        hasher.update(a.as_bytes());
        hasher.update([0]);
    }
    if let Some(cwd) = &req.cwd {
        hasher.update(cwd.to_string_lossy().as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn build_command(req: &RunRequest) -> ExecResult<Command> {
    if req.program.trim().is_empty() && matches!(req.kind, CommandKind::Structured) {
        return Err(ExecError::EmptyProgram);
    }
    // Spawn mode is separate from policy classification (classify_command_kind).
    // Structured argv `sh -c …` must spawn as argv after policy reclassification;
    // RawShell string-wrapping here would double-wrap and change semantics.
    let mut cmd = match req.kind {
        CommandKind::Structured => {
            #[cfg(windows)]
            {
                // CreateProcess cannot execute .cmd/.bat batch files directly
                // (Win32 error 193). Resolve the argv through the shared
                // Windows batch-aware resolver so npm-style shims launch via
                // cmd.exe with literal argv; tokens cmd.exe would reinterpret
                // fail closed (P1-C).
                let argv = resolve_spawn_argv(&req.program, &req.args, req.cwd.as_deref())
                    .map_err(|e| ExecError::Spawn(e.to_string()))?;
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            }
            #[cfg(not(windows))]
            {
                // Shared launchable resolver: PATH plus the deterministic
                // user-local dirs (~/.local/bin, Cargo, Nix, NVM node bins),
                // so command execution never disagrees with profile
                // detection/review pinning/session launch about which file is
                // invocable, and a bare name is never handed to the spawner
                // (P1-D/P1-C). An unresolvable program fails closed before
                // any process is spawned.
                let argv = resolve_spawn_argv(&req.program, &req.args, req.cwd.as_deref())
                    .map_err(|e| ExecError::Spawn(e.to_string()))?;
                let mut c = Command::new(&argv[0]);
                c.args(&argv[1..]);
                c
            }
        }
        CommandKind::RawShell => {
            #[cfg(windows)]
            {
                // Pin the absolute system cmd.exe so CreateProcess can never
                // resolve a shadowing `cmd.exe`/`cmd.com` from the current
                // directory before system directories (CreateProcess search
                // order). Fail closed when it cannot be located.
                let cmd_exe = windows_system_cmd_exe(std::env::var("SystemRoot").ok().as_deref());
                if !Path::new(&cmd_exe).is_file() {
                    return Err(ExecError::Spawn(format!(
                        "cmd.exe not found at {cmd_exe}; raw shell execution unavailable"
                    )));
                }
                let mut c = Command::new(&cmd_exe);
                let mut full = req.program.clone();
                if !req.args.is_empty() {
                    full.push(' ');
                    full.push_str(&req.args.join(" "));
                }
                c.arg("/C").arg(full);
                c
            }
            #[cfg(not(windows))]
            {
                let mut c = Command::new("sh");
                let mut full = req.program.clone();
                if !req.args.is_empty() {
                    full.push(' ');
                    full.push_str(&req.args.join(" "));
                }
                c.arg("-c").arg(full);
                c
            }
        }
    };
    if let Some(cwd) = &req.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &req.env {
        cmd.env(k, v);
    }
    // Put the child in its own process group (Unix) so cancel/timeout can kill
    // the whole tree, including backgrounded descendants of shells.
    #[cfg(unix)]
    {
        cmd.process_group(0);
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(cmd)
}

/// Decoder metadata for non-UTF-8 captured output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OutputDecoding {
    /// Decoder name (for example, `utf-16le` or `windows-oem-cp932`).
    pub encoding: String,
    /// True if recovery required replacement characters.
    pub lossy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DecodedOutput {
    text: String,
    decoding: Option<OutputDecoding>,
}

fn decode_utf16_bom(data: &[u8]) -> Option<DecodedOutput> {
    let (little_endian, body) = match data {
        [0xff, 0xfe, rest @ ..] => (true, rest),
        [0xfe, 0xff, rest @ ..] => (false, rest),
        _ => return None,
    };

    // The captured input has already been bounded. `chunks_exact` makes an
    // odd trailing byte explicit instead of panicking or silently dropping it.
    let mut units = Vec::with_capacity(body.len() / 2);
    let mut chunks = body.chunks_exact(2);
    for bytes in &mut chunks {
        let unit = if little_endian {
            u16::from_le_bytes([bytes[0], bytes[1]])
        } else {
            u16::from_be_bytes([bytes[0], bytes[1]])
        };
        units.push(unit);
    }
    let trailing_byte = !chunks.remainder().is_empty();
    let (text, invalid_units) = match String::from_utf16(&units) {
        Ok(text) => (text, false),
        Err(_) => (String::from_utf16_lossy(&units), true),
    };
    Some(DecodedOutput {
        text,
        decoding: Some(OutputDecoding {
            encoding: if little_endian {
                "utf-16le".into()
            } else {
                "utf-16be".into()
            },
            lossy: invalid_units || trailing_byte,
        }),
    })
}

#[cfg(windows)]
fn decode_windows_code_page(data: &[u8], code_page: u32) -> Option<DecodedOutput> {
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Globalization::{
        MultiByteToWideChar, WideCharToMultiByte, MB_ERR_INVALID_CHARS,
    };

    let input_len = i32::try_from(data.len()).ok()?;
    // `MB_ERR_INVALID_CHARS` provides strict decoding where Windows supports
    // it. Legacy code pages may reject that flag, so retry leniently and use a
    // bounded round-trip check below to expose any recovery as lossy.
    let mut strict = true;
    // SAFETY: `data` is live for `input_len` bytes; null output is the API's
    // documented sizing mode.
    let mut wide_len = unsafe {
        MultiByteToWideChar(
            code_page,
            MB_ERR_INVALID_CHARS,
            data.as_ptr(),
            input_len,
            null_mut(),
            0,
        )
    };
    if wide_len == 0 {
        strict = false;
        // SAFETY: same bounded input and documented null sizing mode as above.
        wide_len =
            unsafe { MultiByteToWideChar(code_page, 0, data.as_ptr(), input_len, null_mut(), 0) };
    }
    if wide_len <= 0 {
        return None;
    }
    let mut wide = vec![0_u16; usize::try_from(wide_len).ok()?];
    // SAFETY: the input slice and destination vector are valid for the exact
    // lengths supplied; both lengths were returned/validated by Windows.
    let converted = unsafe {
        MultiByteToWideChar(
            code_page,
            if strict { MB_ERR_INVALID_CHARS } else { 0 },
            data.as_ptr(),
            input_len,
            wide.as_mut_ptr(),
            wide_len,
        )
    };
    if converted != wide_len {
        return None;
    }

    let (text, invalid_units) = match String::from_utf16(&wide) {
        Ok(text) => (text, false),
        Err(_) => (String::from_utf16_lossy(&wide), true),
    };

    // A bounded round trip distinguishes valid legacy text from Windows'
    // replacement-character recovery for malformed multibyte sequences.
    // SAFETY: `wide` is a valid UTF-16 buffer and null output is documented
    // sizing mode. `wide_len` is its checked element count.
    let encoded_len = unsafe {
        WideCharToMultiByte(
            code_page,
            0,
            wide.as_ptr(),
            wide_len,
            null_mut(),
            0,
            null(),
            null_mut(),
        )
    };
    let round_trips = if encoded_len < 0 || usize::try_from(encoded_len).ok()? > data.len() {
        false
    } else {
        let mut encoded = vec![0_u8; usize::try_from(encoded_len).ok()?];
        // SAFETY: the source and destination vectors are valid for the exact
        // counts already returned by the preceding sizing call.
        let written = unsafe {
            WideCharToMultiByte(
                code_page,
                0,
                wide.as_ptr(),
                wide_len,
                encoded.as_mut_ptr(),
                encoded_len,
                null(),
                null_mut(),
            )
        };
        written == encoded_len && encoded == data
    };

    Some(DecodedOutput {
        text,
        decoding: Some(OutputDecoding {
            encoding: format!("windows-oem-cp{code_page}"),
            lossy: invalid_units || !round_trips,
        }),
    })
}

fn decode_output(data: &[u8]) -> DecodedOutput {
    if let Ok(text) = std::str::from_utf8(data) {
        return DecodedOutput {
            text: text.into(),
            decoding: None,
        };
    }
    if let Some(decoded) = decode_utf16_bom(data) {
        return decoded;
    }
    #[cfg(windows)]
    {
        use windows_sys::Win32::Globalization::GetOEMCP;
        // SAFETY: GetOEMCP has no pointer arguments and only reads the
        // configured system code-page value.
        let code_page = unsafe { GetOEMCP() };
        if code_page != 0 {
            if let Some(decoded) = decode_windows_code_page(data, code_page) {
                return decoded;
            }
        }
    }
    DecodedOutput {
        text: String::from_utf8_lossy(data).into_owned(),
        decoding: Some(OutputDecoding {
            encoding: "utf-8-lossy".into(),
            lossy: true,
        }),
    }
}

/// Kill a process tree. Unix uses process-group signal; Windows uses taskkill /T.
fn kill_process_tree(pid: u32) {
    #[cfg(windows)]
    {
        let _ = std::process::Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(unix)]
    {
        // `kill(2)` with a negative PID targets the process group created by
        // `process_group(0)`.  Do not shell out to a `kill` utility: its
        // option parsing can treat a negative group id as another signal and
        // silently leave descendants alive.
        if let Some(pid) = rustix::process::Pid::from_raw(pid.cast_signed()) {
            let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
        }
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Best-effort process-tree containment after timeout/cancel/limit.
/// Returns the exit code when `wait` completes within the grace period.
async fn kill_child(child: &mut Child) -> Option<i32> {
    if let Some(pid) = child.id() {
        kill_process_tree(pid);
    }
    let _ = child.start_kill();
    match tokio::time::timeout(Duration::from_secs(3), child.wait()).await {
        Ok(Ok(status)) => status.code(),
        _ => None,
    }
}

/// Stream stdout/stderr into independently capped rings. Never `read_to_end`
/// an attacker-controlled pipe. Apply backpressure by stopping reads and killing
/// the process when the aggregate byte budget is exhausted.
#[allow(unused_assignments)] // terminal branches assign flags then break.
#[allow(clippy::too_many_lines)]
async fn collect_bounded_output(
    child: &mut Child,
    max_output_bytes: usize,
    timeout: Option<Duration>,
    mut cancel: Option<watch::Receiver<bool>>,
) -> ExecResult<(Option<i32>, Vec<u8>, Vec<u8>, bool, bool, bool)> {
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut stdout_buf: Vec<u8> = Vec::new();
    let mut stderr_buf: Vec<u8> = Vec::new();
    let mut stdout_done = stdout.is_none();
    let mut stderr_done = stderr.is_none();
    let mut truncated = false;
    let mut cancelled = false;
    let mut timed_out = false;
    let mut exit_code: Option<i32> = None;
    let mut status_done = false;
    let mut stdout_chunk = [0_u8; 8192];
    let mut stderr_chunk = [0_u8; 8192];
    let deadline = timeout.map(|d| tokio::time::Instant::now() + d);

    loop {
        if cancelled || timed_out {
            break;
        }
        if status_done && stdout_done && stderr_done {
            break;
        }

        let budget_left = max_output_bytes
            .saturating_sub(stdout_buf.len())
            .saturating_sub(stderr_buf.len());
        if budget_left == 0 && !(stdout_done && stderr_done) {
            truncated = true;
            // Drop pipes before kill so producers unblock, then contain the tree.
            stdout = None;
            stderr = None;
            stdout_done = true;
            stderr_done = true;
            if !status_done {
                exit_code = kill_child(child).await;
                status_done = true;
            }
            break;
        }

        tokio::select! {
            biased;

            changed = async {
                if let Some(rx) = cancel.as_mut() {
                    if *rx.borrow() {
                        return true;
                    }
                    let _ = rx.changed().await;
                    *rx.borrow()
                } else {
                    std::future::pending::<bool>().await
                }
            } => {
                if changed {
                    cancelled = true;
                    stdout = None;
                    stderr = None;
                    stdout_done = true;
                    stderr_done = true;
                    if !status_done {
                        exit_code = kill_child(child).await;
                        status_done = true;
                    }
                }
            }

            () = async {
                if let Some(deadline) = deadline {
                    tokio::time::sleep_until(deadline).await;
                } else {
                    std::future::pending::<()>().await;
                }
            }, if deadline.is_some() && !timed_out => {
                timed_out = true;
                stdout = None;
                stderr = None;
                stdout_done = true;
                stderr_done = true;
                if !status_done {
                    exit_code = kill_child(child).await;
                    status_done = true;
                }
            }

            read = async {
                match stdout.as_mut() {
                    Some(pipe) => pipe.read(&mut stdout_chunk).await,
                    None => std::future::pending().await,
                }
            }, if !stdout_done => {
                match read {
                    Ok(0) | Err(_) => stdout_done = true,
                    Ok(n) => {
                        let take = n.min(budget_left);
                        stdout_buf.extend_from_slice(&stdout_chunk[..take]);
                        if take < n || stdout_buf.len() + stderr_buf.len() >= max_output_bytes {
                            truncated = true;
                            stdout = None;
                            stderr = None;
                            stdout_done = true;
                            stderr_done = true;
                            if !status_done {
                                exit_code = kill_child(child).await;
                                status_done = true;
                            }
                        }
                    }
                }
            }

            read = async {
                match stderr.as_mut() {
                    Some(pipe) => pipe.read(&mut stderr_chunk).await,
                    None => std::future::pending().await,
                }
            }, if !stderr_done => {
                match read {
                    Ok(0) | Err(_) => stderr_done = true,
                    Ok(n) => {
                        let take = n.min(budget_left);
                        stderr_buf.extend_from_slice(&stderr_chunk[..take]);
                        if take < n || stdout_buf.len() + stderr_buf.len() >= max_output_bytes {
                            truncated = true;
                            stdout = None;
                            stderr = None;
                            stdout_done = true;
                            stderr_done = true;
                            if !status_done {
                                exit_code = kill_child(child).await;
                                status_done = true;
                            }
                        }
                    }
                }
            }

            status = child.wait(), if !status_done => {
                match status {
                    Ok(st) => {
                        exit_code = st.code();
                        status_done = true;
                    }
                    Err(err) => return Err(ExecError::Io(err)),
                }
            }
        }
    }

    Ok((
        exit_code, stdout_buf, stderr_buf, truncated, timed_out, cancelled,
    ))
}

/// Run a command, optionally consulting/updating an idempotency journal.
pub async fn run_command(
    req: &RunRequest,
    journal: Option<&mut IdempotencyJournal>,
) -> ExecResult<RunResult> {
    Box::pin(run_command_cancellable(req, journal, None)).await
}

/// Like [`run_command`], but observes an external cancel signal and kills the
/// process tree without waiting for natural exit.
pub async fn run_command_cancellable(
    req: &RunRequest,
    journal: Option<&mut IdempotencyJournal>,
    cancel: Option<watch::Receiver<bool>>,
) -> ExecResult<RunResult> {
    run_command_cancellable_inner(req, None, journal, cancel).await
}

/// Run a command from a consumed, handle-bound executable image.
///
/// Unlike [`run_command_cancellable`], this path never resolves `req.program`
/// as the child image. For a structured request it is retained only as the
/// approved `argv[0]`; for a raw-shell request it remains the approved command
/// text while the prepared object is the pinned platform shell.
pub async fn run_prepared_command_cancellable(
    req: &RunRequest,
    prepared: PreparedExecutable,
    journal: Option<&mut IdempotencyJournal>,
    cancel: Option<watch::Receiver<bool>>,
) -> ExecResult<RunResult> {
    run_command_cancellable_inner(req, Some(prepared), journal, cancel).await
}

fn capped_request(req: &RunRequest) -> RunRequest {
    let mut capped = req.clone();
    capped.max_output_bytes = req.max_output_bytes.clamp(1, HARD_MAX_OUTPUT_BYTES);
    capped.timeout_ms = req.timeout_ms.map(|ms| ms.clamp(1, HARD_MAX_TIMEOUT_MS));
    capped
}

async fn run_command_cancellable_inner(
    req: &RunRequest,
    prepared: Option<PreparedExecutable>,
    mut journal: Option<&mut IdempotencyJournal>,
    cancel: Option<watch::Receiver<bool>>,
) -> ExecResult<RunResult> {
    // Clamp untrusted ceilings before any allocation or spawn.
    let capped = capped_request(req);
    let max_output_bytes = capped.max_output_bytes;

    // Request validation/building has no external side effect and happens before
    // reserving the key. Spawn remains strictly after the durable marker.
    let mut prepared_command = prepared
        .map(|image| prepared::build_prepared_command(&capped, image))
        .transpose()?;
    let mut ordinary_command = if prepared_command.is_none() {
        Some(build_command(&capped)?)
    } else {
        None
    };
    if let (Some(key), Some(j)) = (capped.idempotency_key.as_deref(), journal.as_deref_mut()) {
        if let Some(prev) = j.get(key) {
            let mut replayed = prev.clone();
            replayed.replayed = true;
            return Ok(replayed);
        }
        if j.is_in_progress(key) {
            return Err(ExecError::IdempotencyConflict(key.to_owned()));
        }
        // This is the durable commit point for starting the external side effect.
        // Failure leaves the key absent and occurs before spawn.
        j.begin(key.to_owned())?;
    }

    let start = Instant::now();
    let command = if let Some(prepared) = prepared_command.as_mut() {
        &mut prepared.command
    } else {
        ordinary_command
            .as_mut()
            .expect("ordinary command exists when no prepared image was supplied")
    };
    let mut child = command
        .spawn()
        .map_err(|source| ExecError::Spawn(describe_spawn_error(&req.program, &source)))?;
    // Retain custody until the child exits. On macOS a shebang launch may
    // return from posix_spawn before the interpreter has reopened the staged
    // script path; deleting it immediately would turn an approved launch into
    // a child-side ENOENT. Linux and Windows also benefit from the simpler
    // invariant that every prepared handle outlives the launched process.
    let pid = child.id();

    if let Some(input) = &capped.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            let _ = stdin.write_all(input.as_bytes()).await;
            drop(stdin);
        }
    }

    let timeout = capped.timeout_ms.map(Duration::from_millis);
    // Box the select-heavy collector so callers stay under clippy large_futures.
    let (exit_code, stdout_raw, stderr_raw, truncated, timed_out, cancelled) = Box::pin(
        collect_bounded_output(&mut child, max_output_bytes, timeout, cancel),
    )
    .await?;
    drop(prepared_command);

    if cancelled {
        // Do not journal a cancelled attempt as a successful side effect; a
        // retry with the same key may legitimately re-run after cancel.
        if let (Some(key), Some(j)) = (req.idempotency_key.as_deref(), journal.as_mut()) {
            let _ = j.clear_in_progress(key);
        }
        return Err(ExecError::Cancelled);
    }

    let stdout = decode_output(&stdout_raw);
    let stderr = decode_output(&stderr_raw);
    let result = if timed_out {
        RunResult {
            exit_code: None,
            stdout: stdout.text,
            stdout_decoding: stdout.decoding,
            stderr: {
                let mut msg = format!(
                    "command timed out after {:?}",
                    timeout.expect("timeout result requires configured duration")
                );
                let err = stderr.text;
                if !err.is_empty() {
                    msg.push('\n');
                    msg.push_str(&err);
                }
                msg
            },
            stderr_decoding: stderr.decoding,
            timed_out: true,
            duration_ms: start.elapsed().as_millis() as u64,
            truncated,
            pid,
            replayed: false,
        }
    } else {
        RunResult {
            exit_code,
            stdout: stdout.text,
            stdout_decoding: stdout.decoding,
            stderr: stderr.text,
            stderr_decoding: stderr.decoding,
            timed_out: false,
            duration_ms: start.elapsed().as_millis() as u64,
            truncated,
            pid,
            replayed: false,
        }
    };

    if let (Some(key), Some(j)) = (req.idempotency_key.clone(), journal.as_mut()) {
        j.put(key, result.clone())?;
    }
    Ok(result)
}

/// Synchronous helper for simple tests (blocks on current runtime or creates one).
pub fn run_command_blocking(
    req: &RunRequest,
    journal_path: Option<&Path>,
) -> ExecResult<RunResult> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        if let Some(p) = journal_path {
            let mut j = IdempotencyJournal::open(p)?;
            run_command(req, Some(&mut j)).await
        } else {
            run_command(req, None).await
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn valid_utf8_output_is_unchanged() {
        let decoded = decode_output("日本語 output".as_bytes());
        assert_eq!(decoded.text, "日本語 output");
        assert_eq!(decoded.decoding, None);
    }

    #[test]
    fn malformed_utf16_bom_output_is_lossy_without_panicking() {
        // An isolated high surrogate cannot form a Unicode scalar value.
        let decoded = decode_output(&[0xff, 0xfe, 0x00, 0xd8]);
        assert_eq!(
            decoded.decoding.as_ref().map(|item| item.encoding.as_str()),
            Some("utf-16le")
        );
        assert!(decoded.decoding.is_some_and(|item| item.lossy));
    }

    #[cfg(windows)]
    #[test]
    fn japanese_windows_code_page_fixture_round_trips() {
        // CP932 bytes for the Windows diagnostic: "アクセスが拒否されました。"
        // Keep the fixture independent from the developer machine's locale.
        let bytes = [
            0x83, 0x41, 0x83, 0x4e, 0x83, 0x5a, 0x83, 0x58, 0x82, 0xaa, 0x8b, 0x91, 0x94, 0xdb,
            0x82, 0xb3, 0x82, 0xea, 0x82, 0xdc, 0x82, 0xb5, 0x82, 0xbd, 0x81, 0x42,
        ];
        let decoded = decode_windows_code_page(&bytes, 932).expect("CP932 must be available");
        assert_eq!(decoded.text, "アクセスが拒否されました。");
        assert_eq!(
            decoded.decoding.as_ref().map(|item| item.encoding.as_str()),
            Some("windows-oem-cp932")
        );
        assert!(decoded.decoding.is_some_and(|item| !item.lossy));
    }

    #[tokio::test]
    async fn structured_echo() {
        #[cfg(windows)]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "cmd.exe".into(),
            args: vec!["/C".into(), "echo hello-ownmesh".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(10_000),
            max_output_bytes: 64 * 1024,
            idempotency_key: None,
        };
        #[cfg(not(windows))]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "echo".into(),
            args: vec!["hello-ownmesh".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(10_000),
            max_output_bytes: 64 * 1024,
            idempotency_key: None,
        };
        let res = run_command(&req, None).await.unwrap();
        assert_eq!(res.exit_code, Some(0));
        assert!(res.stdout.contains("hello-ownmesh"));
        assert!(!res.timed_out);
    }

    #[test]
    fn pin_executable_accepts_large_tool_and_rejects_over_limit() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("large.bin");
        {
            let f = std::fs::File::create(&path).unwrap();
            // Just beyond the former 64 MiB ceiling proves the larger bounded
            // path without hashing a 299 MiB fixture on every CI platform.
            f.set_len((64 * 1024 * 1024) + 1).unwrap();
        }
        let pin = pin_executable(&path, CommandKind::Structured).expect("must accept");
        assert_eq!(pin.len, (64 * 1024 * 1024) + 1);
        assert_eq!(pin.content_sha256.len(), 64);

        std::fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(MAX_EXECUTABLE_PIN_BYTES + 1)
            .unwrap();
        let error = pin_executable(&path, CommandKind::Structured).unwrap_err();
        assert!(matches!(error, ExecError::ResourceLimit(_)));
    }

    #[test]
    fn journal_open_rejects_oversized_file_before_read() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("journal.json");
        {
            let f = std::fs::File::create(&path).unwrap();
            f.set_len(MAX_JOURNAL_FILE_BYTES + 1).unwrap();
        }
        let err = IdempotencyJournal::open(&path).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("journal exceeds") || msg.contains("byte budget"),
            "unexpected error: {msg}"
        );
    }

    #[tokio::test]
    async fn idempotency_prevents_rerun() {
        let dir = tempdir().unwrap();
        let journal_path = dir.path().join("journal.json");
        let mut j = IdempotencyJournal::open(&journal_path).unwrap();
        #[cfg(windows)]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "cmd.exe".into(),
            args: vec!["/C".into(), "echo once".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(10_000),
            max_output_bytes: 4096,
            idempotency_key: Some("op-1".into()),
        };
        #[cfg(not(windows))]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "echo".into(),
            args: vec!["once".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(10_000),
            max_output_bytes: 4096,
            idempotency_key: Some("op-1".into()),
        };
        let first = run_command(&req, Some(&mut j)).await.unwrap();
        assert!(!first.replayed);
        let second = run_command(&req, Some(&mut j)).await.unwrap();
        assert!(second.replayed);
        assert_eq!(first.stdout, second.stdout);
    }

    #[tokio::test]
    async fn infinite_output_is_byte_capped_without_read_to_end() {
        // A writer that would fill memory if collected unbounded.
        #[cfg(windows)]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "cmd.exe".into(),
            // Keep producing lines without waiting for the full command script to end.
            args: vec![
                "/C".into(),
                "for /L %i in (1,1,1000000) do @echo xxxxxxxxxxxxxxxx".into(),
            ],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(10_000),
            max_output_bytes: 8 * 1024,
            idempotency_key: None,
        };
        #[cfg(not(windows))]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "while true; do printf '%s\\n' 'xxxxxxxx'; done".into(),
            ],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(10_000),
            max_output_bytes: 8 * 1024,
            idempotency_key: None,
        };
        let res = tokio::time::timeout(Duration::from_secs(12), run_command(&req, None))
            .await
            .expect("bounded output collection must finish promptly")
            .unwrap();
        assert!(
            res.truncated || res.timed_out,
            "expected truncation or timeout, got {res:?}"
        );
        assert!(res.stdout.len() + res.stderr.len() <= 8 * 1024 + 1024);
    }

    #[tokio::test]
    async fn cancel_kills_long_running_command() {
        let (tx, rx) = watch::channel(false);
        #[cfg(windows)]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "cmd.exe".into(),
            args: vec!["/C".into(), "ping -n 30 127.0.0.1 >NUL".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(60_000),
            max_output_bytes: 4096,
            idempotency_key: None,
        };
        #[cfg(not(windows))]
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "/bin/sleep".into(),
            args: vec!["30".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(60_000),
            max_output_bytes: 4096,
            idempotency_key: None,
        };
        let join = tokio::spawn(async move { run_command_cancellable(&req, None, Some(rx)).await });
        tokio::time::sleep(Duration::from_millis(300)).await;
        let _ = tx.send(true);
        let err = tokio::time::timeout(Duration::from_secs(5), join)
            .await
            .expect("cancel should finish promptly")
            .expect("join")
            .expect_err("expected Cancelled");
        assert!(matches!(err, ExecError::Cancelled));
    }

    /// Prove cancel kills descendants, not only the direct shell child.
    #[tokio::test]
    async fn cancel_kills_process_tree_descendants() {
        use std::fs;
        use std::time::{SystemTime, UNIX_EPOCH};
        let dir = tempdir().unwrap();
        let marker = dir.path().join(format!(
            "child-alive-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let marker_s = marker.to_string_lossy().replace('"', "");

        #[cfg(windows)]
        let req = {
            // Nested cmd is a real child process of the outer cmd (not `start /b`
            // which can detach). Child rewrites the marker every second.
            let inner = format!(
                "for /l %i in (1,1,60) do @((echo alive)>{marker_s} & ping -n 2 127.0.0.1 >NUL)"
            );
            RunRequest {
                kind: CommandKind::Structured,
                program: "cmd.exe".into(),
                args: vec!["/C".into(), format!("cmd.exe /C {inner}")],
                cwd: Some(dir.path().to_path_buf()),
                env: HashMap::new(),
                stdin: None,
                timeout_ms: Some(60_000),
                max_output_bytes: 4096,
                idempotency_key: None,
            }
        };
        #[cfg(not(windows))]
        let req = {
            let script =
                format!("(while true; do echo alive > '{marker_s}'; sleep 0.2; done) & sleep 30");
            RunRequest {
                kind: CommandKind::RawShell,
                program: script,
                args: vec![],
                cwd: Some(dir.path().to_path_buf()),
                env: HashMap::new(),
                stdin: None,
                timeout_ms: Some(60_000),
                max_output_bytes: 4096,
                idempotency_key: None,
            }
        };

        let (tx, rx) = watch::channel(false);
        let join = tokio::spawn(async move { run_command_cancellable(&req, None, Some(rx)).await });
        // Wait until the descendant has written the marker at least once.
        let mut saw = false;
        for _ in 0..80 {
            if marker.exists() {
                saw = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert!(saw, "descendant never wrote marker before cancel");
        let before = fs::metadata(&marker).and_then(|m| m.modified()).ok();
        let _ = tx.send(true);
        let err = tokio::time::timeout(Duration::from_secs(8), join)
            .await
            .expect("tree cancel should finish")
            .expect("join")
            .expect_err("expected Cancelled");
        assert!(matches!(err, ExecError::Cancelled));
        // After cancel, the background writer must stop updating the marker.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let after = fs::metadata(&marker).and_then(|m| m.modified()).ok();
        assert_eq!(
            before, after,
            "descendant kept writing after cancel — process tree not contained"
        );
    }

    #[test]
    fn fingerprint_stable() {
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: "echo".into(),
            args: vec!["a".into()],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: None,
            max_output_bytes: 10,
            idempotency_key: None,
        };
        assert_eq!(request_fingerprint(&req), request_fingerprint(&req));
    }

    #[test]
    fn invocation_resolution_keeps_relative_path_absolute_without_canonicalizing() {
        // A launchable fixture (exec bit set on Unix): invocation resolution
        // must return an absolute path for a relative path without
        // canonicalizing (symlinks preserved). Non-launchable files are
        // rejected by the shared launchable-file semantics (P1-D/P1-F).
        let dir = tempdir().unwrap();
        let tool = dir.path().join("tool");
        std::fs::write(&tool, b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tool).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&tool, perms).unwrap();
        }
        let path = resolve_executable_invocation_path("./tool", Some(dir.path())).unwrap();
        assert!(path.is_absolute(), "invocation path must be persistable");
        assert_eq!(path, dir.path().join("./tool"));
        // A non-launchable relative file is not an invocable executable.
        assert_eq!(
            resolve_executable_invocation_path("./Cargo.toml", Some(dir.path())),
            None
        );
    }

    #[test]
    fn classify_shell_binary_is_always_raw_shell() {
        let cases: &[(&str, &[&str])] = &[
            ("/bin/sh", &["-c", "id"]),
            ("/bin/bash", &["-c", "whoami"]),
            ("bash", &["-c", "echo hi"]),
            ("DASH", &["-c", "true"]),
            ("/usr/bin/zsh", &["-c", "echo z"]),
            ("ksh", &["-c", "echo k"]),
            ("csh", &["-c", "echo c"]),
            ("tcsh", &["-c", "echo tc"]),
            ("C:\\Windows\\System32\\cmd.exe", &["/C", "echo hi"]),
            ("cmd", &["/k", "dir"]),
            ("CMD.EXE", &["/c", "ver"]),
            ("powershell", &["-Command", "Get-Host"]),
            ("powershell.exe", &["-EncodedCommand", "QQA="]),
            ("pwsh", &["-c", "1+1"]),
            ("/usr/bin/pwsh", &["-Command:Get-Process"]),
            // path / case / extension variants, argv irrelevant
            ("bash.exe", &[]),
            ("SH.EXE", &["--version"]),
            ("/bin/bash", &[]),
            ("fish", &["-c", "echo f"]),
            ("Pwsh.EXE", &["--version"]),
        ];
        for (program, args) in cases {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let kind = classify_from_request(Some("structured"), program, &argv);
            assert_eq!(
                kind,
                CommandKind::RawShell,
                "expected raw_shell for {program:?} {args:?}"
            );
            assert_eq!(kind.as_str(), "raw_shell");
            assert!(is_shell_binary(program), "is_shell_binary({program})");
        }
    }

    #[test]
    fn classify_shell_clustered_and_joined_flag_bypasses_are_raw_shell() {
        // Historical hole: SHELL_EXEC_FLAGS exact-match missed `-lc` / `-ic`, so
        // `bash -lc …` could be claimed as structured. Shell binaries must stay raw.
        let cases: &[(&str, &[&str])] = &[
            ("bash", &["-lc", "id"]),
            ("/bin/bash", &["-lc", "whoami"]),
            ("sh", &["-ic", "echo hi"]),
            ("zsh", &["-lc", "true"]),
            ("bash", &["-c", "id"]),
            ("cmd.exe", &["/c:echo hi"]),
            ("CMD", &["/C:dir"]),
            ("powershell", &["-Command:Get-Process"]),
            ("powershell.exe", &["-EncodedCommand:QQA="]),
            ("pwsh", &["-EncodedCommand", "QQA="]),
            ("pwsh.exe", &["-enc", "QQA="]),
            ("bash", &["-ce", "echo x"]),
            // no exec-looking flag at all — still raw because binary is shell
            ("bash", &["--version"]),
            ("cmd.exe", &["/?"]),
        ];
        for (program, args) in cases {
            let argv: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
            let kind = classify_from_request(Some("structured"), program, &argv);
            assert_eq!(
                kind,
                CommandKind::RawShell,
                "bypass must not yield structured: {program:?} {args:?}"
            );
            // Defense-in-depth: clustered/joined exec forms should also be detected.
            if args.iter().any(|a| {
                let t: &str = a;
                t.eq_ignore_ascii_case("-lc")
                    || t.eq_ignore_ascii_case("-ic")
                    || t.eq_ignore_ascii_case("-ce")
                    || t.starts_with("/c:")
                    || t.starts_with("/C:")
                    || t.to_ascii_lowercase().starts_with("-command:")
                    || t.to_ascii_lowercase().starts_with("-encodedcommand:")
                    || t.eq_ignore_ascii_case("-c")
                    || t.eq_ignore_ascii_case("-enc")
                    || t.eq_ignore_ascii_case("-encodedcommand")
            }) {
                assert!(
                    args_have_shell_exec_flag(&argv),
                    "args_have_shell_exec_flag should detect {args:?}"
                );
            }
        }
    }

    #[test]
    fn classify_non_shell_stays_structured() {
        let echo = classify_from_request(Some("structured"), "echo", &["hi".into()]);
        assert_eq!(echo, CommandKind::Structured);

        let ls = classify_from_request(Some("structured"), "/bin/ls", &["-la".into()]);
        assert_eq!(ls, CommandKind::Structured);

        let git = classify_from_request(
            Some("structured"),
            "git",
            &["status".into(), "-c".into(), "foo=bar".into()],
        );
        assert_eq!(git, CommandKind::Structured);

        let python = classify_from_request(
            Some("structured"),
            "python3",
            &["-c".into(), "print(1)".into()],
        );
        assert_eq!(python, CommandKind::RawShell);

        assert!(!is_shell_binary("echo"));
        assert!(!is_shell_binary("python3"));
        assert!(!is_shell_binary("git"));
    }

    #[test]
    fn classify_explicit_raw_stays_raw() {
        let kind = classify_from_request(Some("raw_shell"), "echo", &["x".into()]);
        assert_eq!(kind, CommandKind::RawShell);
    }

    /// The Windows cmd.exe wrapper must always be the pinned absolute
    /// `%SystemRoot%\System32\cmd.exe` so `CreateProcess` can never resolve a
    /// shadowing `cmd.exe`/`cmd.com` from the current directory before system
    /// directories (CreateProcess search order).
    #[test]
    fn windows_cmd_exe_is_pinned_absolute() {
        assert_eq!(
            windows_system_cmd_exe(None),
            "C:\\Windows\\System32\\cmd.exe"
        );
        assert_eq!(
            windows_system_cmd_exe(Some("D:\\Win")),
            "D:\\Win\\System32\\cmd.exe"
        );
        assert_eq!(
            windows_system_cmd_exe(Some("E:\\Win\\")),
            "E:\\Win\\System32\\cmd.exe"
        );
        assert_eq!(
            windows_system_cmd_exe(Some(" ")),
            "C:\\Windows\\System32\\cmd.exe",
            "an empty SystemRoot falls back to the standard path"
        );
    }

    /// P1-C policy boundary: a `.cmd`/`.bat` batch shim is shell content
    /// (`cmd.exe` interprets its file content with full shell semantics even
    /// when argv is passed literally), so it must classify as `RawShell` on
    /// every platform — a policy denying `raw_shell` must deny it. PATHEXT
    /// resolution (which sibling file wins) is handled by the resolver and
    /// never downgrades policy. A `.cmd` with a shebang is a Unix-style
    /// script and stays fail-closed as well.
    #[test]
    fn classify_windows_batch_shim_is_raw_on_every_platform() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi.cmd");
        std::fs::write(&shim, b"@echo off\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
        }
        let cwd = dir.path();
        let args: Vec<String> = vec!["--version".into()];
        let shim_abs = shim.to_string_lossy().into_owned();
        // Batch shims are raw on every platform (including Windows): the
        // payload is shell content that a raw_shell-denying policy must deny.
        let kind = classify_command_kind_in_dir_with_style(
            CommandKind::Structured,
            &shim_abs,
            &args,
            Some(cwd),
        );
        assert_eq!(
            kind,
            CommandKind::RawShell,
            "Windows .cmd shim must classify raw_shell (shell semantics)"
        );
        // A .bat sibling is equally raw.
        let bat = dir.path().join("pi.bat");
        std::fs::write(&bat, b"@echo off\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bat).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bat, perms).unwrap();
        }
        let kind = classify_command_kind_in_dir_with_style(
            CommandKind::Structured,
            &bat.to_string_lossy(),
            &args,
            Some(cwd),
        );
        assert_eq!(kind, CommandKind::RawShell, "Windows .bat shim must be raw");
        // A .cmd with a shebang is a Unix-style script and stays fail-closed.
        let shebang = dir.path().join("evil.cmd");
        std::fs::write(&shebang, b"#!/bin/sh\necho hi\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shebang).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shebang, perms).unwrap();
        }
        let shebang_abs = shebang.to_string_lossy().into_owned();
        let kind = classify_command_kind_in_dir_with_style(
            CommandKind::Structured,
            &shebang_abs,
            &args,
            Some(cwd),
        );
        assert_eq!(
            kind,
            CommandKind::RawShell,
            "shebang .cmd stays fail-closed"
        );
    }

    /// P1-C policy boundary: a structured pin must never accept a Windows
    /// batch shim as a structured payload — the file content is shell code.
    /// Revalidation therefore fails closed on every platform (the same as a
    /// Unix script), so a batch shim must be re-authorized as raw_shell.
    #[test]
    fn verify_pin_rejects_windows_batch_shim_structured_payload() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi.cmd");
        std::fs::write(&shim, b"@echo off\r\n").unwrap();
        let pin = pin_executable(&shim, CommandKind::Structured).unwrap();
        assert!(
            verify_executable_pin(&shim, &pin).is_err(),
            "structured pin must reject a Windows .cmd shim as a script payload"
        );
        let bat = dir.path().join("pi.bat");
        std::fs::write(&bat, b"@echo off\r\n").unwrap();
        let pin_bat = pin_executable(&bat, CommandKind::Structured).unwrap();
        assert!(
            verify_executable_pin(&bat, &pin_bat).is_err(),
            "structured pin must reject a Windows .bat shim as a script payload"
        );
    }

    #[test]
    fn program_basename_handles_paths() {
        assert_eq!(program_basename("/bin/bash"), "bash");
        assert_eq!(
            program_basename("C:\\Windows\\System32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(program_basename("powershell"), "powershell");
        assert_eq!(program_basename("\"/bin/sh\""), "sh");
    }

    #[test]
    fn is_shell_binary_matches_path_case_and_extension() {
        assert!(is_shell_binary("bash"));
        assert!(is_shell_binary("BASH"));
        assert!(is_shell_binary("bash.exe"));
        assert!(is_shell_binary("Bash.EXE"));
        assert!(is_shell_binary("/bin/sh"));
        assert!(is_shell_binary("C:\\Windows\\System32\\cmd.exe"));
        assert!(is_shell_binary("CMD"));
        assert!(is_shell_binary("pwsh.exe"));
        assert!(is_shell_binary("powershell"));
        assert!(!is_shell_binary("bashful"));
        assert!(!is_shell_binary("notcmd"));
        assert!(!is_shell_binary(""));
    }

    /// P2-H: Win32 error 193 spawn failures must surface the actionable cause
    /// (npm-style extensionless shim) instead of a generic internal error.
    #[test]
    fn spawn_error_mapper_preserves_actionable_cause() {
        let generic = std::io::Error::new(std::io::ErrorKind::NotFound, "no such file");
        let msg = describe_spawn_error("pi", &generic);
        assert!(msg.contains("failed to start `pi`"));
        assert!(msg.contains("no such file"), "raw cause preserved: {msg}");

        // Win32 error 193 = invalid executable format.
        let win32 = std::io::Error::from_raw_os_error(193);
        let msg = describe_spawn_error("pi", &win32);
        assert!(
            msg.contains("not a valid Win32 application (error 193)"),
            "{msg}"
        );
        assert!(
            msg.contains("extensionless POSIX shim"),
            "actionable remediation expected: {msg}"
        );
        assert!(msg.contains("pi.exe/.cmd/.bat"), "{msg}");
    }

    #[test]
    fn windows_pathext_candidates_order_invocable_before_bare_name() {
        // Default PATHEXT: .COM;.EXE;.BAT;.CMD, bare name always last.
        // Case is preserved from the PATHEXT string (Windows is case-insensitive).
        let candidates = windows_pathext_candidates("pi", None);
        assert_eq!(
            candidates,
            vec!["pi.COM", "pi.EXE", "pi.BAT", "pi.CMD", "pi"]
        );
        // PATHEXT entries that are not directly invocable (.ps1/.sh) and
        // duplicates are filtered out; case is preserved from PATHEXT.
        let candidates = windows_pathext_candidates("opencode", Some(";.PS1;.exe;.CMD;.SH;.cmd"));
        assert_eq!(candidates, vec!["opencode.exe", "opencode.CMD", "opencode"]);
        // Explicit extensions never go through PATHEXT ordering.
        let candidates = windows_pathext_candidates("pi.cmd", None);
        assert_eq!(candidates, vec!["pi.cmd"]);
    }

    #[test]
    fn windows_candidate_resolution_prefers_cmd_shim_over_extensionless_sibling() {
        // Regression for the npm-shim failure: `pi`, `pi.cmd` and `pi.ps1`
        // siblings must resolve to the invocable `.cmd` shim, never the
        // extensionless POSIX shim that fails with Win32 error 193.
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pi"), b"#!/bin/sh\nexec node ...\n").unwrap();
        std::fs::write(dir.path().join("pi.cmd"), b"@echo off\r\n").unwrap();
        std::fs::write(dir.path().join("pi.ps1"), b"# powershell\n").unwrap();
        std::fs::write(dir.path().join("pi.exe"), b"MZ").unwrap();

        // PATHEXT order: .exe beats .cmd when both exist.  The fixtures use
        // lowercase extensions matching the explicit lowercase PATHEXT below
        // (the CI host filesystem may be case-sensitive).
        let dirs = vec![dir.path().to_path_buf()];
        let pathext = ".exe;.com;.cmd;.bat";
        let resolved = resolve_executable_in_dirs("pi", &dirs, None, true, Some(pathext)).unwrap();
        assert_eq!(resolved, dir.path().join("pi.exe"));

        // Without .exe, the .cmd shim wins over the extensionless sibling.
        std::fs::remove_file(dir.path().join("pi.exe")).unwrap();
        let resolved = resolve_executable_in_dirs("pi", &dirs, None, true, Some(pathext)).unwrap();
        assert_eq!(resolved, dir.path().join("pi.cmd"));
        assert_ne!(
            resolved,
            dir.path().join("pi"),
            "the extensionless POSIX shim must never win while an invocable sibling exists"
        );

        // A genuine extensionless native binary is still reachable when no
        // PATHEXT sibling exists.
        std::fs::remove_file(dir.path().join("pi.cmd")).unwrap();
        std::fs::remove_file(dir.path().join("pi.ps1")).unwrap();
        let resolved = resolve_executable_in_dirs("pi", &dirs, None, true, Some(pathext)).unwrap();
        assert_eq!(resolved, dir.path().join("pi"));
    }

    #[test]
    fn unix_resolution_is_bare_name_only() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("codex"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("codex.cmd"), b"@echo off\r\n").unwrap();
        // Unix semantics: the bare file is the only candidate, even when a
        // .cmd sibling exists (Windows PATHEXT semantics must not leak over).
        let dirs = vec![dir.path().to_path_buf()];
        let resolved = resolve_executable_in_dirs("codex", &dirs, None, false, None).unwrap();
        assert_eq!(resolved, dir.path().join("codex"));
    }

    /// P1-C: an explicit relative path without an extension (`./pi`) must
    /// follow Windows/PATHEXT semantics too — the invocable `.cmd` shim wins
    /// over the extensionless npm-style sibling, so the old error-193 path
    /// cannot win. The bare-name tests covered `pi`; this covers `./pi` and
    /// `pi\\`-style explicit paths.
    #[test]
    fn explicit_relative_windows_path_prefers_invocable_sibling() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pi"), b"#!/bin/sh\nexec node ...\n").unwrap();
        std::fs::write(dir.path().join("pi.cmd"), b"@echo off\r\n").unwrap();
        std::fs::write(dir.path().join("pi.ps1"), b"# powershell\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["pi", "pi.cmd", "pi.ps1"] {
                let path = dir.path().join(name);
                let mut perms = std::fs::metadata(&path).unwrap().permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&path, perms).unwrap();
            }
        }
        let pathext = ".exe;.com;.cmd;.bat";

        // `./pi` resolves to `./pi.cmd`, never the extensionless shim.
        let argv =
            resolve_spawn_argv_in_dirs("./pi", &[], &[], Some(dir.path()), true, Some(pathext))
                .expect("resolve");
        // The batch shim is launched through the documented cmd.exe form with
        // the pinned absolute interpreter (never a bare `cmd.exe`, which
        // CreateProcess could resolve from the current directory first).
        assert!(
            argv[0].to_ascii_lowercase().ends_with("system32\\cmd.exe"),
            "batch shim must launch via the pinned System32 cmd.exe: {:?}",
            argv[0]
        );
        assert!(argv.contains(&dir.path().join("pi.cmd").to_string_lossy().into_owned()));

        // `pi\\`-style explicit path behaves identically (Windows only: on
        // Unix a backslash is a literal filename character).
        #[cfg(windows)]
        {
            let argv =
                resolve_spawn_argv_in_dirs("pi\\", &[], &[], Some(dir.path()), true, Some(pathext))
                    .expect("resolve");
            assert!(argv.contains(&dir.path().join("pi.cmd").to_string_lossy().into_owned()));
        }

        // An explicit extension is used verbatim and never re-ordered.
        let argv =
            resolve_spawn_argv_in_dirs("./pi.cmd", &[], &[], Some(dir.path()), true, Some(pathext))
                .expect("resolve");
        assert!(argv.contains(&dir.path().join("./pi.cmd").to_string_lossy().into_owned()));

        // A genuine extensionless native binary is still reachable when no
        // PATHEXT sibling exists (the PATHEXT branch normalizes the `./`).
        std::fs::remove_file(dir.path().join("pi.cmd")).unwrap();
        std::fs::remove_file(dir.path().join("pi.ps1")).unwrap();
        let argv =
            resolve_spawn_argv_in_dirs("./pi", &[], &[], Some(dir.path()), true, Some(pathext))
                .expect("resolve");
        assert_eq!(argv[0], dir.path().join("pi").to_string_lossy());

        // Unix behavior is unchanged: `./pi` is the exact file, never the
        // `.cmd` sibling.
        let argv = resolve_spawn_argv_in_dirs("./pi", &[], &[], Some(dir.path()), false, None)
            .expect("resolve");
        assert_eq!(argv[0], dir.path().join("./pi").to_string_lossy());
    }

    /// P1-D: launchable resolution skips non-executable Unix files instead of
    /// reporting a candidate that could never spawn.
    #[test]
    fn launchable_resolution_requires_unix_exec_bit() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi");
        std::fs::write(&shim, b"#!/bin/sh\n").unwrap();
        let dirs = vec![dir.path().to_path_buf()];
        #[cfg(unix)]
        {
            // 0644: is_file() true, but not launchable.
            assert!(!is_launchable_file(&shim));
            assert!(
                resolve_launchable_executable_in_dirs("pi", &dirs, None, false, None).is_none()
            );
            assert!(!is_launchable_file(&dir.path().join("missing")));
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
            assert!(is_launchable_file(&shim));
            let resolved =
                resolve_launchable_executable_in_dirs("pi", &dirs, None, false, None).unwrap();
            assert_eq!(resolved, shim);
        }
        #[cfg(not(unix))]
        {
            assert!(is_launchable_file(&shim));
            assert!(
                resolve_launchable_executable_in_dirs("pi", &dirs, None, false, None).is_some()
            );
        }
    }

    /// P1-C: `build_command` (the structured `command.run` spawn path) must
    /// route a `.cmd`/`.bat` program through the shared cmd.exe wrapper on
    /// Windows — CreateProcess cannot exec batch files directly (Win32 error
    /// 193). Runs on Windows CI; the pure resolver behavior is pinned on all
    /// platforms by `spawn_argv_windows_selects_cmd_shim_and_wraps`.
    #[cfg(windows)]
    #[test]
    fn build_command_wraps_windows_batch_shim_in_cmd_exe() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("pi.cmd");
        std::fs::write(&shim, b"@echo off\r\n").unwrap();
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: shim.to_string_lossy().into_owned(),
            args: vec!["--version".into()],
            cwd: Some(dir.path().to_path_buf()),
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(5_000),
            max_output_bytes: 64 * 1024,
            idempotency_key: None,
        };
        let cmd = build_command(&req).expect("build_command");
        let program = cmd.as_std().get_program().to_string_lossy().into_owned();
        let argv: Vec<String> = cmd
            .as_std()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(
            program.to_ascii_lowercase().ends_with("system32\\cmd.exe"),
            "batch shim must launch via the pinned System32 cmd.exe: {program:?} {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a == "call"),
            "cmd.exe wrapper must use `call`: {argv:?}"
        );
        assert!(
            argv.iter().any(|a| a.ends_with("pi.cmd")),
            "the resolved shim must be a separate argv token: {argv:?}"
        );
    }

    /// P1-C: session launch argv resolution — npm-style `name` + `name.cmd` +
    /// `name.ps1` siblings must select the invocable `.cmd` shim and rewrite
    /// the argv to `cmd.exe /c "<shim>" <args>` (CreateProcess cannot exec
    /// batch files directly).  Windows-only behavior is pinned here via the
    /// `windows_style` parameter so it runs on any CI platform.
    #[test]
    fn spawn_argv_windows_selects_cmd_shim_and_wraps() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pi"), b"#!/bin/sh\n").unwrap();
        std::fs::write(dir.path().join("pi.cmd"), b"@echo off\r\n").unwrap();
        std::fs::write(dir.path().join("pi.ps1"), b"# powershell\n").unwrap();
        // The `windows_style` simulation runs on any platform; give the
        // fixtures the exec bit so the launchable check (Unix) matches real
        // Windows behavior (any regular file).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for name in ["pi", "pi.cmd", "pi.ps1"] {
                let mut perms = std::fs::metadata(dir.path().join(name))
                    .unwrap()
                    .permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(dir.path().join(name), perms).unwrap();
            }
        }
        let dirs = vec![dir.path().to_path_buf()];
        let pathext = ".exe;.com;.cmd;.bat";
        let argv = resolve_spawn_argv_in_dirs(
            "pi",
            &["--version".into()],
            &dirs,
            None,
            true,
            Some(pathext),
        )
        .expect("resolved");
        assert!(
            argv[0].to_ascii_lowercase().ends_with("system32\\cmd.exe"),
            "argv[0] must be the pinned System32 cmd.exe, not a bare name"
        );
        assert_eq!(argv[1], "/e:ON");
        assert_eq!(argv[2], "/v:OFF");
        assert_eq!(argv[3], "/d");
        assert_eq!(argv[4], "/s");
        assert_eq!(argv[5], "/c");
        assert_eq!(argv[6], "call");
        assert_eq!(
            argv[7],
            dir.path().join("pi.cmd").display().to_string(),
            "the resolved .cmd shim must be a separate argv token after `call`"
        );
        assert_eq!(argv[8], "--version");
        assert_eq!(argv.len(), 9);

        // With .exe present, no cmd wrapper is needed.
        std::fs::write(dir.path().join("pi.exe"), b"MZ").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dir.path().join("pi.exe"))
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(dir.path().join("pi.exe"), perms).unwrap();
        }
        let argv = resolve_spawn_argv_in_dirs(
            "pi",
            &["--version".into()],
            &dirs,
            None,
            true,
            Some(pathext),
        )
        .expect("resolved");
        assert_eq!(argv[0], dir.path().join("pi.exe").display().to_string());
        assert_eq!(argv[1], "--version");

        // Extensionless-only fallback: bare shim last (Windows has no exec
        // bits; if no invocable sibling exists there is nothing better).
        std::fs::remove_file(dir.path().join("pi.exe")).unwrap();
        std::fs::remove_file(dir.path().join("pi.cmd")).unwrap();
        std::fs::remove_file(dir.path().join("pi.ps1")).unwrap();
        std::fs::write(dir.path().join("pi"), b"MZ").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(dir.path().join("pi"))
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(dir.path().join("pi"), perms).unwrap();
        }
        let argv =
            resolve_spawn_argv_in_dirs("pi", &["-v".into()], &dirs, None, true, Some(pathext))
                .expect("resolved");
        assert_eq!(
            argv,
            vec![dir.path().join("pi").display().to_string(), "-v".into()]
        );
    }

    /// P1-C: Unix session launch resolution replaces argv[0] with the resolved
    /// absolute path and requires the exec bit.
    #[test]
    fn spawn_argv_unix_resolves_absolute_and_requires_exec() {
        let dir = tempdir().unwrap();
        let shim = dir.path().join("codex");
        std::fs::write(&shim, b"#!/bin/sh\n").unwrap();
        let dirs = vec![dir.path().to_path_buf()];
        #[cfg(unix)]
        {
            // Non-executable: unresolved (never hand a bare name to a spawner).
            assert_eq!(
                resolve_spawn_argv_in_dirs("codex", &["exec".into()], &dirs, None, false, None),
                Err(SpawnResolveError::NotFound)
            );
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&shim).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&shim, perms).unwrap();
            let argv =
                resolve_spawn_argv_in_dirs("codex", &["exec".into()], &dirs, None, false, None)
                    .expect("resolved");
            assert_eq!(argv[0], shim.display().to_string());
            assert_eq!(argv[1], "exec");
            // Absolute-path programs are verified directly (profile launch plans).
            let argv = resolve_spawn_argv_in_dirs(
                shim.to_str().unwrap(),
                &["exec".into()],
                &[],
                None,
                false,
                None,
            )
            .expect("absolute path");
            assert_eq!(argv[0], shim.display().to_string());
        }
        #[cfg(not(unix))]
        {
            let argv =
                resolve_spawn_argv_in_dirs("codex", &["exec".into()], &dirs, None, false, None)
                    .expect("resolved");
            assert_eq!(argv[0], shim.display().to_string());
        }
    }

    /// P1-D review: the actual spawn path (`build_command` behind
    /// `run_command`) must fail closed when a structured program resolves to
    /// nothing, instead of silently handing a bare name to the spawner and
    /// letting the OS PATH lookup disagree with profile detection and review
    /// pinning. An absolute path to a missing file is deterministic on every
    /// platform and exercises the shared `resolve_spawn_argv` core on Unix
    /// (Windows already routes through it).
    #[tokio::test]
    async fn structured_spawn_fails_closed_when_program_is_unresolvable() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("no-such-ownmesh-tool");
        let req = RunRequest {
            kind: CommandKind::Structured,
            program: missing.to_string_lossy().into_owned(),
            args: vec![],
            cwd: None,
            env: HashMap::new(),
            stdin: None,
            timeout_ms: Some(5_000),
            max_output_bytes: 64 * 1024,
            idempotency_key: None,
        };
        let err = run_command(&req, None).await.unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("could not be resolved") || msg.contains("Spawn"),
            "unresolvable structured program must fail closed before spawn: {msg}"
        );
    }

    /// P1-C: Windows batch launch must preserve argv semantics or fail closed.
    /// Tokens with whitespace are quoted by the spawner, so quoted cmd
    /// metacharacters are literal; bare metacharacters, embedded quotes, `%`/
    /// `!` and control characters are rejected with `CmdUnsafeArgument`.
    #[test]
    #[allow(clippy::too_many_lines)] // exhaustive fail-closed matrix stays one test
    fn windows_batch_argv_preserves_argv_or_fails_closed() {
        let dir = tempdir().unwrap();
        std::fs::write(dir.path().join("pi.cmd"), b"@echo off\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                dir.path().join("pi.cmd"),
                std::fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }
        let dirs = vec![dir.path().to_path_buf()];
        let pathext = ".exe;.com;.cmd;.bat";
        let resolve = |args: &[&str]| {
            let owned: Vec<String> = args.iter().map(ToString::to_string).collect();
            resolve_spawn_argv_in_dirs("pi", &owned, &dirs, None, true, Some(pathext))
        };

        // Spaces in args and in the script path stay separate argv tokens
        // (the spawner quotes them); `call` keeps cmd's /s strip rule inert.
        let with_space = resolve(&["two words", "a&b c"]).expect("quoted tokens");
        assert_eq!(
            with_space[7],
            dir.path().join("pi.cmd").display().to_string()
        );
        assert_eq!(with_space[8], "two words");
        assert_eq!(with_space[9], "a&b c");

        // Bare cmd metacharacters cannot be quoted by the spawner -> fail closed.
        assert_eq!(resolve(&["a&b"]), Err(SpawnResolveError::CmdUnsafeArgument));
        assert_eq!(resolve(&["a|b"]), Err(SpawnResolveError::CmdUnsafeArgument));
        assert_eq!(resolve(&["a^b"]), Err(SpawnResolveError::CmdUnsafeArgument));
        assert_eq!(resolve(&["(a)"]), Err(SpawnResolveError::CmdUnsafeArgument));

        // Embedded quotes are never representable through cmd.exe -> fail closed.
        assert_eq!(
            resolve(&["say \"hi\""]),
            Err(SpawnResolveError::CmdUnsafeArgument)
        );

        // % and ! expansion cannot be neutralized -> fail closed.
        assert_eq!(
            resolve(&["100%"]),
            Err(SpawnResolveError::CmdUnsafeArgument)
        );
        assert_eq!(
            resolve(&["bang!"]),
            Err(SpawnResolveError::CmdUnsafeArgument)
        );

        // Control characters -> fail closed.
        assert_eq!(
            resolve(&["line\nbreak"]),
            Err(SpawnResolveError::CmdUnsafeArgument)
        );
        assert_eq!(
            resolve(&["a\rb"]),
            Err(SpawnResolveError::CmdUnsafeArgument)
        );

        // A script path with whitespace is representable (quoted + call).
        std::fs::create_dir_all(dir.path().join("Program Files (x86)")).unwrap();
        let spaced = dir.path().join("Program Files (x86)").join("pi.cmd");
        std::fs::write(&spaced, b"@echo off\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&spaced, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let dirs_spaced = vec![spaced.parent().unwrap().to_path_buf()];
        let argv = resolve_spawn_argv_in_dirs(
            "pi",
            &["--version".into()],
            &dirs_spaced,
            None,
            true,
            Some(pathext),
        )
        .expect("spaced script path stays a single quoted token");
        assert_eq!(argv[6], "call");
        assert_eq!(argv[7], spaced.display().to_string());

        // ...but a script path with a % or ! fails closed too.
        let bad = dir.path().join("pi%x.cmd");
        std::fs::write(&bad, b"@echo off\r\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        let dirs_bad = vec![dir.path().to_path_buf()];
        assert_eq!(
            resolve_spawn_argv_in_dirs(
                "pi%x",
                &["--version".into()],
                &dirs_bad,
                None,
                true,
                Some(pathext),
            ),
            Err(SpawnResolveError::CmdUnsafeArgument)
        );
    }

    #[test]
    fn cmd_token_safety_predicate_is_explicit() {
        // Bare-safe: alphanumerics, path chars, dashes, dots, `=`, `,`, `;`.
        for token in ["--version", "C:\\npm\\pi.cmd", "key=value", "a,b;c"] {
            assert!(cmd_token_safe(token), "{token} must be bare-safe");
        }
        // Whitespace triggers spawner quoting -> metachars become literal.
        assert!(cmd_token_safe("a&b c"));
        assert!(cmd_token_safe("Program Files (x86)"));
        // Always unsafe.
        for token in ["a\"b", "100%", "bang!", "x\ny", "a\rb"] {
            assert!(!cmd_token_safe(token), "{token:?} must be rejected");
        }
        // Bare metachars are unsafe.
        for token in ["a&b", "a|b", "a<b", "a>b", "(a)", "a^b"] {
            assert!(!cmd_token_safe(token), "{token:?} must be rejected");
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn user_cli_search_dirs_are_deterministic_and_shell_free() {
        let home = tempdir().unwrap();
        // NVM layout with several node versions.
        let nvm = home.path().join(".nvm").join("versions").join("node");
        std::fs::create_dir_all(nvm.join("v20.19.0").join("bin")).unwrap();
        std::fs::create_dir_all(nvm.join("v18.3.1").join("bin")).unwrap();
        std::fs::create_dir_all(nvm.join("v22.14.1").join("bin")).unwrap();
        // Decoy non-version entry must be ignored.
        std::fs::create_dir_all(nvm.join("current").join("bin")).unwrap();

        let dirs = user_cli_search_dirs(Some(home.path()));
        let names: Vec<String> = dirs.iter().map(|d| d.display().to_string()).collect();
        assert!(names.contains(&home.path().join(".local/bin").display().to_string()));
        assert!(names.contains(&home.path().join(".cargo/bin").display().to_string()));
        assert!(names.contains(&home.path().join(".nix-profile/bin").display().to_string()));
        assert!(names.contains(&home.path().join(".npm-global/bin").display().to_string()));
        assert!(names.contains(&"/nix/var/nix/profiles/default/bin".to_string()));
        // NVM versions sorted ascending (indices must be strictly increasing).
        let positions: Vec<usize> = ["v18.3.1", "v20.19.0", "v22.14.1"]
            .iter()
            .map(|v| {
                names
                    .iter()
                    .position(|n| n.ends_with(&format!("/.nvm/versions/node/{v}/bin")))
                    .expect("nvm bin dir present")
            })
            .collect();
        assert_eq!(
            positions,
            {
                let mut sorted = positions.clone();
                sorted.sort_unstable();
                sorted
            },
            "nvm versions must be sorted: {names:?}"
        );
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with("/.nvm/versions/node/current/bin")),
            "decoy non-version dir must not be searched: {names:?}"
        );
        // No home: only the fixed nix profile dir remains; deterministic and
        // never loads any shell startup file (source-level guard below).
        assert_eq!(
            user_cli_search_dirs(None),
            vec![PathBuf::from("/nix/var/nix/profiles/default/bin")]
        );
    }

    #[cfg(windows)]
    #[test]
    fn user_cli_search_dirs_are_empty_on_windows() {
        let home = tempdir().unwrap();
        assert!(user_cli_search_dirs(Some(home.path())).is_empty());
        assert!(user_cli_search_dirs(None).is_empty());
    }

    #[cfg(not(windows))]
    #[test]
    fn user_local_dir_resolution_finds_installed_clis() {
        let home = tempdir().unwrap();
        let local_bin = home.path().join(".local/bin");
        std::fs::create_dir_all(&local_bin).unwrap();
        std::fs::write(local_bin.join("codex"), b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(local_bin.join("codex"))
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(local_bin.join("codex"), perms).unwrap();
        }
        let nvm_bin = home.path().join(".nvm/versions/node/v24.19.0/bin");
        std::fs::create_dir_all(&nvm_bin).unwrap();
        std::fs::write(nvm_bin.join("pi"), b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(nvm_bin.join("pi")).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(nvm_bin.join("pi"), perms).unwrap();
        }
        let dirs = user_cli_search_dirs(Some(home.path()));
        assert_eq!(
            resolve_executable_in_dirs("codex", &dirs, None, false, None),
            Some(local_bin.join("codex"))
        );
        assert_eq!(
            resolve_executable_in_dirs("pi", &dirs, None, false, None),
            Some(nvm_bin.join("pi"))
        );
        assert_eq!(
            resolve_executable_in_dirs("absent-cli", &dirs, None, false, None),
            None
        );
    }

    /// The user-CLI discovery path must never load a shell startup file:
    /// source-level guard on the production code (tests module stripped).
    #[test]
    fn user_cli_discovery_never_sources_shell_startup_files() {
        let src = include_str!("lib.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        // A real sourcing implementation would have to reference these file
        // names or spawn a shell; none may appear in production code.
        for forbidden in [
            ".bashrc",
            ".zshrc",
            ".bash_profile",
            "bash_login",
            ".profile",
            ".zprofile",
        ] {
            assert!(
                !prod.contains(forbidden),
                "user CLI discovery must not reference shell startup files: {forbidden}"
            );
        }
    }

    /// P1-D/P1-F: invocation-path resolution must use the same launchable-file
    /// semantics as profile detection. A non-executable first PATH match must
    /// be skipped (a later executable wins), so command/review pinning can
    /// never pin a file that discovery would not report installed and that
    /// spawning would reject with EACCES.
    #[cfg(unix)]
    #[test]
    fn invocation_resolution_skips_non_launchable_first_match() {
        let dir = tempdir().unwrap();
        let first = dir.path().join("first");
        let second = dir.path().join("second");
        std::fs::create_dir_all(&first).unwrap();
        std::fs::create_dir_all(&second).unwrap();
        // Non-executable first match (leftover shim without its exec bit).
        std::fs::write(first.join("codex"), b"#!/bin/sh\n").unwrap();
        // Executable later match.
        std::fs::write(second.join("codex"), b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(second.join("codex"))
                .unwrap()
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(second.join("codex"), perms).unwrap();
        }
        let dirs = vec![first.clone(), second.clone()];
        // Profile detection (launchable) skips the first match.
        assert_eq!(
            resolve_launchable_executable_in_dirs("codex", &dirs, None, false, None),
            Some(second.join("codex"))
        );
        // Invocation resolution uses the same launchable core, so it must
        // agree (P1-F: no detect-ready-then-pin-unlaunchable divergence).
        assert_eq!(
            resolve_launchable_executable_in_dirs("codex", &dirs, None, false, None),
            Some(second.join("codex"))
        );
        // And spawn resolution agrees too.
        let argv = resolve_spawn_argv_in_dirs("codex", &[], &dirs, None, false, None).unwrap();
        assert_eq!(argv[0], second.join("codex").to_string_lossy());
    }

    /// P1-D: an unset `PATH` must not make invocation/spawn resolution fail
    /// before the deterministic user-local dirs are searched — discovery and
    /// launch must agree even when the service environment has no PATH.
    #[cfg(not(windows))]
    #[test]
    fn unset_path_still_searches_user_local_dirs() {
        let home = tempfile::tempdir().unwrap();
        let bin = home.path().join(".local/bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("codex"), b"#!/bin/sh\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(bin.join("codex")).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(bin.join("codex"), perms).unwrap();
        }
        // The pure dirs core: user-local dirs are searched even with an empty
        // PATH-derived list (the production wrapper treats unset PATH as
        // empty and appends these dirs).
        let dirs = user_cli_search_dirs(Some(home.path()));
        assert_eq!(
            resolve_launchable_executable_in_dirs("codex", &dirs, None, false, None),
            Some(bin.join("codex")),
            "user-local dirs must be searched with no PATH"
        );
        let argv = resolve_spawn_argv_in_dirs("codex", &[], &dirs, None, false, None).unwrap();
        assert_eq!(argv[0], bin.join("codex").to_string_lossy());
    }
}
