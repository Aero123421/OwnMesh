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

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
    #[error("cancelled")]
    Cancelled,
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
    /// Canonical absolute path that was inspected.
    pub path: String,
    /// Hex SHA-256 of the full file contents at pin time.
    pub content_sha256: String,
    /// Byte length at pin time (fast reject before hashing).
    pub len: u64,
    /// Platform file identity (Unix dev+ino; Windows unavailable → None).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inode: Option<u64>,
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
    if known_interpreter_name(program) || script_extension(program) {
        return true;
    }
    let resolved = resolve_executable_path(program, cwd);
    let Some(path) = resolved.as_deref() else {
        return false;
    };
    if path
        .to_str()
        .is_some_and(|s| known_interpreter_name(s) || script_extension(s))
    {
        return true;
    }
    path_has_shebang(path)
}

/// Hard ceiling for structured executable pin/revalidation hashing.
/// Prevents a remote full-access structured command from forcing unbounded
/// `read()` of a huge regular file before policy execution.
pub const MAX_EXECUTABLE_PIN_BYTES: u64 = 64 * 1024 * 1024;

/// Hard ceiling for the on-disk idempotency journal file.
pub const MAX_JOURNAL_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// Stream SHA-256 of a regular file up to `max_bytes` without unbounded allocation.
fn hash_file_bounded(path: &Path, expected_len: u64, max_bytes: u64) -> ExecResult<String> {
    if expected_len > max_bytes {
        return Err(ExecError::Journal(format!(
            "executable exceeds {max_bytes} byte pin budget: {} ({expected_len} bytes)",
            path.display()
        )));
    }
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
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
            return Err(ExecError::Journal(format!(
                "executable exceeded {max_bytes} byte pin budget while hashing: {}",
                path.display()
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

/// Capture device/inode/content digest for a structured executable path.
///
/// # Errors
///
/// Returns an error when the path cannot be read or is not a regular file.
pub fn pin_executable(path: &Path, policy_kind: CommandKind) -> ExecResult<ExecutablePin> {
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() {
        return Err(ExecError::Journal(format!(
            "executable pin requires a regular file: {}",
            path.display()
        )));
    }
    let content_sha256 = hash_file_bounded(path, meta.len(), MAX_EXECUTABLE_PIN_BYTES)?;
    let (device, inode) = file_identity(&meta);
    Ok(ExecutablePin {
        path: path.to_string_lossy().into_owned(),
        content_sha256,
        len: meta.len(),
        device,
        inode,
        policy_kind: policy_kind.as_str().to_owned(),
    })
}

/// Re-read `path` and ensure it still matches `pin` (fail closed on any drift).
///
/// # Errors
///
/// Returns [`ExecError::Journal`] describing the mismatch / IO failure.
pub fn verify_executable_pin(path: &Path, pin: &ExecutablePin) -> ExecResult<()> {
    let meta = std::fs::metadata(path).map_err(|e| {
        ExecError::Journal(format!(
            "executable pin revalidation failed for {}: {e}",
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
    let (device, inode) = file_identity(&meta);
    if (pin.device.is_some() || pin.inode.is_some()) && (device != pin.device || inode != pin.inode)
    {
        return Err(ExecError::Journal(
            "executable device/inode drifted before execution; request must be re-authorized"
                .into(),
        ));
    }
    let digest = hash_file_bounded(path, meta.len(), MAX_EXECUTABLE_PIN_BYTES).map_err(|e| {
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
        && (path_has_shebang(path) || path.to_str().is_some_and(script_extension))
    {
        return Err(ExecError::Journal(
            "executable became a script/shebang payload before execution; request must be re-authorized"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn file_identity(meta: &std::fs::Metadata) -> (Option<u64>, Option<u64>) {
    use std::os::unix::fs::MetadataExt;
    (Some(meta.dev()), Some(meta.ino()))
}

#[cfg(not(unix))]
fn file_identity(_meta: &std::fs::Metadata) -> (Option<u64>, Option<u64>) {
    (None, None)
}

/// Resolve an executable exactly once through an explicit path or the current PATH.
/// Callers can spawn the returned canonical path to prevent a classified symlink
/// from being reopened through a different target.
#[must_use]
pub fn resolve_executable_path(program: &str, cwd: Option<&Path>) -> Option<PathBuf> {
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
        return std::fs::canonicalize(candidate).ok();
    }

    let search = std::env::var_os("PATH")?;
    for directory in std::env::split_paths(&search) {
        let directory = if directory.is_absolute() {
            directory
        } else {
            cwd.unwrap_or_else(|| Path::new(".")).join(directory)
        };
        let direct = directory.join(raw);
        if let Ok(resolved) = std::fs::canonicalize(&direct) {
            return Some(resolved);
        }
        #[cfg(windows)]
        if Path::new(raw).extension().is_none() {
            for ext in ["exe", "cmd", "bat", "com"] {
                if let Ok(resolved) = std::fs::canonicalize(directory.join(format!("{raw}.{ext}")))
                {
                    return Some(resolved);
                }
            }
        }
    }
    None
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
/// Absolute ceiling for wall-clock timeout (ms).
pub const HARD_MAX_TIMEOUT_MS: u64 = 300_000;

/// Captured command result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RunResult {
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub truncated: bool,
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
            let mut c = Command::new(&req.program);
            c.args(&req.args);
            c
        }
        CommandKind::RawShell => {
            #[cfg(windows)]
            {
                let mut c = Command::new("cmd.exe");
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

fn bytes_to_text(data: &[u8]) -> String {
    String::from_utf8_lossy(data).into_owned()
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
        // Negative PID = process group (spawned with process_group(0)).
        let _ = std::process::Command::new("kill")
            .args(["-KILL", &format!("-{pid}")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
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
    mut journal: Option<&mut IdempotencyJournal>,
    cancel: Option<watch::Receiver<bool>>,
) -> ExecResult<RunResult> {
    // Clamp untrusted ceilings before any allocation or spawn.
    let max_output_bytes = req.max_output_bytes.clamp(1, HARD_MAX_OUTPUT_BYTES);
    let timeout_ms = req.timeout_ms.map(|ms| ms.clamp(1, HARD_MAX_TIMEOUT_MS));
    let mut capped = req.clone();
    capped.max_output_bytes = max_output_bytes;
    capped.timeout_ms = timeout_ms;

    // Request validation/building has no external side effect and happens before
    // reserving the key. Spawn remains strictly after the durable marker.
    let mut cmd = build_command(&capped)?;
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
    let mut child = cmd.spawn()?;

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

    if cancelled {
        // Do not journal a cancelled attempt as a successful side effect; a
        // retry with the same key may legitimately re-run after cancel.
        if let (Some(key), Some(j)) = (req.idempotency_key.as_deref(), journal.as_mut()) {
            let _ = j.clear_in_progress(key);
        }
        return Err(ExecError::Cancelled);
    }

    let result = if timed_out {
        RunResult {
            exit_code: None,
            stdout: bytes_to_text(&stdout_raw),
            stderr: {
                let mut msg = format!(
                    "command timed out after {:?}",
                    timeout.expect("timeout result requires configured duration")
                );
                let err = bytes_to_text(&stderr_raw);
                if !err.is_empty() {
                    msg.push('\n');
                    msg.push_str(&err);
                }
                msg
            },
            timed_out: true,
            duration_ms: start.elapsed().as_millis() as u64,
            truncated,
            replayed: false,
        }
    } else {
        RunResult {
            exit_code,
            stdout: bytes_to_text(&stdout_raw),
            stderr: bytes_to_text(&stderr_raw),
            timed_out: false,
            duration_ms: start.elapsed().as_millis() as u64,
            truncated,
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
    fn pin_executable_rejects_oversized_before_allocation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("huge.bin");
        {
            let f = std::fs::File::create(&path).unwrap();
            // Sparse when the FS supports it — still reports large len() for the ceiling.
            f.set_len(MAX_EXECUTABLE_PIN_BYTES + 1).unwrap();
        }
        let err = pin_executable(&path, CommandKind::Structured).expect_err("must reject");
        let msg = err.to_string();
        assert!(
            msg.contains("pin budget") || msg.contains("byte"),
            "unexpected error: {msg}"
        );
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
}
