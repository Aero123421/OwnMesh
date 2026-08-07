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
use tokio::process::Command;

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
    1024 * 1024
}

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
            let raw = std::fs::read_to_string(&path)?;
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
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    Ok(cmd)
}

fn truncate_bytes(mut data: Vec<u8>, max: usize) -> (String, bool) {
    let truncated = data.len() > max;
    if truncated {
        data.truncate(max);
    }
    let text = String::from_utf8_lossy(&data).into_owned();
    (text, truncated)
}

/// Run a command, optionally consulting/updating an idempotency journal.
pub async fn run_command(
    req: &RunRequest,
    mut journal: Option<&mut IdempotencyJournal>,
) -> ExecResult<RunResult> {
    // Request validation/building has no external side effect and happens before
    // reserving the key. Spawn remains strictly after the durable marker.
    let mut cmd = build_command(req)?;
    if let (Some(key), Some(j)) = (req.idempotency_key.as_deref(), journal.as_deref_mut()) {
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

    if let Some(input) = &req.stdin {
        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin.write_all(input.as_bytes()).await?;
        }
    }

    let timeout = req.timeout_ms.map(Duration::from_millis);
    let wait_fut = child.wait_with_output();
    let output = if let Some(dur) = timeout {
        match tokio::time::timeout(dur, wait_fut).await {
            Ok(res) => Some(res?),
            // Best-effort kill; kill_on_drop also helps. The timeout result is
            // still journaled so retry cannot start a second process.
            Err(_) => None,
        }
    } else {
        Some(wait_fut.await?)
    };

    let result = if let Some(output) = output {
        let (stdout, t1) = truncate_bytes(output.stdout, req.max_output_bytes);
        let remain = req.max_output_bytes.saturating_sub(stdout.len());
        let (stderr, t2) = truncate_bytes(output.stderr, remain);
        RunResult {
            exit_code: output.status.code(),
            stdout,
            stderr,
            timed_out: false,
            duration_ms: start.elapsed().as_millis() as u64,
            truncated: t1 || t2,
            replayed: false,
        }
    } else {
        RunResult {
            exit_code: None,
            stdout: String::new(),
            stderr: format!(
                "command timed out after {:?}",
                timeout.expect("timeout result requires configured duration")
            ),
            timed_out: true,
            duration_ms: start.elapsed().as_millis() as u64,
            truncated: false,
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
        assert_eq!(python, CommandKind::Structured);

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
