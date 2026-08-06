//! OwnMesh structured command and process execution.
//!
//! Provides shell-free structured commands, optional raw shell, timeouts,
//! process-tree kill best-effort, bounded output, and an idempotency journal.

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

/// Simple file-backed idempotency journal.
#[derive(Debug, Default)]
pub struct IdempotencyJournal {
    path: PathBuf,
    entries: HashMap<String, RunResult>,
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

    /// Lookup a previous result.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&RunResult> {
        self.entries.get(key)
    }

    /// Record a result.
    pub fn put(&mut self, key: String, result: RunResult) -> ExecResult<()> {
        self.entries.insert(key, result);
        self.flush()
    }

    fn flush(&self) -> ExecResult<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let raw = serde_json::to_string_pretty(&self.entries)
            .map_err(|e| ExecError::Journal(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, raw)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
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
    journal: Option<&mut IdempotencyJournal>,
) -> ExecResult<RunResult> {
    if let (Some(key), Some(j)) = (req.idempotency_key.as_deref(), journal.as_ref()) {
        if let Some(prev) = j.get(key) {
            let mut replayed = prev.clone();
            replayed.replayed = true;
            return Ok(replayed);
        }
    }

    let start = Instant::now();
    let mut cmd = build_command(req)?;
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
            Ok(res) => res?,
            Err(_) => {
                // Best-effort kill; kill_on_drop also helps.
                return Ok(RunResult {
                    exit_code: None,
                    stdout: String::new(),
                    stderr: format!("command timed out after {dur:?}"),
                    timed_out: true,
                    duration_ms: start.elapsed().as_millis() as u64,
                    truncated: false,
                    replayed: false,
                });
            }
        }
    } else {
        wait_fut.await?
    };

    let (stdout, t1) = truncate_bytes(output.stdout, req.max_output_bytes);
    let remain = req.max_output_bytes.saturating_sub(stdout.len());
    let (stderr, t2) = truncate_bytes(output.stderr, remain);
    let result = RunResult {
        exit_code: output.status.code(),
        stdout,
        stderr,
        timed_out: false,
        duration_ms: start.elapsed().as_millis() as u64,
        truncated: t1 || t2,
        replayed: false,
    };

    if let (Some(key), Some(j)) = (req.idempotency_key.clone(), journal) {
        j.put(key, result.clone())?;
    }
    Ok(result)
}

/// Synchronous helper for simple tests (blocks on current runtime or creates one).
pub fn run_command_blocking(req: &RunRequest, journal_path: Option<&Path>) -> ExecResult<RunResult> {
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
}
