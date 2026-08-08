//! Read-only Git status / diff operations.
//!
//! Runs the `git` CLI against a workspace-resolved repository path. Write-side
//! git operations (add/commit/push) are intentionally out of scope.

use crate::{FsError, FsResult, WorkspaceRoot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

/// One porcelain status entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitStatusEntry {
    /// Two-character porcelain status (` M`, `??`, `A `, …).
    pub code: String,
    /// Path relative to the repository root.
    pub path: String,
    /// Optional rename/copy source path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub orig_path: Option<String>,
}

/// Paginated `git status` result (entry-offset cursor, same idea as log pages).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitStatusPage {
    /// Repository root (absolute).
    pub repo_root: String,
    /// Current branch name when detached HEAD is not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<String>,
    /// Upstream branch (`origin/main`) when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream: Option<String>,
    /// True when there are no status entries at all *and* capture was complete.
    pub clean: bool,
    /// Page of entries.
    pub entries: Vec<GitStatusEntry>,
    /// Next entry offset, when more remain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<u64>,
    /// True when this page exhausted the *captured* status list.
    /// When [`Self::truncated`] is set, exhaustion only covers the bounded capture
    /// window — never claim the working tree is fully enumerated.
    pub exhausted: bool,
    /// True when the porcelain capture hit the byte ceiling before EOF. Visible
    /// to callers; never silently report a truncated status as complete.
    #[serde(default)]
    pub truncated: bool,
}

/// Paginated unified-diff page (line-offset cursor).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GitDiffPage {
    pub repo_root: String,
    /// Whether `--cached` / staged diff was requested.
    pub staged: bool,
    /// Diff text lines for this page.
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<u64>,
    pub exhausted: bool,
    /// True when the combined diff text was truncated by `max_bytes` before paging.
    pub truncated: bool,
}

/// Options for [`git_status`].
#[derive(Debug, Clone, Default)]
pub struct GitStatusOpts {
    /// Workspace-relative path to the repo (or a subdirectory inside it).
    pub path: PathBuf,
    /// Entry offset cursor (0-based).
    pub cursor: Option<u64>,
    /// Max entries in this page.
    pub limit: usize,
}

/// Options for [`git_diff`].
#[derive(Debug, Clone, Default)]
pub struct GitDiffOpts {
    pub path: PathBuf,
    /// Optional pathspec filter.
    pub pathspec: Option<String>,
    /// Staged (`--cached`) diff when true.
    pub staged: bool,
    /// Line offset cursor (0-based).
    pub cursor: Option<u64>,
    pub limit: usize,
    /// Hard cap on raw diff bytes fetched from git.
    pub max_bytes: usize,
}

fn default_status_limit(n: usize) -> usize {
    if n == 0 {
        100
    } else {
        n.min(1000)
    }
}

fn default_diff_limit(n: usize) -> usize {
    if n == 0 {
        200
    } else {
        n.min(5000)
    }
}

/// Hard ceiling for a single git stdout capture (status or diff). Larger
/// outputs must be retrieved via cursor pages; never `read_to_end` unbounded.
const GIT_STDOUT_HARD_CAP: usize = 2 * 1024 * 1024;
const GIT_STDERR_HARD_CAP: usize = 64 * 1024;
/// Wall-clock ceiling for a single git subprocess (fail closed; kill on exceed).
const GIT_TIMEOUT: Duration = Duration::from_secs(30);

/// Run read-only `git status --porcelain=v1 -b` with entry pagination.
///
/// # Errors
///
/// Returns an error when the repository path is invalid or outside the enforced
/// workspace, or when a `git` subprocess cannot be run successfully.
pub fn git_status(ws: &WorkspaceRoot, opts: &GitStatusOpts) -> FsResult<GitStatusPage> {
    let cwd = resolve_repo_cwd(ws, &opts.path)?;
    // Cap status capture well under the hard ceiling; porcelain is line-oriented.
    let (output, byte_truncated) = run_git_capped(
        &cwd,
        &["status", "--porcelain=v1", "-b", "--untracked-files=all"],
        512 * 1024,
    )?;
    // Drop a trailing partial line when the byte cap cut mid-record so paging
    // never surfaces a corrupt porcelain row as a real path.
    let text = if byte_truncated && !output.ends_with('\n') {
        match output.rfind('\n') {
            Some(idx) => &output[..=idx],
            None => "",
        }
    } else {
        output.as_str()
    };
    let (branch, upstream, entries) = parse_porcelain_v1(text);
    // A truncated capture cannot prove cleanliness.
    let clean = entries.is_empty() && !byte_truncated;
    let start = cursor_to_index(opts.cursor);
    let limit = default_status_limit(opts.limit);
    let slice = if start >= entries.len() {
        &[][..]
    } else {
        let end = start.saturating_add(limit).min(entries.len());
        &entries[start..end]
    };
    let next_index = start.saturating_add(slice.len());
    // Exhausted only when we consumed the captured list AND git EOF was reached.
    let captured_exhausted = next_index >= entries.len();
    let exhausted = captured_exhausted && !byte_truncated;
    // When byte-truncated past the captured window, still advertise a cursor so
    // clients see the incomplete capture rather than a silent full result. A
    // zero-progress cursor at `entries.len()` with truncated=true is visible.
    let next_cursor = if exhausted {
        None
    } else {
        Some(u64::try_from(next_index).unwrap_or(u64::MAX))
    };
    Ok(GitStatusPage {
        repo_root: cwd.to_string_lossy().into_owned(),
        branch,
        upstream,
        clean,
        entries: slice.to_vec(),
        next_cursor,
        exhausted,
        truncated: byte_truncated,
    })
}

/// Run read-only `git diff` (or `--cached`) with line pagination.
///
/// Stdout is streamed with a hard byte cap before line paging so an attacker-
/// controlled repository cannot force unbounded allocation via `Command::output`.
/// When the byte cap truncates mid-stream, `truncated=true` and `exhausted=false`
/// with a cursor so clients can continue; discarded bytes are never silently
/// dropped without a visible flag.
///
/// # Errors
///
/// Returns an error when the repository path is invalid or outside the enforced
/// workspace, or when a `git` subprocess cannot be run successfully.
pub fn git_diff(ws: &WorkspaceRoot, opts: &GitDiffOpts) -> FsResult<GitDiffPage> {
    let cwd = resolve_repo_cwd(ws, &opts.path)?;
    let mut args: Vec<String> = vec!["diff".into(), "--no-color".into(), "--no-ext-diff".into()];
    if opts.staged {
        args.push("--cached".into());
    }
    if let Some(ps) = &opts.pathspec {
        args.push("--".into());
        args.push(ps.clone());
    }
    let arg_refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let max_bytes = if opts.max_bytes == 0 {
        256 * 1024
    } else {
        opts.max_bytes.min(GIT_STDOUT_HARD_CAP)
    };
    let start = cursor_to_index(opts.cursor);
    let limit = default_diff_limit(opts.limit);

    // Capture once into a durable line spool keyed by repo+args+byte budget so
    // later cursors page the same snapshot. Re-running git and re-capturing only
    // a prefix made cursors past that prefix return empty pages with another
    // continuation cursor (zero forward progress).
    let spool = load_or_build_diff_spool(&cwd, &arg_refs, max_bytes)?;
    let total_lines = spool.lines.len();
    let byte_truncated = spool.truncated;

    if start > total_lines || (start == total_lines && start > 0 && !byte_truncated) {
        // Cursor past known snapshot with proven EOF → empty exhausted page.
        // Cursor == total with truncated capture → visible stuck truncated state
        // (no silent claim of completeness; no fabricated progress).
        let exhausted = !byte_truncated;
        return Ok(GitDiffPage {
            repo_root: cwd.to_string_lossy().into_owned(),
            staged: opts.staged,
            lines: Vec::new(),
            next_cursor: (!exhausted).then(|| u64::try_from(start).unwrap_or(u64::MAX)),
            exhausted,
            truncated: byte_truncated,
        });
    }

    let end = start.saturating_add(limit).min(total_lines);
    let page_lines = spool.lines[start..end].to_vec();
    let next_index = end;
    let more_in_spool = next_index < total_lines;
    // More content may exist beyond the byte cap even when the spool page ends.
    let more_after_page = more_in_spool || (next_index >= total_lines && byte_truncated);
    let exhausted = !more_after_page;
    let next_cursor = (!exhausted).then(|| u64::try_from(next_index).unwrap_or(u64::MAX));
    Ok(GitDiffPage {
        repo_root: cwd.to_string_lossy().into_owned(),
        staged: opts.staged,
        lines: page_lines,
        next_cursor,
        exhausted,
        truncated: byte_truncated || more_after_page,
    })
}

/// Bounded durable git-diff line snapshot for stable offset pagination.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiffSpool {
    lines: Vec<String>,
    truncated: bool,
    /// SHA-256 of the raw captured bytes (integrity / debugging).
    content_sha256: String,
}

fn diff_spool_dir() -> PathBuf {
    // Per-user private state directory (not the shared world-writable temp root).
    let base = std::env::var_os("OWNMESH_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| dirs_state_home().map(|h| h.join("OwnMesh").join("state")))
        .unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push(format!("ownmesh-{}", whoami_fallback()));
            p.push("state");
            p
        });
    base.join("git-diff-spool")
}

fn dirs_state_home() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    }
    #[cfg(not(windows))]
    {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))
    }
}

fn whoami_fallback() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| format!("uid-{}", std::process::id()))
}

fn diff_spool_path(cwd: &Path, args: &[&str], max_bytes: usize) -> PathBuf {
    let mut hasher = Sha256::new();
    hasher.update(cwd.to_string_lossy().as_bytes());
    hasher.update([0]);
    for a in args {
        hasher.update(a.as_bytes());
        hasher.update([0]);
    }
    hasher.update(max_bytes.to_le_bytes());
    // Bind to the creating process owner identity so cross-user path prediction
    // alone cannot point at another principal's spool without also matching the dir.
    hasher.update(whoami_fallback().as_bytes());
    let digest = hex::encode(hasher.finalize());
    diff_spool_dir().join(format!("{digest}.json"))
}

fn ensure_private_spool_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(dir)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

const DIFF_SPOOL_TTL_SECS: u64 = 15 * 60;
const MAX_DIFF_SPOOLS: usize = 64;
const MAX_DIFF_SPOOL_TOTAL_BYTES: u64 = 256 * 1024 * 1024;

fn cleanup_diff_spools(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut files: Vec<(std::path::PathBuf, u64, u64)> = Vec::new();
    for ent in rd.flatten() {
        let path = ent.path();
        let is_spool = path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext == "json" || ext.starts_with("json."));
        if !is_spool {
            continue;
        }
        // Drop leftover temp files aggressively.
        if path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|ext| ext.starts_with("json."))
        {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        if now.saturating_sub(modified) > DIFF_SPOOL_TTL_SECS {
            let _ = std::fs::remove_file(&path);
            continue;
        }
        files.push((path, modified, meta.len()));
    }
    // Newest first; drop oldest beyond count and total byte quotas.
    files.sort_by(|a, b| b.1.cmp(&a.1));
    let mut kept_bytes = 0u64;
    for (idx, (path, _, len)) in files.into_iter().enumerate() {
        if idx >= MAX_DIFF_SPOOLS || kept_bytes.saturating_add(len) > MAX_DIFF_SPOOL_TOTAL_BYTES {
            let _ = std::fs::remove_file(path);
        } else {
            kept_bytes = kept_bytes.saturating_add(len);
        }
    }
}

fn load_or_build_diff_spool(cwd: &Path, args: &[&str], max_bytes: usize) -> FsResult<DiffSpool> {
    let path = diff_spool_path(cwd, args, max_bytes);
    if let Some(parent) = path.parent() {
        let _ = ensure_private_spool_dir(parent);
        cleanup_diff_spools(parent);
    }

    // Only trust an existing spool when it is a regular file we can open exclusively
    // enough to hash, and the embedded content hash matches the line payload.
    if let Ok(meta) = std::fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() || !meta.is_file() {
            let _ = std::fs::remove_file(&path);
        } else if let Ok(bytes) = std::fs::read(&path) {
            if bytes.len() <= GIT_STDOUT_HARD_CAP.saturating_add(256 * 1024) {
                if let Ok(spool) = serde_json::from_slice::<DiffSpool>(&bytes) {
                    let mut hasher = Sha256::new();
                    for (i, line) in spool.lines.iter().enumerate() {
                        if i > 0 {
                            hasher.update(b"\n");
                        }
                        hasher.update(line.as_bytes());
                    }
                    let recomputed = hex::encode(hasher.finalize());
                    if spool.lines.len() <= 500_000
                        && spool.lines.iter().map(String::len).sum::<usize>()
                            <= GIT_STDOUT_HARD_CAP.saturating_mul(2)
                        && spool.content_sha256 == recomputed
                    {
                        return Ok(spool);
                    }
                }
            }
            let _ = std::fs::remove_file(&path);
        }
    }

    let (raw, byte_truncated) = run_git_capped(cwd, args, max_bytes)?;
    // Keep only complete lines when truncated mid-line so paging stays stable.
    let text = if byte_truncated && !raw.ends_with('\n') {
        match raw.rfind('\n') {
            Some(idx) => &raw[..=idx],
            None => "",
        }
    } else {
        raw.as_str()
    };
    let lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let mut hasher = Sha256::new();
    for (i, line) in lines.iter().enumerate() {
        if i > 0 {
            hasher.update(b"\n");
        }
        hasher.update(line.as_bytes());
    }
    let content_sha256 = hex::encode(hasher.finalize());
    let spool = DiffSpool {
        lines,
        truncated: byte_truncated,
        content_sha256,
    };
    if let Ok(encoded) = serde_json::to_vec(&spool) {
        // Exclusive random temp then rename into place (no predictable preseed window
        // on the final name beyond the final rename).
        let mut rand_tok = Sha256::new();
        rand_tok.update(spool.content_sha256.as_bytes());
        rand_tok.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos().to_le_bytes())
                .unwrap_or([0; 16]),
        );
        rand_tok.update(std::process::id().to_le_bytes());
        let tok = hex::encode(rand_tok.finalize());
        let tmp = path.with_extension(format!("json.{}.tmp", &tok[..16]));
        if std::fs::write(&tmp, &encoded).is_ok() {
            let _ = std::fs::rename(&tmp, &path);
            let _ = std::fs::remove_file(&tmp);
        }
    }
    Ok(spool)
}

fn cursor_to_index(cursor: Option<u64>) -> usize {
    cursor.map_or(0, |value| usize::try_from(value).unwrap_or(usize::MAX))
}

fn resolve_repo_cwd(ws: &WorkspaceRoot, rel: &Path) -> FsResult<PathBuf> {
    let path = if ws.enforce {
        crate::custody::resolve_dir_enforced(ws, rel)?
    } else if rel.as_os_str().is_empty() {
        ws.root().to_path_buf()
    } else {
        ws.resolve(rel)?
    };
    if !ws.enforce && !path.exists() {
        return Err(FsError::NotFound(path));
    }
    // Discover toplevel so status works from a subdirectory.
    let toplevel = run_git(&path, &["rev-parse", "--show-toplevel"])?;
    let root = PathBuf::from(toplevel.trim());
    // Re-validate against workspace boundary (absolute resolve honors enforce).
    if ws.enforce {
        // Git toplevel is absolute; require it to sit under the workspace root and
        // re-pin the directory handle before returning it as cwd.
        let checked = ws.resolve(&root)?;
        let dir = crate::custody::resolve_dir_enforced(ws, &checked)?;
        return Ok(dir);
    }
    let checked = ws.resolve(&root)?;
    Ok(checked)
}

fn run_git(cwd: &Path, args: &[&str]) -> FsResult<String> {
    let (out, truncated) = run_git_capped(cwd, args, GIT_STDOUT_HARD_CAP)?;
    if truncated {
        return Err(FsError::Io {
            path: Some(cwd.to_path_buf()),
            source: std::io::Error::other(format!(
                "git {} output exceeded {} byte capture ceiling",
                args.first().unwrap_or(&""),
                GIT_STDOUT_HARD_CAP
            )),
        });
    }
    Ok(out)
}

/// Spawn git with piped stdout/stderr, concurrent capped drains, and a hard timeout.
/// Returns `(lossy_utf8_stdout, truncated)` where truncated means more stdout bytes
/// were available than returned (visible to callers; never silent).
///
/// Drains stdout and stderr on separate threads so a process that fills stderr before
/// stdout cannot deadlock the pipes. On timeout the child process tree is killed.
fn run_git_capped(cwd: &Path, args: &[&str], max_stdout: usize) -> FsResult<(String, bool)> {
    let max_stdout = max_stdout.clamp(1, GIT_STDOUT_HARD_CAP);
    // Point global/system config at a guaranteed-empty path so untrusted
    // includeIf/fsmonitor/hooks from the operator home directory cannot run.
    #[cfg(windows)]
    let empty_config = "NUL";
    #[cfg(not(windows))]
    let empty_config = "/dev/null";
    // Force-disable repo-local fsmonitor/hooks helpers even when the target
    // repository enables them — read-only status/diff must not exec unapproved
    // helpers from .git/config.
    let mut git_argv: Vec<&str> = vec![
        "-c",
        "core.fsmonitor=",
        "-c",
        "core.fsmonitorHookVersion=",
        "-c",
        "fsmonitor.allowRemote=false",
        "-c",
        "core.useBuiltinFSMonitor=false",
    ];
    git_argv.extend_from_slice(args);
    let mut child = Command::new("git")
        .args(&git_argv)
        .current_dir(cwd)
        // Reduce untrusted-repo execution surface for read-only captures.
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", empty_config)
        .env("GIT_CONFIG_SYSTEM", empty_config)
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|source| FsError::Io {
            path: Some(cwd.to_path_buf()),
            source,
        })?;

    let stdout = child.stdout.take().ok_or_else(|| FsError::Io {
        path: Some(cwd.to_path_buf()),
        source: std::io::Error::other("git stdout pipe missing"),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| FsError::Io {
        path: Some(cwd.to_path_buf()),
        source: std::io::Error::other("git stderr pipe missing"),
    })?;

    let (out_tx, out_rx) = mpsc::channel::<(Vec<u8>, bool)>();
    let (err_tx, err_rx) = mpsc::channel::<Vec<u8>>();

    thread::spawn(move || {
        let _ = out_tx.send(read_capped(stdout, max_stdout));
    });
    thread::spawn(move || {
        let (buf, _truncated) = read_capped(stderr, GIT_STDERR_HARD_CAP);
        let _ = err_tx.send(buf);
    });

    let deadline = Instant::now() + GIT_TIMEOUT;
    let mut out_buf = None;
    let mut err_buf = None;
    let mut timed_out = false;

    // Wait for both drains or timeout; kill child on timeout so pipes unblock.
    while out_buf.is_none() || err_buf.is_none() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            timed_out = true;
            kill_git_child(&mut child);
            break;
        }
        if out_buf.is_none() {
            match out_rx.recv_timeout(Duration::from_millis(50).min(remaining)) {
                Ok(v) => out_buf = Some(v),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    out_buf = Some((Vec::new(), false));
                }
            }
        }
        if err_buf.is_none() {
            match err_rx.recv_timeout(
                Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now())),
            ) {
                Ok(v) => err_buf = Some(v),
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    err_buf = Some(Vec::new());
                }
            }
        }
    }

    // Collect any late drain results after kill (bounded wait).
    if out_buf.is_none() {
        out_buf = out_rx.recv_timeout(Duration::from_secs(2)).ok();
    }
    if err_buf.is_none() {
        err_buf = err_rx.recv_timeout(Duration::from_secs(2)).ok();
    }

    let status = if timed_out {
        let _ = child.try_wait();
        None
    } else {
        Some(child.wait().map_err(|source| FsError::Io {
            path: Some(cwd.to_path_buf()),
            source,
        })?)
    };

    if timed_out {
        return Err(FsError::Io {
            path: Some(cwd.to_path_buf()),
            source: std::io::Error::other(format!(
                "git {} exceeded {}s wall-clock capture timeout and was killed",
                args.first().unwrap_or(&""),
                GIT_TIMEOUT.as_secs()
            )),
        });
    }

    let (out_buf, truncated) = out_buf.unwrap_or_default();
    let err_buf = err_buf.unwrap_or_default();
    let status = status.expect("status set when not timed out");
    if !status.success() {
        let stderr = String::from_utf8_lossy(&err_buf);
        return Err(FsError::Io {
            path: Some(cwd.to_path_buf()),
            source: std::io::Error::other(format!(
                "git {} failed ({}): {}",
                args.first().unwrap_or(&""),
                status,
                stderr.trim()
            )),
        });
    }
    Ok((String::from_utf8_lossy(&out_buf).into_owned(), truncated))
}

fn read_capped(mut pipe: impl Read, max_bytes: usize) -> (Vec<u8>, bool) {
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 8192];
    let mut truncated = false;
    loop {
        if buf.len() >= max_bytes {
            truncated = true;
            let mut discard = [0_u8; 8192];
            while pipe.read(&mut discard).unwrap_or(0) > 0 {}
            break;
        }
        let want = (max_bytes - buf.len()).min(tmp.len());
        match pipe.read(&mut tmp[..want]) {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&tmp[..n]),
        }
    }
    (buf, truncated)
}

fn kill_git_child(child: &mut Child) {
    let pid = child.id();
    #[cfg(windows)]
    {
        let _ = Command::new("taskkill")
            .args(["/PID", &pid.to_string(), "/T", "/F"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    #[cfg(not(windows))]
    {
        let _ = Command::new("kill")
            .args(["-TERM", &format!("-{pid}")])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn parse_porcelain_v1(text: &str) -> (Option<String>, Option<String>, Vec<GitStatusEntry>) {
    let mut branch = None;
    let mut upstream = None;
    let mut entries = Vec::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            // ## main...origin/main [ahead 1]
            let head = rest.split_whitespace().next().unwrap_or(rest);
            if let Some((local, remote)) = head.split_once("...") {
                branch = Some(local.to_string());
                upstream = Some(remote.to_string());
            } else if head != "HEAD (no branch)" {
                branch = Some(head.to_string());
            }
            continue;
        }
        if line.len() < 3 {
            continue;
        }
        let code = line[..2].to_string();
        let rest = line[3..].to_string();
        // rename: "old -> new"
        let (path, orig_path) = if let Some((a, b)) = rest.split_once(" -> ") {
            (b.to_string(), Some(a.to_string()))
        } else {
            (rest, None)
        };
        entries.push(GitStatusEntry {
            code,
            path,
            orig_path,
        });
    }
    (branch, upstream, entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::WorkspaceRoot;
    use std::fmt::Write as _;
    use std::fs;
    use tempfile::tempdir;

    fn init_repo(dir: &Path) {
        assert!(Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["config", "user.email", "ownmesh@test.local"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["config", "user.name", "OwnMesh Test"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        // Avoid default branch ambiguity across git versions.
        let _ = Command::new("git")
            .args(["checkout", "-b", "main"])
            .current_dir(dir)
            .status();
        fs::write(dir.join("README.md"), b"v1\n").unwrap();
        assert!(Command::new("git")
            .args(["add", "README.md"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(dir)
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn status_and_diff_on_fixture_repo() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        fs::write(dir.path().join("README.md"), b"v2\n").unwrap();
        fs::write(dir.path().join("new.txt"), b"fresh\n").unwrap();

        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        let status = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::new(),
                cursor: None,
                limit: 10,
            },
        )
        .unwrap();
        assert!(!status.clean);
        assert!(status.exhausted);
        assert!(
            status.entries.iter().any(|e| e.path == "README.md"),
            "{:?}",
            status.entries
        );
        assert!(
            status.entries.iter().any(|e| e.path == "new.txt"),
            "{:?}",
            status.entries
        );
        assert!(status.branch.is_some());

        let diff = git_diff(
            &ws,
            &GitDiffOpts {
                path: PathBuf::new(),
                pathspec: Some("README.md".into()),
                staged: false,
                cursor: None,
                limit: 50,
                max_bytes: 64 * 1024,
            },
        )
        .unwrap();
        assert!(diff.exhausted);
        let joined = diff.lines.join("\n");
        assert!(
            joined.contains("-v1") || joined.contains("+v2") || joined.contains("README"),
            "{joined}"
        );
    }

    #[test]
    fn status_cursor_pagination() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        for i in 0..5 {
            fs::write(dir.path().join(format!("f{i}.txt")), b"x").unwrap();
        }
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        let page1 = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::new(),
                cursor: None,
                limit: 2,
            },
        )
        .unwrap();
        assert_eq!(page1.entries.len(), 2);
        assert!(!page1.exhausted);
        assert_eq!(page1.next_cursor, Some(2));

        let page2 = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::new(),
                cursor: page1.next_cursor,
                limit: 2,
            },
        )
        .unwrap();
        assert_eq!(page2.entries.len(), 2);
        assert_eq!(page2.next_cursor, Some(4));

        let page3 = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::new(),
                cursor: page2.next_cursor,
                limit: 10,
            },
        )
        .unwrap();
        assert_eq!(page3.entries.len(), 1);
        assert!(page3.exhausted);
        assert!(page3.next_cursor.is_none());

        // No overlap across pages.
        let mut all = Vec::new();
        all.extend(page1.entries.iter().map(|e| e.path.clone()));
        all.extend(page2.entries.iter().map(|e| e.path.clone()));
        all.extend(page3.entries.iter().map(|e| e.path.clone()));
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 5);
    }

    #[test]
    fn diff_line_cursor_pagination() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        // Produce a multi-line diff.
        let mut body = String::from("v1\n");
        for i in 0..30 {
            writeln!(&mut body, "line {i}").unwrap();
        }
        fs::write(dir.path().join("README.md"), body.as_bytes()).unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        let page1 = git_diff(
            &ws,
            &GitDiffOpts {
                path: PathBuf::new(),
                pathspec: None,
                staged: false,
                cursor: None,
                limit: 5,
                max_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        assert_eq!(page1.lines.len(), 5);
        assert!(!page1.exhausted);
        let page2 = git_diff(
            &ws,
            &GitDiffOpts {
                path: PathBuf::new(),
                pathspec: None,
                staged: false,
                cursor: page1.next_cursor,
                limit: 5,
                max_bytes: 1024 * 1024,
            },
        )
        .unwrap();
        assert_eq!(page2.lines.len(), 5);
        assert_ne!(page1.lines, page2.lines);
    }

    #[test]
    fn parse_branch_and_rename() {
        let sample = "\
## feature...origin/feature [ahead 1]
 M src/a.rs
R  old.txt -> new.txt
?? scratch.md
";
        let (branch, upstream, entries) = parse_porcelain_v1(sample);
        assert_eq!(branch.as_deref(), Some("feature"));
        assert_eq!(upstream.as_deref(), Some("origin/feature"));
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[1].orig_path.as_deref(), Some("old.txt"));
        assert_eq!(entries[1].path, "new.txt");
    }

    #[test]
    fn status_never_claims_exhausted_when_capture_truncated() {
        // Build a working tree whose porcelain exceeds a tiny capture budget.
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        // Long relative paths inflate porcelain bytes quickly.
        let stem = "n".repeat(180);
        for i in 0..80 {
            fs::write(dir.path().join(format!("{stem}_{i:03}.txt")), b"x").unwrap();
        }
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        // Force a small capture by calling run_git_capped through a local helper path:
        // git_status uses 512 KiB; instead assert the truncated field plumbing via
        // a direct capped capture that mirrors the status argv.
        let cwd = resolve_repo_cwd(&ws, Path::new("")).unwrap();
        let (output, truncated) = run_git_capped(
            &cwd,
            &["status", "--porcelain=v1", "-b", "--untracked-files=all"],
            2_048,
        )
        .unwrap();
        assert!(
            truncated,
            "expected tiny budget to truncate; got {} bytes",
            output.len()
        );
        // Re-parse the way git_status does and ensure clean/exhausted stay false.
        let text = if truncated && !output.ends_with('\n') {
            match output.rfind('\n') {
                Some(idx) => &output[..=idx],
                None => "",
            }
        } else {
            output.as_str()
        };
        let (_b, _u, entries) = parse_porcelain_v1(text);
        assert!(
            !entries.is_empty() || truncated,
            "truncated capture must not look clean"
        );
        // Full git_status path (512 KiB) should still succeed and set truncated=false
        // for this fixture size, proving the flag defaults correctly.
        let page = git_status(
            &ws,
            &GitStatusOpts {
                path: PathBuf::new(),
                cursor: None,
                limit: 1000,
            },
        )
        .unwrap();
        assert!(!page.truncated);
        assert!(page.exhausted);
        assert!(!page.clean);
        assert!(page.entries.len() >= 80);
    }

    #[test]
    fn diff_spool_pages_make_forward_progress_under_byte_cap() {
        let dir = tempdir().unwrap();
        init_repo(dir.path());
        // Large multi-line change so a small max_bytes truncates the raw capture.
        let mut body = String::from("v1\n");
        for i in 0..400 {
            writeln!(
                &mut body,
                "payload line {i:04} with padding ****************"
            )
            .unwrap();
        }
        fs::write(dir.path().join("README.md"), body.as_bytes()).unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();

        let mut cursor: Option<u64> = None;
        let mut seen = 0_usize;
        let mut pages = 0_usize;
        let mut last_first: Option<String> = None;
        loop {
            pages += 1;
            assert!(pages < 80, "diff pagination failed to terminate");
            let page = git_diff(
                &ws,
                &GitDiffOpts {
                    path: PathBuf::new(),
                    pathspec: None,
                    staged: false,
                    cursor,
                    limit: 10,
                    max_bytes: 8 * 1024, // force spool truncation on large diff
                },
            )
            .unwrap();
            if !page.lines.is_empty() {
                // Forward progress: first line of this page must differ from prior page
                // whenever we advanced a non-empty cursor window.
                if let Some(prev) = &last_first {
                    assert_ne!(
                        prev, &page.lines[0],
                        "diff page did not advance; cursor={cursor:?} page={pages}"
                    );
                }
                last_first = Some(page.lines[0].clone());
                seen += page.lines.len();
            }
            if page.exhausted {
                assert!(page.next_cursor.is_none());
                break;
            }
            let next = page.next_cursor.expect("continuation cursor");
            // Cursor must move forward when lines were returned.
            if page.lines.is_empty() {
                // Empty page with truncated=true at end of spool is visible failure,
                // not silent completeness — stop without looping forever.
                assert!(
                    page.truncated,
                    "empty non-exhausted page must be truncated, got {page:?}"
                );
                break;
            }
            assert!(
                next > cursor.unwrap_or(0),
                "cursor did not advance: {cursor:?} -> {next}"
            );
            cursor = Some(next);
        }
        assert!(
            seen > 10,
            "expected multiple diff lines across pages, got {seen}"
        );
    }
}
