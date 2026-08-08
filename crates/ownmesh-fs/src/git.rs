//! Read-only Git status / diff operations.
//!
//! Runs the `git` CLI against a workspace-resolved repository path. Write-side
//! git operations (add/commit/push) are intentionally out of scope.

use crate::{FsError, FsResult, WorkspaceRoot};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;

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
    /// True when there are no status entries at all.
    pub clean: bool,
    /// Page of entries.
    pub entries: Vec<GitStatusEntry>,
    /// Next entry offset, when more remain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<u64>,
    /// True when this page exhausted the status list.
    pub exhausted: bool,
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

/// Run read-only `git status --porcelain=v1 -b` with entry pagination.
///
/// # Errors
///
/// Returns an error when the repository path is invalid or outside the enforced
/// workspace, or when a `git` subprocess cannot be run successfully.
pub fn git_status(ws: &WorkspaceRoot, opts: &GitStatusOpts) -> FsResult<GitStatusPage> {
    let cwd = resolve_repo_cwd(ws, &opts.path)?;
    let output = run_git(
        &cwd,
        &["status", "--porcelain=v1", "-b", "--untracked-files=all"],
    )?;
    let (branch, upstream, entries) = parse_porcelain_v1(&output);
    let clean = entries.is_empty();
    let start = cursor_to_index(opts.cursor);
    let limit = default_status_limit(opts.limit);
    let slice = if start >= entries.len() {
        &[][..]
    } else {
        let end = start.saturating_add(limit).min(entries.len());
        &entries[start..end]
    };
    let next_index = start.saturating_add(slice.len());
    let exhausted = next_index >= entries.len();
    let next_cursor = (!exhausted).then(|| u64::try_from(next_index).unwrap_or(u64::MAX));
    Ok(GitStatusPage {
        repo_root: cwd.to_string_lossy().into_owned(),
        branch,
        upstream,
        clean,
        entries: slice.to_vec(),
        next_cursor,
        exhausted,
    })
}

/// Run read-only `git diff` (or `--cached`) with line pagination.
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
    let mut raw = run_git(&cwd, &arg_refs)?;
    let max_bytes = if opts.max_bytes == 0 {
        1024 * 1024
    } else {
        opts.max_bytes
    };
    let truncated = raw.len() > max_bytes;
    if truncated {
        raw.truncate(max_bytes);
    }
    let all_lines: Vec<String> = raw.lines().map(str::to_owned).collect();
    let start = cursor_to_index(opts.cursor);
    let limit = default_diff_limit(opts.limit);
    let slice = if start >= all_lines.len() {
        &[][..]
    } else {
        let end = start.saturating_add(limit).min(all_lines.len());
        &all_lines[start..end]
    };
    let next_index = start.saturating_add(slice.len());
    let exhausted = next_index >= all_lines.len();
    let next_cursor = (!exhausted).then(|| u64::try_from(next_index).unwrap_or(u64::MAX));
    Ok(GitDiffPage {
        repo_root: cwd.to_string_lossy().into_owned(),
        staged: opts.staged,
        lines: slice.to_vec(),
        next_cursor,
        exhausted,
        truncated,
    })
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
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|source| FsError::Io {
            path: Some(cwd.to_path_buf()),
            source,
        })?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(FsError::Io {
            path: Some(cwd.to_path_buf()),
            source: std::io::Error::other(format!(
                "git {} failed ({}): {}",
                args.first().unwrap_or(&""),
                output.status,
                stderr.trim()
            )),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
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
}
