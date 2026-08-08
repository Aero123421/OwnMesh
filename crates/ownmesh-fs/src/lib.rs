//! `OwnMesh` filesystem operations and path safety.
//!
//! Workspace-relative resolution, symlink/junction-aware canonicalization,
//! list/stat/read/write/delete, hash-checked patch apply, and read-only git
//! status/diff.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

mod git;

pub use git::{
    git_diff, git_status, GitDiffOpts, GitDiffPage, GitStatusEntry, GitStatusOpts, GitStatusPage,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use thiserror::Error;
use walkdir::WalkDir;

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

/// Filesystem errors.
#[derive(Debug, Error)]
pub enum FsError {
    #[error("io error at {path:?}: {source}")]
    Io {
        path: Option<PathBuf>,
        source: std::io::Error,
    },
    #[error("path escapes workspace: {0}")]
    EscapesWorkspace(PathBuf),
    #[error("path not found: {0}")]
    NotFound(PathBuf),
    #[error("expected hash mismatch for {path}: expected {expected}, got {actual}")]
    HashMismatch {
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("invalid relative path: {0}")]
    InvalidPath(String),
    #[error("not a file: {0}")]
    NotAFile(PathBuf),
    #[error("not a directory: {0}")]
    NotADirectory(PathBuf),
    #[error("entry limit exceeded")]
    EntryLimit,
    #[error("file too large")]
    TooLarge,
}

/// Result alias.
pub type FsResult<T> = Result<T, FsError>;

/// Access boundary for restricted modes.
#[derive(Debug, Clone)]
pub struct WorkspaceRoot {
    root: PathBuf,
    /// When false, paths outside root are rejected.
    enforce: bool,
}

impl WorkspaceRoot {
    /// Create a workspace root. `enforce=false` is Full Access style.
    ///
    /// # Errors
    ///
    /// This constructor currently accepts both existing and not-yet-created roots;
    /// the result type preserves compatibility with fallible workspace setup.
    pub fn new(root: impl Into<PathBuf>, enforce: bool) -> FsResult<Self> {
        let root = root.into();
        let canon = dunce_canonicalize(&root).unwrap_or(root);
        Ok(Self {
            root: canon,
            enforce,
        })
    }

    /// Resolve a relative (or absolute when not enforcing) path safely.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid paths, paths that escape an enforced workspace,
    /// or paths whose existing ancestors cannot be canonicalized.
    pub fn resolve(&self, rel: impl AsRef<Path>) -> FsResult<PathBuf> {
        let rel = rel.as_ref();
        if rel.as_os_str().is_empty() {
            return Ok(self.root.clone());
        }
        // Reject null bytes / obvious weirdness.
        if rel.to_string_lossy().contains('\0') {
            return Err(FsError::InvalidPath(rel.display().to_string()));
        }

        let candidate = if rel.is_absolute() {
            rel.to_path_buf()
        } else {
            // Normalize `..` without following symlinks first.
            let mut out = self.root.clone();
            for c in rel.components() {
                match c {
                    Component::ParentDir => {
                        if !out.pop() {
                            return Err(FsError::EscapesWorkspace(rel.to_path_buf()));
                        }
                    }
                    Component::Normal(s) => out.push(s),
                    Component::CurDir => {}
                    Component::RootDir | Component::Prefix(_) => {
                        return Err(FsError::InvalidPath(rel.display().to_string()));
                    }
                }
            }
            out
        };

        let resolved = if candidate.exists() {
            dunce_canonicalize(&candidate).map_err(|source| FsError::Io {
                path: Some(candidate.clone()),
                source,
            })?
        } else {
            // For create paths: walk up to an existing ancestor, canonicalize it,
            // then re-join the relative suffix (allows nested creates).
            let mut suffix = Vec::new();
            let mut cursor = candidate.as_path();
            while !cursor.exists() {
                let name = cursor
                    .file_name()
                    .ok_or_else(|| FsError::InvalidPath(candidate.display().to_string()))?;
                suffix.push(name.to_os_string());
                cursor = cursor
                    .parent()
                    .ok_or_else(|| FsError::InvalidPath(candidate.display().to_string()))?;
                if self.enforce && !cursor.starts_with(&self.root) && cursor != self.root {
                    // still building; continue until root
                }
                if suffix.len() > 64 {
                    return Err(FsError::InvalidPath(candidate.display().to_string()));
                }
            }
            let mut base = dunce_canonicalize(cursor).map_err(|source| FsError::Io {
                path: Some(cursor.to_path_buf()),
                source,
            })?;
            for part in suffix.into_iter().rev() {
                base.push(part);
            }
            base
        };

        if self.enforce && !resolved.starts_with(&self.root) {
            return Err(FsError::EscapesWorkspace(resolved));
        }
        Ok(resolved)
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

fn dunce_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
    let c = fs::canonicalize(path)?;
    // Strip Windows \\?\ prefix for stable comparisons.
    let s = c.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        Ok(PathBuf::from(stripped))
    } else {
        Ok(c)
    }
}

/// Directory entry metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: String,
    pub path: String,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: Option<u64>,
}

/// File stat.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FileStat {
    pub path: String,
    pub is_dir: bool,
    pub is_file: bool,
    pub is_symlink: bool,
    pub size: u64,
    pub sha256: Option<String>,
}

/// One page of directory listing results with a stable name-ordered cursor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirListPage {
    pub entries: Vec<DirEntryInfo>,
    pub next_cursor: Option<String>,
    pub truncated: bool,
    /// Total entries considered after sorting (not necessarily returned).
    pub total_matched: usize,
}

const MAX_NAME_CHARS: usize = 512;
const MAX_PATH_CHARS: usize = 4096;

fn encode_list_cursor(name: &str) -> String {
    // Cursor is the exclusive lower bound name (UTF-8, name-ordered).
    format!("name:{name}")
}

fn decode_list_cursor(cursor: Option<&str>) -> Option<String> {
    let raw = cursor?.trim();
    if raw.is_empty() {
        return None;
    }
    raw.strip_prefix("name:")
        .map(str::to_owned)
        .or_else(|| Some(raw.to_owned()))
}

fn entry_within_budgets(entry: &DirEntryInfo) -> bool {
    entry.name.chars().count() <= MAX_NAME_CHARS && entry.path.chars().count() <= MAX_PATH_CHARS
}

/// List directory (non-recursive by default).
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or read, is not a directory,
/// or when the requested entry limit is reached (legacy fail-closed behavior).
pub fn list_dir(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    recursive: bool,
    max_entries: usize,
) -> FsResult<Vec<DirEntryInfo>> {
    let page = list_dir_page(ws, rel, recursive, max_entries, None)?;
    if page.truncated {
        return Err(FsError::EntryLimit);
    }
    Ok(page.entries)
}

/// Cursor-paginated directory listing. Entries are sorted by name; `cursor` is an
/// exclusive lower-bound on that name. Name/path character budgets drop oversized
/// entries rather than allocating unbounded JSON.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or read, or is not a directory.
pub fn list_dir_page(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    recursive: bool,
    max_entries: usize,
    cursor: Option<&str>,
) -> FsResult<DirListPage> {
    let path = ws.resolve(rel)?;
    if !path.exists() {
        return Err(FsError::NotFound(path));
    }
    if !path.is_dir() {
        return Err(FsError::NotADirectory(path));
    }
    let after = decode_list_cursor(cursor);
    // Server-side ceiling independent of caller-supplied max_entries.
    const MAX_PAGE_ENTRIES: usize = 500;
    let limit = max_entries.clamp(1, MAX_PAGE_ENTRIES);
    // Hard scan budget prevents unbounded WalkDir collection before paging.
    let scan_budget = limit.saturating_mul(8).max(limit).min(4_000);

    let mut collected = Vec::new();
    if recursive {
        for entry in WalkDir::new(&path).min_depth(1) {
            if collected.len() >= scan_budget {
                break;
            }
            let entry = entry.map_err(|e| FsError::Io {
                path: Some(path.clone()),
                source: std::io::Error::other(e.to_string()),
            })?;
            let meta = entry.metadata().ok();
            let info = DirEntryInfo {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path().to_string_lossy().into_owned(),
                is_dir: entry.file_type().is_dir(),
                is_symlink: entry.file_type().is_symlink(),
                size: meta.and_then(|m| if m.is_file() { Some(m.len()) } else { None }),
            };
            if entry_within_budgets(&info) {
                collected.push(info);
            }
        }
    } else {
        let rd = fs::read_dir(&path).map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
        for entry in rd {
            if collected.len() >= scan_budget {
                break;
            }
            let entry = entry.map_err(|source| FsError::Io {
                path: Some(path.clone()),
                source,
            })?;
            let ft = entry.file_type().map_err(|source| FsError::Io {
                path: Some(entry.path()),
                source,
            })?;
            let meta = entry.metadata().ok();
            let info = DirEntryInfo {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path().to_string_lossy().into_owned(),
                is_dir: ft.is_dir(),
                is_symlink: ft.is_symlink(),
                size: meta.and_then(|m| if m.is_file() { Some(m.len()) } else { None }),
            };
            if entry_within_budgets(&info) {
                collected.push(info);
            }
        }
    }
    collected.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));
    if let Some(after_name) = after.as_deref() {
        collected.retain(|e| e.name.as_str() > after_name);
    }
    let total_matched = collected.len();
    let truncated = total_matched > limit;
    if truncated {
        collected.truncate(limit);
    }
    let next_cursor = if truncated {
        collected.last().map(|e| encode_list_cursor(&e.name))
    } else {
        None
    };
    Ok(DirListPage {
        entries: collected,
        next_cursor,
        truncated,
        total_matched,
    })
}

/// Stat a path; optionally compute SHA-256 for files.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved, inspected, or read for
/// hashing.
pub fn stat_path(ws: &WorkspaceRoot, rel: impl AsRef<Path>, hash: bool) -> FsResult<FileStat> {
    let path = ws.resolve(rel)?;
    let meta = fs::symlink_metadata(&path).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    let is_symlink = meta.file_type().is_symlink();
    let is_dir = meta.is_dir();
    let is_file = meta.is_file();
    let size = meta.len();
    let sha256 = if hash && is_file {
        Some(hash_file(&path)?)
    } else {
        None
    };
    Ok(FileStat {
        path: path.to_string_lossy().into_owned(),
        is_dir,
        is_file,
        is_symlink,
        size,
        sha256,
    })
}

/// Read file bytes with size cap.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or read, does not identify a
/// file, or exceeds `max_bytes`.
pub fn read_file(ws: &WorkspaceRoot, rel: impl AsRef<Path>, max_bytes: u64) -> FsResult<Vec<u8>> {
    let (bytes, _total, truncated) = read_file_range(ws, rel, 0, max_bytes)?;
    if truncated {
        // Preserve historical whole-file semantics: refuse rather than silently clip.
        return Err(FsError::TooLarge);
    }
    Ok(bytes)
}

/// Read a bounded byte range from a file.
///
/// Returns `(bytes, total_size, truncated)` where `truncated` is true when more
/// bytes remain after the returned range. Never loads the whole file when only a
/// window is requested.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or read, or is not a file.
pub fn read_file_range(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    offset: u64,
    max_bytes: u64,
) -> FsResult<(Vec<u8>, u64, bool)> {
    use std::io::{Read, Seek, SeekFrom};

    let path = ws.resolve(rel)?;
    let meta = fs::metadata(&path).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    if !meta.is_file() {
        return Err(FsError::NotAFile(path));
    }
    let total = meta.len();
    if offset >= total {
        return Ok((Vec::new(), total, false));
    }
    let remaining = total - offset;
    let take = remaining.min(max_bytes);
    let mut file = fs::File::open(&path).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
    let mut buf = vec![0_u8; usize::try_from(take).unwrap_or(usize::MAX)];
    let mut read_total = 0_usize;
    while read_total < buf.len() {
        match file.read(&mut buf[read_total..]) {
            Ok(0) => break,
            Ok(n) => read_total += n,
            Err(source) => {
                return Err(FsError::Io {
                    path: Some(path),
                    source,
                });
            }
        }
    }
    buf.truncate(read_total);
    let truncated = offset.saturating_add(read_total as u64) < total;
    Ok((buf, total, truncated))
}

/// Write file atomically (exclusive random temp + rename) when possible.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or its parent, temporary
/// file, or final destination cannot be written.
pub fn write_file(ws: &WorkspaceRoot, rel: impl AsRef<Path>, data: &[u8]) -> FsResult<()> {
    let path = ws.resolve(rel)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| FsError::Io {
            path: Some(parent.to_path_buf()),
            source,
        })?;
        // Re-validate parent identity after create_dir_all (replacement race).
        if ws.enforce {
            let parent_canon = dunce_canonicalize(parent).map_err(|source| FsError::Io {
                path: Some(parent.to_path_buf()),
                source,
            })?;
            if !parent_canon.starts_with(ws.root()) {
                return Err(FsError::EscapesWorkspace(parent_canon));
            }
        }
    }
    // Exclusive randomized temp name resists predictable *.ownmesh-tmp swap races.
    let token = {
        let mut hasher = Sha256::new();
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos().to_le_bytes())
                .unwrap_or([0; 16]),
        );
        hasher.update((data.len() as u64).to_le_bytes());
        hex::encode(hasher.finalize())
    };
    let tmp = match path.parent() {
        Some(parent) => parent.join(format!(
            ".ownmesh-{}.tmp",
            token.get(..16).unwrap_or(token.as_str())
        )),
        None => path.with_extension(format!(
            "ownmesh-{}.tmp",
            token.get(..16).unwrap_or(token.as_str())
        )),
    };
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)
            .map_err(|source| FsError::Io {
                path: Some(tmp.clone()),
                source,
            })?;
        f.write_all(data).map_err(|source| FsError::Io {
            path: Some(tmp.clone()),
            source,
        })?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, &path).map_err(|source| {
        let _ = fs::remove_file(&tmp);
        FsError::Io {
            path: Some(path.clone()),
            source,
        }
    })?;
    // Final identity check after rename for restricted workspaces.
    if ws.enforce {
        if let Ok(final_canon) = dunce_canonicalize(&path) {
            if !final_canon.starts_with(ws.root()) {
                let _ = fs::remove_file(&path);
                return Err(FsError::EscapesWorkspace(final_canon));
            }
        }
    }
    Ok(())
}

/// Delete file or empty directory; `recursive` removes trees.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved, does not exist, or cannot be
/// removed.
pub fn delete_path(ws: &WorkspaceRoot, rel: impl AsRef<Path>, recursive: bool) -> FsResult<()> {
    let path = ws.resolve(rel)?;
    if !path.exists() {
        return Err(FsError::NotFound(path));
    }
    if path.is_dir() {
        if recursive {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_dir(&path)
        }
    } else {
        fs::remove_file(&path)
    }
    .map_err(|source| FsError::Io {
        path: Some(path),
        source,
    })
}

/// Apply whole-file patch when `expected_sha256` matches (if provided).
///
/// # Errors
///
/// Returns an error when the path cannot be resolved, the current file cannot be
/// hashed, the expected hash differs, or the replacement cannot be written.
pub fn apply_patch(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    new_content: &[u8],
    expected_sha256: Option<&str>,
) -> FsResult<String> {
    let path = ws.resolve(rel.as_ref())?;
    if let Some(expected) = expected_sha256 {
        if path.exists() {
            let actual = hash_file(&path)?;
            if actual != expected {
                return Err(FsError::HashMismatch {
                    path,
                    expected: expected.to_string(),
                    actual,
                });
            }
        } else if expected != empty_hash() {
            return Err(FsError::HashMismatch {
                path,
                expected: expected.to_string(),
                actual: empty_hash().to_string(),
            });
        }
    }
    write_file(ws, rel, new_content)?;
    Ok(hash_bytes(new_content))
}

fn hash_file(path: &Path) -> FsResult<String> {
    let mut f = fs::File::open(path).map_err(|source| FsError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = f.read(&mut buf).map_err(|source| FsError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn hash_bytes(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn empty_hash() -> &'static str {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

/// Detect common sensitive path basenames (UX hint only — never a hard deny).
#[must_use]
pub fn looks_sensitive(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(
        name.as_str(),
        ".env"
            | ".env.local"
            | "id_rsa"
            | "id_ed25519"
            | "credentials"
            | "credentials.json"
            | "secret"
            | "secrets.yaml"
            | "secrets.yml"
    ) || name == ".pem"
        || name == ".key"
        || Path::new(&name)
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("key"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn rejects_escape_when_enforced() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        fs::write(dir.path().join("a.txt"), b"hi").unwrap();
        let err = ws.resolve("../outside.txt").unwrap_err();
        assert!(matches!(err, FsError::EscapesWorkspace(_)));
    }

    #[test]
    fn allows_escape_when_not_enforced() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
        // parent of temp dir exists
        let resolved = ws.resolve("..").unwrap();
        assert!(resolved.exists());
    }

    #[test]
    fn write_read_patch_roundtrip() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        write_file(&ws, "foo.txt", b"v1").unwrap();
        let s = stat_path(&ws, "foo.txt", true).unwrap();
        assert_eq!(s.size, 2);
        let h = s.sha256.unwrap();
        let new_h = apply_patch(&ws, "foo.txt", b"v2", Some(&h)).unwrap();
        assert_ne!(h, new_h);
        let body = read_file(&ws, "foo.txt", 100).unwrap();
        assert_eq!(body, b"v2");
        // mismatch
        let err = apply_patch(&ws, "foo.txt", b"v3", Some(&h)).unwrap_err();
        assert!(matches!(err, FsError::HashMismatch { .. }));
    }

    #[test]
    fn list_and_delete() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        write_file(&ws, "a/b.txt", b"x").unwrap();
        let entries = list_dir(&ws, "", true, 100).unwrap();
        assert!(entries.iter().any(|e| e.name == "b.txt"));
        delete_path(&ws, "a", true).unwrap();
        assert!(list_dir(&ws, "", true, 100).unwrap().is_empty());
    }

    #[test]
    fn sensitive_hint() {
        assert!(looks_sensitive(Path::new("/tmp/.env")));
        assert!(looks_sensitive(Path::new("/tmp/server.key")));
        assert!(looks_sensitive(Path::new("/tmp/.key")));
        assert!(looks_sensitive(Path::new("/tmp/.pem")));
        assert!(!looks_sensitive(Path::new("/tmp/readme.md")));
    }
}
