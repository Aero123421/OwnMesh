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

mod custody;
mod git;

pub use git::{
    git_diff, git_head_oid, git_status, GitDiffOpts, GitDiffPage, GitStatusEntry, GitStatusOpts,
    GitStatusPage,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
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
    #[error("symlink or reparse point not permitted in restricted workspace: {0}")]
    SymlinkOrReparse(PathBuf),
    #[error("cross-boundary hardlink not permitted in restricted workspace: {0}")]
    CrossBoundaryHardlink(PathBuf),
    #[error("cross-mount path not permitted in restricted workspace: {0}")]
    CrossMount(PathBuf),
    #[error("entry limit exceeded")]
    EntryLimit,
    #[error("file too large")]
    TooLarge,
    #[error("unified diff apply failed: {0}")]
    Patch(String),
}

/// Result alias.
pub type FsResult<T> = Result<T, FsError>;

/// Access boundary for restricted modes.
#[derive(Debug, Clone)]
pub struct WorkspaceRoot {
    root: PathBuf,
    /// When true, restricted-mode handle-rooted custody is enforced.
    pub(crate) enforce: bool,
}

/// A regular file opened and verified beneath a [`WorkspaceRoot`].
///
/// The retained handle, rather than its original pathname, is the authority
/// for subsequent reads.  In restricted workspaces it has passed the full
/// no-follow, final-handle, mount, and hardlink custody checks.
pub struct WorkspaceReadHandle {
    file: File,
    final_path: PathBuf,
    size_bytes: u64,
}

impl WorkspaceReadHandle {
    /// Consume this custody proof and return the already verified handle.
    #[must_use]
    pub fn into_file(self) -> File {
        self.file
    }

    /// Final path observed from the retained operating-system handle.
    #[must_use]
    pub fn final_path(&self) -> &Path {
        &self.final_path
    }

    /// Size observed from the retained operating-system handle.
    #[must_use]
    pub const fn size_bytes(&self) -> u64 {
        self.size_bytes
    }
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

    /// Open a regular file once and retain the verified OS handle for reading.
    ///
    /// In restricted mode callers must use this instead of `resolve` followed
    /// by `File::open`, which would reintroduce a pathname TOCTOU boundary.
    pub fn open_verified_read(&self, rel: impl AsRef<Path>) -> FsResult<WorkspaceReadHandle> {
        let (file, final_path) = if self.enforce {
            custody::open_regular_file_read(self, rel.as_ref())?
        } else {
            let path = self.resolve(rel)?;
            let file = File::open(&path).map_err(|source| FsError::Io {
                path: Some(path.clone()),
                source,
            })?;
            (file, path)
        };
        let meta = file.metadata().map_err(|source| FsError::Io {
            path: Some(final_path.clone()),
            source,
        })?;
        if !meta.is_file() {
            return Err(FsError::NotAFile(final_path));
        }
        Ok(WorkspaceReadHandle {
            file,
            final_path,
            size_bytes: meta.len(),
        })
    }

    /// Open a retained handle for an authenticated immutable transfer artifact.
    ///
    /// This is deliberately not a general-purpose read API: transfer
    /// publication uses a no-replace hardlink, so the normal anti-alias policy
    /// would reject it. Callers must still verify the immutable transfer plan
    /// against this exact retained handle before returning any bytes.
    pub fn open_verified_transfer_artifact_read(
        &self,
        rel: impl AsRef<Path>,
    ) -> FsResult<WorkspaceReadHandle> {
        let (file, final_path) = if self.enforce {
            custody::open_regular_file_read_allow_hardlinks(self, rel.as_ref())?
        } else {
            let path = self.resolve(rel)?;
            let file = File::open(&path).map_err(|source| FsError::Io {
                path: Some(path.clone()),
                source,
            })?;
            (file, path)
        };
        let meta = file.metadata().map_err(|source| FsError::Io {
            path: Some(final_path.clone()),
            source,
        })?;
        if !meta.is_file() {
            return Err(FsError::NotAFile(final_path));
        }
        Ok(WorkspaceReadHandle {
            file,
            final_path,
            size_bytes: meta.len(),
        })
    }

    /// Publish an already verified private transfer file into this restricted
    /// workspace without replacing an existing destination. The destination is
    /// resolved relative to a retained no-follow parent handle, not reopened by
    /// pathname after custody validation.
    pub fn publish_retained_transfer_file_no_replace(
        &self,
        rel: impl AsRef<Path>,
        source: &File,
    ) -> FsResult<()> {
        if self.enforce {
            return custody::publish_retained_file_no_replace(self, rel.as_ref(), source);
        }
        let destination = self.resolve(rel)?;
        let source_path = custody::final_path_of_handle(source).map_err(|source| FsError::Io {
            path: Some(destination.clone()),
            source,
        })?;
        fs::hard_link(source_path, &destination).map_err(|source| FsError::Io {
            path: Some(destination),
            source,
        })
    }

    #[must_use]
    pub fn root(&self) -> &Path {
        &self.root
    }
}

pub(crate) fn dunce_canonicalize(path: &Path) -> std::io::Result<PathBuf> {
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

/// Opaque cursor binding the full sort tuple `(name, path)` plus a version tag.
/// Format: `v1:<base64url(name)>.<base64url(path)>` so duplicate names across
/// directories do not skip later entries when paging recursively.
fn encode_list_cursor(name: &str, path: &str) -> String {
    format!(
        "v1:{}.{}",
        base64url_nopad(name.as_bytes()),
        base64url_nopad(path.as_bytes())
    )
}

fn decode_list_cursor(cursor: Option<&str>) -> Option<(String, String)> {
    let raw = cursor?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Some(rest) = raw.strip_prefix("v1:") {
        let (name_b64, path_b64) = rest.split_once('.')?;
        let name = String::from_utf8(base64url_decode_nopad(name_b64)?).ok()?;
        let path = String::from_utf8(base64url_decode_nopad(path_b64)?).ok()?;
        return Some((name, path));
    }
    // Legacy name-only cursors: treat path as empty so comparison still advances
    // past the name, accepting that duplicate names may have been skipped before.
    if let Some(name) = raw.strip_prefix("name:") {
        return Some((name.to_owned(), String::new()));
    }
    Some((raw.to_owned(), String::new()))
}

fn base64url_nopad(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    let mut i = 0;
    while i < bytes.len() {
        let b0 = bytes[i];
        let b1 = if i + 1 < bytes.len() { bytes[i + 1] } else { 0 };
        let b2 = if i + 2 < bytes.len() { bytes[i + 2] } else { 0 };
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if i + 1 < bytes.len() {
            out.push(TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if i + 2 < bytes.len() {
            out.push(TABLE[(b2 & 0x3f) as usize] as char);
        }
        i += 3;
    }
    out
}

fn base64url_decode_nopad(input: &str) -> Option<Vec<u8>> {
    fn sextet(byte: u8) -> Option<u8> {
        match byte {
            b'A'..=b'Z' => Some(byte - b'A'),
            b'a'..=b'z' => Some(byte - b'a' + 26),
            b'0'..=b'9' => Some(byte - b'0' + 52),
            b'-' => Some(62),
            b'_' => Some(63),
            _ => None,
        }
    }
    let bytes = input.as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(bytes.len().div_ceil(4) * 3);
    let mut offset = 0;
    while offset < bytes.len() {
        let remaining = bytes.len() - offset;
        if remaining == 1 {
            return None;
        }
        let s0 = sextet(bytes[offset])?;
        let s1 = sextet(bytes[offset + 1])?;
        out.push((s0 << 2) | (s1 >> 4));
        if remaining == 2 {
            break;
        }
        let s2 = sextet(bytes[offset + 2])?;
        out.push(((s1 & 0x0f) << 4) | (s2 >> 2));
        if remaining == 3 {
            break;
        }
        let s3 = sextet(bytes[offset + 3])?;
        out.push(((s2 & 0x03) << 6) | s3);
        offset += 4;
    }
    Some(out)
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

/// Cursor-paginated directory listing. Entries are sorted by `(name, path)`;
/// `cursor` is an exclusive lower-bound on that tuple. Name/path character
/// budgets drop oversized entries rather than allocating unbounded JSON.
///
/// Small directories stay in-memory. Directories that exceed the memory snapshot
/// bound spill into a private durable spool with quota/TTL so Full Access can
/// still retrieve every entry via chunks without unbounded RSS. Never issues a
/// continuation cursor from an incomplete unsorted window.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved or read, is not a directory,
/// or when the hard spool entry/byte quota is exceeded.
pub fn list_dir_page(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    recursive: bool,
    max_entries: usize,
    cursor: Option<&str>,
) -> FsResult<DirListPage> {
    // Restricted mode holds the directory handle across enumeration so a
    // rename-to-symlink replacement of the checked path cannot retarget listing.
    let (held_dir, path) = if ws.enforce {
        let (dir, path) = custody::open_dir_enforced(ws, rel.as_ref())?;
        (Some(dir), path)
    } else {
        let path = ws.resolve(rel)?;
        if !path.exists() {
            return Err(FsError::NotFound(path));
        }
        if !path.is_dir() {
            return Err(FsError::NotADirectory(path));
        }
        (None, path)
    };
    // Server-side ceiling independent of caller-supplied max_entries.
    const MAX_PAGE_ENTRIES: usize = 500;
    /// UTF-8 JSON page budget so Agent/DeviceRoom envelopes never lose the
    /// directory cursor to a generic truncation stand-in.
    const MAX_PAGE_JSON_BYTES: usize = 96_000;
    /// In-memory snapshot bound. Above this, entries spill to a durable spool.
    const MAX_DIR_MEMORY_SNAPSHOT: usize = 25_000;
    /// Hard spool entry quota (disk-backed, still bounded).
    const MAX_DIR_SPOOL_ENTRIES: usize = 250_000;
    let limit = max_entries.clamp(1, MAX_PAGE_ENTRIES);

    // Resume from a durable spool cursor without re-walking the tree.
    // Cursor is bound to this request's canonical root + recursive flag so a
    // workspace-A spool cannot be substituted into a workspace-B listing.
    if let Some((spool_id, after)) = decode_v2_list_cursor(cursor) {
        let snapshot = load_dir_spool(&spool_id, &path, recursive)?;
        return Ok(page_sorted_snapshot(
            snapshot,
            after.as_ref(),
            limit,
            MAX_PAGE_JSON_BYTES,
            Some(spool_id.as_str()),
        ));
    }

    let after = decode_list_cursor(cursor);

    // Phase 1: walk. Stay in RAM until memory bound, then spill to durable spool.
    // Byte budget is checked before every append (never only after full serialize).
    let mut snapshot: Vec<DirEntryInfo> = Vec::new();
    let mut spool_entries: Vec<DirEntryInfo> = Vec::new();
    let mut spilled = false;
    let mut aggregate_bytes: usize = 0;

    let mut push_entry = |info: DirEntryInfo| -> FsResult<()> {
        if !entry_within_budgets(&info) {
            return Ok(());
        }
        // Conservative JSON/object overhead per entry (keys + punctuation + bools).
        const ENTRY_JSON_OVERHEAD: usize = 96;
        let entry_bytes = info
            .name
            .len()
            .saturating_add(info.path.len())
            .saturating_add(ENTRY_JSON_OVERHEAD);
        let next_aggregate = aggregate_bytes.saturating_add(entry_bytes);
        if next_aggregate > MAX_DIR_SPOOL_FILE_BYTES {
            return Err(FsError::EntryLimit);
        }
        if !spilled {
            if snapshot.len() >= MAX_DIR_MEMORY_SNAPSHOT {
                // Spill existing snapshot + continue on disk-backed vector with
                // a much higher hard cap so large valid trees remain retrievable.
                spool_entries = std::mem::take(&mut snapshot);
                spilled = true;
            } else {
                snapshot.push(info);
                aggregate_bytes = next_aggregate;
                return Ok(());
            }
        }
        if spool_entries.len() >= MAX_DIR_SPOOL_ENTRIES {
            return Err(FsError::EntryLimit);
        }
        spool_entries.push(info);
        aggregate_bytes = next_aggregate;
        Ok(())
    };

    if let Some(dir) = held_dir.as_ref() {
        // Handle-held walk: never drop the validated descriptor before side effect.
        custody::walk_dir_held(ws, dir, &path, recursive, &mut push_entry)?;
    } else if recursive {
        for entry in WalkDir::new(&path).min_depth(1) {
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
            push_entry(info)?;
        }
    } else {
        let rd = fs::read_dir(&path).map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
        for entry in rd {
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
            push_entry(info)?;
        }
    }
    // Explicitly keep the handle alive through the walk above.
    drop(held_dir);

    let mut snapshot = if spilled { spool_entries } else { snapshot };

    // Phase 2: stable total order (required; filesystem order is not lexical).
    snapshot.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.path.cmp(&b.path)));

    let spool_id = if spilled {
        Some(persist_dir_spool(&path, recursive, &snapshot)?)
    } else {
        None
    };

    Ok(page_sorted_snapshot(
        snapshot,
        after.as_ref(),
        limit,
        MAX_PAGE_JSON_BYTES,
        spool_id.as_deref(),
    ))
}

fn page_sorted_snapshot(
    snapshot: Vec<DirEntryInfo>,
    after: Option<&(String, String)>,
    limit: usize,
    max_page_json_bytes: usize,
    spool_id: Option<&str>,
) -> DirListPage {
    // Exclusive cursor lower-bound without a second full clone when possible.
    let start_idx = match after {
        None => 0,
        Some((after_name, after_path)) => snapshot
            .iter()
            .position(|info| {
                info.name.as_str() > after_name.as_str()
                    || (info.name.as_str() == after_name.as_str()
                        && info.path.as_str() > after_path.as_str())
            })
            .unwrap_or(snapshot.len()),
    };
    let total_matched = snapshot.len().saturating_sub(start_idx);

    let mut page_entries: Vec<DirEntryInfo> = Vec::new();
    let mut page_bytes: usize = 2; // []
    let mut hit_entry_cap = false;
    let mut hit_byte_cap = false;
    for entry in snapshot.into_iter().skip(start_idx) {
        if page_entries.len() >= limit {
            hit_entry_cap = true;
            break;
        }
        let entry_json_len = match serde_json::to_vec(&entry) {
            Ok(v) => v.len(),
            Err(_) => entry
                .name
                .len()
                .saturating_add(entry.path.len())
                .saturating_add(64),
        };
        let comma = usize::from(!page_entries.is_empty());
        let next_bytes = page_bytes
            .saturating_add(comma)
            .saturating_add(entry_json_len);
        if !page_entries.is_empty() && next_bytes > max_page_json_bytes {
            hit_byte_cap = true;
            break;
        }
        page_bytes = if page_entries.is_empty() {
            entry_json_len.saturating_add(2)
        } else {
            next_bytes
        };
        page_entries.push(entry);
    }
    if !hit_byte_cap && total_matched > page_entries.len() {
        hit_entry_cap = true;
    }
    let truncated = hit_entry_cap || hit_byte_cap || total_matched > page_entries.len();
    let next_cursor = if truncated {
        page_entries.last().map(|e| match spool_id {
            Some(id) => encode_v2_list_cursor(id, &e.name, &e.path),
            None => encode_list_cursor(&e.name, &e.path),
        })
    } else {
        None
    };
    DirListPage {
        entries: page_entries,
        next_cursor,
        truncated,
        total_matched,
    }
}

/// Durable directory list spool (sorted snapshot) for large trees.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DirListSpool {
    version: u32,
    root_key: String,
    recursive: bool,
    created_unix: u64,
    entry_count: usize,
    content_sha256: String,
    entries: Vec<DirEntryInfo>,
}

const DIR_SPOOL_VERSION: u32 = 1;
const DIR_SPOOL_TTL_SECS: u64 = 15 * 60;
const MAX_DIR_SPOOLS: usize = 32;
const MAX_DIR_SPOOL_FILE_BYTES: usize = 64 * 1024 * 1024;

fn dir_spool_dir() -> PathBuf {
    let base = std::env::var_os("OWNMESH_STATE_DIR")
        .map(PathBuf::from)
        .or_else(|| {
            #[cfg(windows)]
            {
                std::env::var_os("LOCALAPPDATA")
                    .map(|h| PathBuf::from(h).join("OwnMesh").join("state"))
            }
            #[cfg(not(windows))]
            {
                std::env::var_os("XDG_STATE_HOME")
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var_os("HOME")
                            .map(|h| PathBuf::from(h).join(".local/state/OwnMesh"))
                    })
                    .map(|h| h.join("state"))
            }
        })
        .unwrap_or_else(|| {
            let mut p = std::env::temp_dir();
            p.push(format!(
                "ownmesh-{}",
                std::env::var("USERNAME")
                    .or_else(|_| std::env::var("USER"))
                    .unwrap_or_else(|_| format!("uid-{}", std::process::id()))
            ));
            p.push("state");
            p
        });
    base.join("dir-list-spool")
}

fn ensure_dir_spool_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::metadata(dir)?;
        let mut perms = meta.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(dir, perms)?;
    }
    Ok(())
}

fn cleanup_dir_spools(dir: &Path) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut files: Vec<(PathBuf, u64, u64)> = Vec::new();
    for ent in rd.flatten() {
        let path = ent.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() || !meta.is_file() {
            let _ = fs::remove_file(&path);
            continue;
        }
        let modified = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        if now.saturating_sub(modified) > DIR_SPOOL_TTL_SECS {
            let _ = fs::remove_file(&path);
            continue;
        }
        files.push((path, modified, meta.len()));
    }
    // Keep newest MAX_DIR_SPOOLS; drop oldest beyond quota.
    files.sort_by(|a, b| b.1.cmp(&a.1));
    for (path, _, _) in files.into_iter().skip(MAX_DIR_SPOOLS) {
        let _ = fs::remove_file(path);
    }
}

fn persist_dir_spool(root: &Path, recursive: bool, entries: &[DirEntryInfo]) -> FsResult<String> {
    let dir = dir_spool_dir();
    let _ = ensure_dir_spool_dir(&dir);
    cleanup_dir_spools(&dir);

    let mut hasher = Sha256::new();
    hasher.update(root.to_string_lossy().as_bytes());
    hasher.update([u8::from(recursive)]);
    for e in entries {
        hasher.update(e.name.as_bytes());
        hasher.update([0]);
        hasher.update(e.path.as_bytes());
        hasher.update([0]);
    }
    let content_sha256 = hex::encode(hasher.finalize());
    let created_unix = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut id_hasher = Sha256::new();
    id_hasher.update(content_sha256.as_bytes());
    id_hasher.update(created_unix.to_le_bytes());
    id_hasher.update(std::process::id().to_le_bytes());
    let spool_id = hex::encode(id_hasher.finalize());
    let spool_id = spool_id[..32].to_owned();

    let spool = DirListSpool {
        version: DIR_SPOOL_VERSION,
        root_key: root.to_string_lossy().into_owned(),
        recursive,
        created_unix,
        entry_count: entries.len(),
        content_sha256: content_sha256.clone(),
        entries: entries.to_vec(),
    };
    let encoded = serde_json::to_vec(&spool).map_err(|e| FsError::Io {
        path: Some(dir.clone()),
        source: std::io::Error::other(e.to_string()),
    })?;
    if encoded.len() > MAX_DIR_SPOOL_FILE_BYTES {
        return Err(FsError::EntryLimit);
    }
    let path = dir.join(format!("{spool_id}.json"));
    let tmp = dir.join(format!("{spool_id}.json.tmp"));
    fs::write(&tmp, &encoded).map_err(|source| FsError::Io {
        path: Some(tmp.clone()),
        source,
    })?;
    fs::rename(&tmp, &path).map_err(|source| FsError::Io {
        path: Some(path),
        source,
    })?;
    Ok(spool_id)
}

fn load_dir_spool(
    spool_id: &str,
    expected_root: &Path,
    expected_recursive: bool,
) -> FsResult<Vec<DirEntryInfo>> {
    if spool_id.len() != 32 || !spool_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(FsError::InvalidPath(
            "invalid directory list spool id".to_owned(),
        ));
    }
    let path = dir_spool_dir().join(format!("{spool_id}.json"));
    let meta = fs::symlink_metadata(&path).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        let _ = fs::remove_file(&path);
        return Err(FsError::NotFound(path));
    }
    if usize::try_from(meta.len()).map_or(true, |n| n > MAX_DIR_SPOOL_FILE_BYTES) {
        let _ = fs::remove_file(&path);
        return Err(FsError::EntryLimit);
    }
    let bytes = fs::read(&path).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    let spool: DirListSpool = serde_json::from_slice(&bytes).map_err(|e| FsError::Io {
        path: Some(path.clone()),
        source: std::io::Error::other(e.to_string()),
    })?;
    if spool.version != DIR_SPOOL_VERSION {
        let _ = fs::remove_file(&path);
        return Err(FsError::InvalidPath("unsupported dir spool version".into()));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if now.saturating_sub(spool.created_unix) > DIR_SPOOL_TTL_SECS {
        let _ = fs::remove_file(&path);
        return Err(FsError::NotFound(path));
    }
    // Integrity: recompute content hash over entry name/path tuples.
    let mut hasher = Sha256::new();
    hasher.update(spool.root_key.as_bytes());
    hasher.update([u8::from(spool.recursive)]);
    for e in &spool.entries {
        hasher.update(e.name.as_bytes());
        hasher.update([0]);
        hasher.update(e.path.as_bytes());
        hasher.update([0]);
    }
    let recomputed = hex::encode(hasher.finalize());
    if recomputed != spool.content_sha256 || spool.entry_count != spool.entries.len() {
        let _ = fs::remove_file(&path);
        return Err(FsError::InvalidPath("dir spool integrity failure".into()));
    }
    let expected_key = expected_root.to_string_lossy();
    if spool.root_key != expected_key || spool.recursive != expected_recursive {
        return Err(FsError::InvalidPath(
            "directory list cursor does not match request root/recursive identity".into(),
        ));
    }
    Ok(spool.entries)
}

fn encode_v2_list_cursor(spool_id: &str, name: &str, path: &str) -> String {
    format!(
        "v2:{spool_id}.{}.{}",
        base64url_nopad(name.as_bytes()),
        base64url_nopad(path.as_bytes())
    )
}

fn decode_v2_list_cursor(cursor: Option<&str>) -> Option<(String, Option<(String, String)>)> {
    let raw = cursor?.trim();
    let rest = raw.strip_prefix("v2:")?;
    let (spool_id, after_part) = rest.split_once('.')?;
    if spool_id.len() != 32 || !spool_id.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let (name_b64, path_b64) = after_part.split_once('.')?;
    let name = String::from_utf8(base64url_decode_nopad(name_b64)?).ok()?;
    let path = String::from_utf8(base64url_decode_nopad(path_b64)?).ok()?;
    Some((spool_id.to_owned(), Some((name, path))))
}

/// Stat a path; optionally compute SHA-256 for files.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved, inspected, or read for
/// hashing.
pub fn stat_path(ws: &WorkspaceRoot, rel: impl AsRef<Path>, hash: bool) -> FsResult<FileStat> {
    if ws.enforce {
        return custody::stat_enforced(ws, rel.as_ref(), hash);
    }
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

    if ws.enforce {
        let (bytes, total, truncated, _path) =
            custody::read_range_enforced(ws, rel.as_ref(), offset, max_bytes)?;
        return Ok((bytes, total, truncated));
    }

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
    if ws.enforce {
        let _final = custody::write_file_enforced(ws, rel.as_ref(), data)?;
        return Ok(());
    }
    let path = ws.resolve(rel)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| FsError::Io {
            path: Some(parent.to_path_buf()),
            source,
        })?;
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
    Ok(())
}

/// Delete file or empty directory; `recursive` removes trees.
///
/// # Errors
///
/// Returns an error when the path cannot be resolved, does not exist, or cannot be
/// removed.
pub fn delete_path(ws: &WorkspaceRoot, rel: impl AsRef<Path>, recursive: bool) -> FsResult<()> {
    if ws.enforce {
        return custody::delete_enforced(ws, rel.as_ref(), recursive);
    }
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
    if let Some(expected) = expected_sha256 {
        if ws.enforce {
            match custody::open_regular_file_read(ws, rel.as_ref()) {
                Ok((mut file, path)) => {
                    let actual = custody::hash_open_file(&mut file, &path)?;
                    if actual != expected {
                        return Err(FsError::HashMismatch {
                            path,
                            expected: expected.to_string(),
                            actual,
                        });
                    }
                }
                Err(FsError::NotFound(path)) => {
                    if expected != empty_hash() {
                        return Err(FsError::HashMismatch {
                            path,
                            expected: expected.to_string(),
                            actual: empty_hash().to_string(),
                        });
                    }
                }
                Err(err) => return Err(err),
            }
        } else {
            let path = ws.resolve(rel.as_ref())?;
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
    }
    write_file(ws, rel, new_content)?;
    Ok(hash_bytes(new_content))
}

/// Maximum unified-diff text accepted for a single apply (pre-parse ceiling).
pub const MAX_UNIFIED_DIFF_BYTES: usize = 512 * 1024;
/// Maximum target file size that may be patched via unified diff.
pub const MAX_UNIFIED_DIFF_TARGET_BYTES: usize = 2 * 1024 * 1024;
/// Maximum lines in a unified-diff target after apply.
pub const MAX_UNIFIED_DIFF_TARGET_LINES: usize = 200_000;

/// True when `content` looks like a unified diff (not a whole-file body).
#[must_use]
pub fn looks_like_unified_diff(content: &str) -> bool {
    let trimmed = content.trim_start();
    if trimmed.starts_with("diff --git ") || trimmed.starts_with("--- ") {
        return trimmed.lines().any(|l| l.starts_with("@@"));
    }
    false
}

/// Apply a bounded single-file unified diff to `rel`.
///
/// Supports standard `---`/`+++`/`@@` hunks against one text file. Multi-file
/// patches, binary diffs, and rename/copy headers are rejected fail-closed.
/// When `expected_sha256` is set it must match the pre-image file.
///
/// # Errors
///
/// Returns [`FsError::Patch`] / hash / IO errors on mismatch or overflow.
pub fn apply_unified_diff(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    diff_text: &str,
    expected_sha256: Option<&str>,
) -> FsResult<String> {
    if diff_text.len() > MAX_UNIFIED_DIFF_BYTES {
        return Err(FsError::Patch(format!(
            "unified diff exceeds {MAX_UNIFIED_DIFF_BYTES} byte budget"
        )));
    }
    if diff_text.as_bytes().contains(&0) {
        return Err(FsError::Patch(
            "binary/NUL unified diffs are not supported".into(),
        ));
    }

    let hunks = parse_unified_diff_hunks(diff_text)?;
    if hunks.is_empty() {
        return Err(FsError::Patch("unified diff contains no hunks".into()));
    }

    // Load current file (empty pre-image allowed for create-style patches).
    let current = match read_file_text_bounded(ws, rel.as_ref(), MAX_UNIFIED_DIFF_TARGET_BYTES) {
        Ok(text) => text,
        Err(FsError::NotFound(_)) => String::new(),
        Err(e) => return Err(e),
    };
    if let Some(expected) = expected_sha256 {
        let actual = hash_bytes(current.as_bytes());
        if actual != expected {
            let path = ws
                .resolve(rel.as_ref())
                .unwrap_or_else(|_| rel.as_ref().to_path_buf());
            return Err(FsError::HashMismatch {
                path,
                expected: expected.to_string(),
                actual,
            });
        }
    }

    let old_lines: Vec<&str> = split_lines_preserve(&current);
    let new_lines = apply_hunks_to_lines(&old_lines, &hunks)?;
    if new_lines.len() > MAX_UNIFIED_DIFF_TARGET_LINES {
        return Err(FsError::Patch(format!(
            "patched file would exceed {MAX_UNIFIED_DIFF_TARGET_LINES} lines"
        )));
    }
    let mut out = String::new();
    for (i, line) in new_lines.iter().enumerate() {
        if i > 0 {
            out.push('\n');
        }
        out.push_str(line);
    }
    // Preserve a trailing newline when the post-image is non-empty and the
    // final hunk did not explicitly omit it via `\ No newline` (simplified:
    // always end text files with newline when non-empty — matches git apply
    // common case for ChatGPT-authored patches).
    if !out.is_empty() && !out.ends_with('\n') && current.ends_with('\n') {
        out.push('\n');
    }
    if out.len() > MAX_UNIFIED_DIFF_TARGET_BYTES {
        return Err(FsError::Patch(format!(
            "patched file would exceed {MAX_UNIFIED_DIFF_TARGET_BYTES} byte budget"
        )));
    }
    write_file(ws, rel, out.as_bytes())?;
    Ok(hash_bytes(out.as_bytes()))
}

#[derive(Debug, Clone)]
struct DiffHunk {
    /// 1-based old start line (0 means empty file).
    old_start: usize,
    old_count: usize,
    lines: Vec<DiffLine>,
}

#[derive(Debug, Clone)]
enum DiffLine {
    Context(String),
    Delete(String),
    Add(String),
}

fn parse_unified_diff_hunks(diff_text: &str) -> FsResult<Vec<DiffHunk>> {
    let mut hunks = Vec::new();
    let mut lines = diff_text.lines().peekable();
    let mut saw_file_header = false;
    let mut file_headers = 0usize;

    while let Some(line) = lines.next() {
        if line.starts_with("diff --git ") {
            file_headers = file_headers.saturating_add(1);
            if file_headers > 1 {
                return Err(FsError::Patch(
                    "multi-file unified diffs are not supported; patch one path at a time".into(),
                ));
            }
            saw_file_header = true;
            continue;
        }
        if line.starts_with("--- ") || line.starts_with("+++ ") {
            saw_file_header = true;
            continue;
        }
        if line.starts_with("@@") {
            let (old_start, old_count) = parse_hunk_header(line)?;
            let mut hunk_lines = Vec::new();
            while let Some(&next) = lines.peek() {
                if next.starts_with("@@")
                    || next.starts_with("diff --git ")
                    || next.starts_with("--- ")
                {
                    break;
                }
                let body = lines.next().unwrap_or(next);
                if body.starts_with('\\') {
                    // "\ No newline at end of file" — ignore (handled softly).
                    continue;
                }
                if body.is_empty() {
                    // Some producers emit a blank line as context " ".
                    hunk_lines.push(DiffLine::Context(String::new()));
                    continue;
                }
                let (tag, rest) = body.split_at(1);
                match tag {
                    " " => hunk_lines.push(DiffLine::Context(rest.to_owned())),
                    "-" => hunk_lines.push(DiffLine::Delete(rest.to_owned())),
                    "+" => hunk_lines.push(DiffLine::Add(rest.to_owned())),
                    _ => {
                        return Err(FsError::Patch(format!(
                            "invalid hunk line (expected ' ','-','+'): {body:?}"
                        )));
                    }
                }
                if hunk_lines.len() > MAX_UNIFIED_DIFF_TARGET_LINES {
                    return Err(FsError::Patch("hunk line budget exceeded".into()));
                }
            }
            hunks.push(DiffHunk {
                old_start,
                old_count,
                lines: hunk_lines,
            });
            continue;
        }
        // Ignore index/mode headers and noise between files.
        let _ = saw_file_header;
    }
    Ok(hunks)
}

fn parse_hunk_header(line: &str) -> FsResult<(usize, usize)> {
    // @@ -l,s +l,s @@ optional
    let rest = line
        .strip_prefix("@@")
        .and_then(|s| s.split("@@").next())
        .ok_or_else(|| FsError::Patch(format!("malformed hunk header: {line}")))?
        .trim();
    let old = rest
        .split_whitespace()
        .next()
        .ok_or_else(|| FsError::Patch(format!("malformed hunk header: {line}")))?;
    let old = old
        .strip_prefix('-')
        .ok_or_else(|| FsError::Patch(format!("malformed hunk old range: {line}")))?;
    let mut parts = old.split(',');
    let start: usize = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| FsError::Patch(format!("malformed hunk old start: {line}")))?;
    let count: usize = match parts.next() {
        Some(s) => s
            .parse()
            .map_err(|_| FsError::Patch(format!("malformed hunk old count: {line}")))?,
        None => 1,
    };
    Ok((start, count))
}

fn split_lines_preserve(text: &str) -> Vec<&str> {
    if text.is_empty() {
        return Vec::new();
    }
    // Keep line bodies without the newline separator.
    let mut out: Vec<&str> = text.split('\n').collect();
    // If text ends with newline, split leaves a trailing empty element representing
    // the empty line after the final newline — drop it so line counts match git.
    if text.ends_with('\n') && out.last().is_some_and(|s| s.is_empty()) {
        out.pop();
    }
    out
}

fn apply_hunks_to_lines(old_lines: &[&str], hunks: &[DiffHunk]) -> FsResult<Vec<String>> {
    let mut result: Vec<String> = old_lines.iter().map(|s| (*s).to_owned()).collect();
    // Apply from bottom to top so earlier line numbers stay stable.
    let mut ordered: Vec<&DiffHunk> = hunks.iter().collect();
    ordered.sort_by(|a, b| b.old_start.cmp(&a.old_start));

    for hunk in ordered {
        let start_idx = if hunk.old_start == 0 {
            0usize
        } else {
            hunk.old_start.saturating_sub(1)
        };
        if start_idx > result.len() {
            return Err(FsError::Patch(format!(
                "hunk old_start {} past end of file ({} lines)",
                hunk.old_start,
                result.len()
            )));
        }

        // Verify context/delete lines match the current file slice.
        let mut cursor = start_idx;
        let mut delete_count = 0usize;
        for line in &hunk.lines {
            match line {
                DiffLine::Context(s) | DiffLine::Delete(s) => {
                    if cursor >= result.len() || result[cursor] != *s {
                        return Err(FsError::Patch(format!(
                            "hunk context mismatch at line {}: expected {s:?}, got {:?}",
                            cursor + 1,
                            result.get(cursor)
                        )));
                    }
                    if matches!(line, DiffLine::Delete(_)) {
                        delete_count = delete_count.saturating_add(1);
                    }
                    cursor = cursor.saturating_add(1);
                }
                DiffLine::Add(_) => {}
            }
        }
        let old_span = cursor.saturating_sub(start_idx);
        if hunk.old_count > 0 && old_span != hunk.old_count {
            return Err(FsError::Patch(format!(
                "hunk old_count mismatch: header {}, matched {old_span}",
                hunk.old_count
            )));
        }
        let _ = delete_count;

        // Build replacement slice for [start_idx, cursor).
        let mut replacement = Vec::new();
        let mut verify_cursor = start_idx;
        for line in &hunk.lines {
            match line {
                DiffLine::Context(s) => {
                    replacement.push(s.clone());
                    verify_cursor = verify_cursor.saturating_add(1);
                }
                DiffLine::Delete(_) => {
                    verify_cursor = verify_cursor.saturating_add(1);
                }
                DiffLine::Add(s) => {
                    replacement.push(s.clone());
                }
            }
        }
        let _ = verify_cursor;
        result.splice(start_idx..cursor, replacement);
    }
    Ok(result)
}

fn read_file_text_bounded(ws: &WorkspaceRoot, rel: &Path, max_bytes: usize) -> FsResult<String> {
    // Hold the open file (custody path) so we hash/read the same inode we authorized.
    let (mut f, path) = if ws.enforce {
        custody::open_regular_file_read(ws, rel)?
    } else {
        let path = ws.resolve(rel)?;
        if !path.exists() {
            return Err(FsError::NotFound(path));
        }
        let f = fs::File::open(&path).map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
        (f, path)
    };
    let meta = f.metadata().map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    if !meta.is_file() {
        return Err(FsError::NotAFile(path));
    }
    if usize::try_from(meta.len()).map_or(true, |n| n > max_bytes) {
        return Err(FsError::TooLarge);
    }
    let mut buf = Vec::new();
    let mut limited = Read::take(&mut f, max_bytes as u64 + 1);
    limited
        .read_to_end(&mut buf)
        .map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
    if buf.len() > max_bytes {
        return Err(FsError::TooLarge);
    }
    if buf.contains(&0) {
        return Err(FsError::Patch(
            "target file is binary; unified diff apply requires text".into(),
        ));
    }
    String::from_utf8(buf).map_err(|e| FsError::Patch(format!("target is not UTF-8: {e}")))
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
    use std::sync::Mutex;
    use tempfile::tempdir;

    /// OWNMESH_STATE_DIR is process-global; serialize spool tests that mutate it.
    static DIR_SPOOL_TEST_LOCK: Mutex<()> = Mutex::new(());

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

    #[test]
    fn list_page_byte_budget_retains_stable_cursor() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        // Windows component limit is 255 chars — use many medium basenames so the
        // serialized absolute path page exceeds MAX_PAGE_JSON_BYTES before the
        // 500-entry cap. Entry count alone would allow all of them.
        let stem = "n".repeat(200);
        let n = 400_usize;
        for i in 0..n {
            let name = format!("{stem}_{i:04}.txt");
            assert!(name.len() < 240, "keep under Windows component limit");
            write_file(&ws, &name, b"x").unwrap();
        }
        let page1 = list_dir_page(&ws, "", false, 500, None).unwrap();
        let page_json = serde_json::to_vec(&page1.entries).expect("serialize page");
        assert!(
            page1.truncated,
            "expected byte/entry truncation; entries={} total_matched={} json_bytes={}",
            page1.entries.len(),
            page1.total_matched,
            page_json.len()
        );
        assert!(!page1.entries.is_empty());
        assert!(
            page1.entries.len() < n,
            "byte budget should stop before all {n} entries, got {}",
            page1.entries.len()
        );
        assert!(
            page_json.len() <= 96_000 + 8_192,
            "page JSON should stay near the 96 KiB budget, got {}",
            page_json.len()
        );
        let cursor = page1.next_cursor.expect("cursor required when truncated");
        assert!(cursor.starts_with("v1:"), "cursor={cursor}");
        let page2 = list_dir_page(&ws, "", false, 500, Some(cursor.as_str())).unwrap();
        assert!(!page2.entries.is_empty(), "second page must make progress");
        if let (Some(a), Some(b)) = (page1.entries.last(), page2.entries.first()) {
            assert!(
                (a.name.as_str(), a.path.as_str()) < (b.name.as_str(), b.path.as_str()),
                "cursor did not advance: last={a:?} first={b:?}"
            );
        }
    }

    #[test]
    fn list_page_cursor_preserves_duplicate_names_across_dirs() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        // Same basename in two directories — sort is (name, path).
        write_file(&ws, "dir_a/dup.txt", b"a").unwrap();
        write_file(&ws, "dir_b/dup.txt", b"b").unwrap();
        write_file(&ws, "zzz.txt", b"z").unwrap();

        let page1 = list_dir_page(&ws, "", true, 1, None).unwrap();
        assert_eq!(page1.entries.len(), 1);
        assert!(page1.truncated);
        let cursor = page1.next_cursor.expect("page1 cursor");
        assert!(cursor.starts_with("v1:"), "cursor={cursor}");

        let page2 = list_dir_page(&ws, "", true, 10, Some(cursor.as_str())).unwrap();
        // Must still see the second dup.txt and zzz.txt (not drop same-named entry).
        let names: Vec<&str> = page2.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            names.contains(&"dup.txt"),
            "second page lost duplicate name: {names:?} page1={:?}",
            page1.entries
        );
        let all_paths: std::collections::HashSet<String> = page1
            .entries
            .iter()
            .chain(page2.entries.iter())
            .map(|e| e.path.clone())
            .collect();
        assert!(
            all_paths.iter().any(|p| p.contains("dir_a"))
                && all_paths.iter().any(|p| p.contains("dir_b")),
            "both dup paths must appear across pages: {all_paths:?}"
        );
    }

    #[test]
    fn list_page_walks_past_four_thousand_entries_without_silent_drop() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        // Reproduce the former scan_budget=4000 trap: later pages must still see
        // entries beyond the first window, every name exactly once.
        const N: usize = 4_500;
        for i in 0..N {
            let name = format!("f{i:05}.txt");
            write_file(&ws, &name, b"x").unwrap();
        }
        let mut seen = std::collections::HashSet::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0_usize;
        loop {
            pages += 1;
            assert!(pages < 200, "pagination failed to terminate");
            let page = list_dir_page(&ws, "", false, 200, cursor.as_deref()).unwrap();
            for entry in &page.entries {
                assert!(
                    seen.insert(entry.name.clone()),
                    "duplicate entry across pages: {}",
                    entry.name
                );
            }
            if !page.truncated {
                break;
            }
            cursor = page.next_cursor;
            assert!(cursor.is_some(), "truncated page must carry next_cursor");
        }
        assert_eq!(
            seen.len(),
            N,
            "expected every entry once; got {} across {pages} pages",
            seen.len()
        );
        for i in 0..N {
            let name = format!("f{i:05}.txt");
            assert!(seen.contains(&name), "missing {name}");
        }
    }

    /// Large directories that exceed the in-memory snapshot bound must still be
    /// fully retrievable via durable spool cursors (Full Access chunking).
    #[test]
    fn list_page_retrieves_all_entries_beyond_memory_snapshot_via_spool() {
        let _guard = DIR_SPOOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempdir().unwrap();
        // Isolate spool IO under the test temp dir.
        std::env::set_var("OWNMESH_STATE_DIR", dir.path().join("state"));
        let ws = WorkspaceRoot::new(dir.path().join("tree"), true).unwrap();
        std::fs::create_dir_all(ws.root()).unwrap();
        // Just over the 25_000 in-memory bound.
        const N: usize = 25_050;
        for i in 0..N {
            let name = format!("g{i:05}.txt");
            write_file(&ws, &name, b"x").unwrap();
        }
        let mut seen = std::collections::HashSet::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0_usize;
        let mut saw_v2 = false;
        loop {
            pages += 1;
            assert!(pages < 400, "pagination failed to terminate");
            let page = list_dir_page(&ws, "", false, 200, cursor.as_deref()).unwrap();
            for entry in &page.entries {
                assert!(
                    seen.insert(entry.name.clone()),
                    "duplicate entry across pages: {}",
                    entry.name
                );
            }
            if let Some(c) = page.next_cursor.as_deref() {
                if c.starts_with("v2:") {
                    saw_v2 = true;
                }
            }
            if !page.truncated {
                break;
            }
            cursor = page.next_cursor;
            assert!(cursor.is_some(), "truncated page must carry next_cursor");
        }
        assert!(
            saw_v2,
            "expected durable v2 spool cursor for >25k directory"
        );
        assert_eq!(
            seen.len(),
            N,
            "expected every entry once via spool pages; got {} across {pages} pages",
            seen.len()
        );
    }

    /// Adversarial unordered-enumeration property: names that sort early must not
    /// be permanently skipped when the filesystem yields late-sorting names first.
    /// Full snapshot-then-sort is the integrity guarantee under test.
    #[test]
    fn list_page_unordered_enumeration_does_not_skip_early_names() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), true).unwrap();
        // Create late-sorting names first, then early-sorting names. Regardless of
        // OS dirent order, paging must surface every name exactly once.
        for i in 0..300 {
            write_file(&ws, format!("z{i:04}.txt"), b"z").unwrap();
        }
        for i in 0..300 {
            write_file(&ws, format!("a{i:04}.txt"), b"a").unwrap();
        }
        for i in 0..300 {
            write_file(&ws, format!("m{i:04}.txt"), b"m").unwrap();
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut cursor: Option<String> = None;
        let mut pages = 0_usize;
        loop {
            pages += 1;
            assert!(pages < 50, "pagination failed to terminate");
            let page = list_dir_page(&ws, "", false, 100, cursor.as_deref()).unwrap();
            for entry in &page.entries {
                assert!(
                    seen.insert(entry.name.clone()),
                    "duplicate across pages: {}",
                    entry.name
                );
            }
            if !page.truncated {
                break;
            }
            cursor = page.next_cursor;
            assert!(cursor.is_some(), "truncated page must carry next_cursor");
        }
        assert_eq!(seen.len(), 900, "got {} across {pages} pages", seen.len());
        // Early-sorting names must all be present (the former partial-window bug
        // dropped these when z* filled the collect budget first).
        for i in 0..300 {
            assert!(
                seen.contains(&format!("a{i:04}.txt")),
                "missing early name a{i:04}"
            );
            assert!(
                seen.contains(&format!("m{i:04}.txt")),
                "missing mid name m{i:04}"
            );
            assert!(
                seen.contains(&format!("z{i:04}.txt")),
                "missing late name z{i:04}"
            );
        }
        // First page must start with an early-sorted name under total order.
        let first = list_dir_page(&ws, "", false, 10, None).unwrap();
        assert!(
            first.entries[0].name.starts_with('a'),
            "sorted snapshot must page from a*, got {:?}",
            first.entries[0].name
        );
    }

    #[test]
    fn list_page_v2_cursor_bound_to_root_rejects_cross_workspace_substitution() {
        let _guard = DIR_SPOOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempdir().unwrap();
        std::env::set_var("OWNMESH_STATE_DIR", dir.path().join("state"));
        let ws_a = WorkspaceRoot::new(dir.path().join("a"), true).unwrap();
        let ws_b = WorkspaceRoot::new(dir.path().join("b"), true).unwrap();
        std::fs::create_dir_all(ws_a.root()).unwrap();
        std::fs::create_dir_all(ws_b.root()).unwrap();
        // Force durable spool on A.
        const N: usize = 25_050;
        for i in 0..N {
            write_file(&ws_a, format!("a{i:05}.txt"), b"x").unwrap();
        }
        write_file(&ws_b, "only-b.txt", b"b").unwrap();
        let page_a = list_dir_page(&ws_a, "", false, 10, None).unwrap();
        assert!(page_a.truncated);
        let cursor = page_a.next_cursor.expect("v2 cursor");
        assert!(cursor.starts_with("v2:"), "cursor={cursor}");
        // Same cursor against workspace B must fail closed (not return A's snapshot).
        let err = list_dir_page(&ws_b, "", false, 10, Some(cursor.as_str())).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("does not match") || msg.contains("cursor"),
            "expected request-identity bind failure, got {msg}"
        );
        // Control: continuation on A still works.
        let page_a2 = list_dir_page(&ws_a, "", false, 10, Some(cursor.as_str())).unwrap();
        assert!(!page_a2.entries.is_empty());
    }

    #[test]
    fn list_page_rejects_oversized_name_path_aggregate_budget() {
        let _guard = DIR_SPOOL_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempdir().unwrap();
        std::env::set_var("OWNMESH_STATE_DIR", dir.path().join("state"));
        let ws = WorkspaceRoot::new(dir.path().join("tree"), true).unwrap();
        std::fs::create_dir_all(ws.root()).unwrap();
        // Long-but-legal basenames: aggregate byte budget is enforced before
        // serialize, so huge transient JSON allocations cannot accumulate unbounded.
        const M: usize = 8_000;
        for i in 0..M {
            // Stay under Windows 255-char component limit.
            let name = format!("N{i:05}_{}.txt", "x".repeat(200));
            write_file(&ws, &name, b"x").unwrap();
        }
        match list_dir_page(&ws, "", false, 50, None) {
            Ok(page) => {
                let json = serde_json::to_vec(&page.entries).unwrap();
                assert!(json.len() <= 96_000 + 8_192);
                assert!(!page.entries.is_empty());
            }
            Err(FsError::EntryLimit) => {
                // Fail-closed on aggregate budget is acceptable and preferred.
            }
            Err(other) => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn unified_diff_apply_replaces_bounded_hunk() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
        write_file(&ws, "note.txt", b"alpha\nbeta\ngamma\n").unwrap();
        let diff = concat!(
            "--- a/note.txt\n",
            "+++ b/note.txt\n",
            "@@ -1,3 +1,3 @@\n",
            " alpha\n",
            "-beta\n",
            "+BETA\n",
            " gamma\n",
        );
        assert!(looks_like_unified_diff(diff));
        let hash = apply_unified_diff(&ws, "note.txt", diff, None).unwrap();
        let bytes = read_file(&ws, "note.txt", 1024).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert_eq!(text, "alpha\nBETA\ngamma\n");
        assert_eq!(hash, hash_bytes(text.as_bytes()));
    }

    #[test]
    fn unified_diff_apply_rejects_context_mismatch() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
        write_file(&ws, "note.txt", b"alpha\nbeta\n").unwrap();
        let diff = concat!(
            "--- a/note.txt\n",
            "+++ b/note.txt\n",
            "@@ -1,2 +1,2 @@\n",
            " alpha\n",
            "-BETA\n",
            "+gamma\n",
        );
        let err = apply_unified_diff(&ws, "note.txt", diff, None).unwrap_err();
        assert!(matches!(err, FsError::Patch(_)), "{err:?}");
    }

    #[test]
    fn unified_diff_apply_rejects_oversized_diff_text() {
        let dir = tempdir().unwrap();
        let ws = WorkspaceRoot::new(dir.path(), false).unwrap();
        write_file(&ws, "note.txt", b"x\n").unwrap();
        let mut huge = String::from("--- a/note.txt\n+++ b/note.txt\n@@ -1 +1 @@\n-x\n+");
        huge.push_str(&"y".repeat(MAX_UNIFIED_DIFF_BYTES));
        let err = apply_unified_diff(&ws, "note.txt", &huge, None).unwrap_err();
        assert!(matches!(err, FsError::Patch(_)), "{err:?}");
    }
}
