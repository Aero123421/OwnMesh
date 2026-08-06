//! OwnMesh filesystem operations and path safety.
//!
//! Workspace-relative resolution, symlink/junction-aware canonicalization,
//! list/stat/read/write/delete, hash-checked patch apply, and read-only git
//! status/diff.

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
    pub fn new(root: impl Into<PathBuf>, enforce: bool) -> FsResult<Self> {
        let root = root.into();
        let canon = dunce_canonicalize(&root).unwrap_or(root);
        Ok(Self {
            root: canon,
            enforce,
        })
    }

    /// Resolve a relative (or absolute when not enforcing) path safely.
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

/// List directory (non-recursive by default).
pub fn list_dir(
    ws: &WorkspaceRoot,
    rel: impl AsRef<Path>,
    recursive: bool,
    max_entries: usize,
) -> FsResult<Vec<DirEntryInfo>> {
    let path = ws.resolve(rel)?;
    if !path.exists() {
        return Err(FsError::NotFound(path));
    }
    if !path.is_dir() {
        return Err(FsError::NotADirectory(path));
    }
    let mut out = Vec::new();
    if recursive {
        for entry in WalkDir::new(&path).min_depth(1) {
            let entry = entry.map_err(|e| FsError::Io {
                path: Some(path.clone()),
                source: std::io::Error::other(e.to_string()),
            })?;
            if out.len() >= max_entries {
                return Err(FsError::EntryLimit);
            }
            let meta = entry.metadata().ok();
            out.push(DirEntryInfo {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path().to_string_lossy().into_owned(),
                is_dir: entry.file_type().is_dir(),
                is_symlink: entry.file_type().is_symlink(),
                size: meta.and_then(|m| if m.is_file() { Some(m.len()) } else { None }),
            });
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
            if out.len() >= max_entries {
                return Err(FsError::EntryLimit);
            }
            let ft = entry.file_type().map_err(|source| FsError::Io {
                path: Some(entry.path()),
                source,
            })?;
            let meta = entry.metadata().ok();
            out.push(DirEntryInfo {
                name: entry.file_name().to_string_lossy().into_owned(),
                path: entry.path().to_string_lossy().into_owned(),
                is_dir: ft.is_dir(),
                is_symlink: ft.is_symlink(),
                size: meta.and_then(|m| if m.is_file() { Some(m.len()) } else { None }),
            });
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Stat a path; optionally compute sha256 for files.
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
pub fn read_file(ws: &WorkspaceRoot, rel: impl AsRef<Path>, max_bytes: u64) -> FsResult<Vec<u8>> {
    let path = ws.resolve(rel)?;
    let meta = fs::metadata(&path).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    if !meta.is_file() {
        return Err(FsError::NotAFile(path));
    }
    if meta.len() > max_bytes {
        return Err(FsError::TooLarge);
    }
    fs::read(&path).map_err(|source| FsError::Io {
        path: Some(path),
        source,
    })
}

/// Write file atomically (temp + rename) when possible.
pub fn write_file(ws: &WorkspaceRoot, rel: impl AsRef<Path>, data: &[u8]) -> FsResult<()> {
    let path = ws.resolve(rel)?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| FsError::Io {
            path: Some(parent.to_path_buf()),
            source,
        })?;
    }
    let tmp = path.with_extension("ownmesh-tmp");
    {
        let mut f = fs::File::create(&tmp).map_err(|source| FsError::Io {
            path: Some(tmp.clone()),
            source,
        })?;
        f.write_all(data).map_err(|source| FsError::Io {
            path: Some(tmp.clone()),
            source,
        })?;
        f.sync_all().ok();
    }
    fs::rename(&tmp, &path).map_err(|source| FsError::Io {
        path: Some(path),
        source,
    })?;
    Ok(())
}

/// Delete file or empty directory; `recursive` removes trees.
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
    hash_bytes(new_content)
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

fn hash_bytes(data: &[u8]) -> FsResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    Ok(hex::encode(hasher.finalize()))
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
    ) || name.ends_with(".pem")
        || name.ends_with(".key")
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
        assert!(!looks_sensitive(Path::new("/tmp/readme.md")));
    }
}
