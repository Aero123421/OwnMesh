//! Shared durable file-persistence primitives.
//!
//! The workspace pins Rust 1.92.0 (`ded5c06cf`). Its shipped Windows
//! `std::fs::rename` source was verified to call
//! `MoveFileExW(..., MOVEFILE_REPLACE_EXISTING)` and, for its access-denied
//! fallback, `SetFileInformationByHandle` with
//! `FILE_RENAME_FLAG_REPLACE_IF_EXISTS`. Therefore replacing a sibling target
//! does not require a target delete and has no delete/create window.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

/// Result of an atomic create-once operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CreateOnce {
    /// This operation created and published the target.
    Created,
    /// Another operation had already published the target.
    AlreadyExists,
}

/// Durably write `data` to a unique sibling temporary file and atomically replace `target`.
///
/// Every operation creates its own temporary file with `create_new`; writers never remove or
/// reuse another writer's temporary path. `prepare` runs on the newly created file before data
/// is written and is intended for required permission changes. The target is never pre-deleted.
///
/// On Unix the parent directory is opened before writing and synced before the rename, so an
/// ordinary directory-open/sync failure is reported before commit. The directory is synced
/// again after rename. A failure of that post-commit sync is not returned as a not-committed
/// error: once rename succeeds, callers must not roll memory back while the target has advanced.
///
/// Callers must create the target's parent directory first. A pre-commit failure can leave only
/// this operation's uniquely named temporary file for diagnosis.
///
/// # Errors
///
/// Returns errors from parent-directory preparation, unique temporary-file creation,
/// preparation, writing, syncing, or atomic replacement. No error is returned after commit.
pub fn write_atomically_with<F>(target: &Path, data: &[u8], prepare: F) -> io::Result<()>
where
    F: FnOnce(&File) -> io::Result<()>,
{
    let parent = ParentDirectory::open(target)?;
    let (tmp, mut file) = create_unique_temp(target)?;

    prepare(&file)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);

    // Flush creation of the temporary directory entry while failure is still pre-commit.
    parent.sync_before_commit()?;
    replace_sibling(&tmp, target)?;

    // Rename is the commit point. Do not turn a later durability warning into an ordinary
    // failure that invites callers to roll back memory while disk already contains `data`.
    parent.sync_after_commit();
    Ok(())
}

/// Durably write `data` and atomically replace `target` without extra preparation.
///
/// # Errors
///
/// Returns only errors that occur before the atomic replacement commits.
pub fn write_atomically(target: &Path, data: &[u8]) -> io::Result<()> {
    write_atomically_with(target, data, |_| Ok(()))
}

/// Publish `data` at `target` only if the target does not already exist.
///
/// The complete, synced bytes are first written to a per-operation unique sibling. A hard-link
/// creation then publishes that inode at `target` atomically without replacing an existing
/// winner. This avoids exposing a partially written create-new file to concurrent readers.
///
/// # Errors
///
/// Returns only errors that occur before this operation publishes the target. If another writer
/// wins, [`CreateOnce::AlreadyExists`] is returned and its target is never modified.
pub fn create_once_with<F>(target: &Path, data: &[u8], prepare: F) -> io::Result<CreateOnce>
where
    F: FnOnce(&File) -> io::Result<()>,
{
    let parent = ParentDirectory::open(target)?;
    let (tmp, mut file) = create_unique_temp(target)?;

    prepare(&file)?;
    file.write_all(data)?;
    file.sync_all()?;
    drop(file);
    parent.sync_before_commit()?;

    match fs::hard_link(&tmp, target) {
        Ok(()) => {
            // The target now names the complete inode. Cleanup and the second directory sync are
            // post-commit and therefore must not be reported as if creation had not happened.
            let _ = fs::remove_file(&tmp);
            parent.sync_after_commit();
            Ok(CreateOnce::Created)
        }
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {
            // This path belongs to this operation, so removing it cannot disrupt the winner.
            let _ = fs::remove_file(&tmp);
            Ok(CreateOnce::AlreadyExists)
        }
        Err(err) => Err(err),
    }
}

fn create_unique_temp(target: &Path) -> io::Result<(PathBuf, File)> {
    loop {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let tmp = unique_temp_path(target, std::process::id(), id);
        match OpenOptions::new().write(true).create_new(true).open(&tmp) {
            Ok(file) => return Ok((tmp, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
            Err(err) => return Err(err),
        }
    }
}

fn unique_temp_path(target: &Path, process_id: u32, id: u64) -> PathBuf {
    let mut tmp: OsString = target.as_os_str().to_os_string();
    tmp.push(format!(".tmp.{process_id}.{id}"));
    PathBuf::from(tmp)
}

/// Replace `target` with its sibling `tmp` in one platform rename operation.
fn replace_sibling(tmp: &Path, target: &Path) -> io::Result<()> {
    if tmp.parent() != target.parent() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "atomic replacement paths must be siblings",
        ));
    }
    fs::rename(tmp, target)
}

#[cfg(unix)]
struct ParentDirectory(File);

#[cfg(unix)]
impl ParentDirectory {
    fn open(target: &Path) -> io::Result<Self> {
        File::open(parent_path(target)).map(Self)
    }

    fn sync_before_commit(&self) -> io::Result<()> {
        self.0.sync_all()
    }

    fn sync_after_commit(&self) {
        let _ = self.0.sync_all();
    }
}

#[cfg(not(unix))]
struct ParentDirectory;

#[cfg(not(unix))]
#[allow(clippy::unnecessary_wraps, clippy::unused_self)]
impl ParentDirectory {
    fn open(_target: &Path) -> io::Result<Self> {
        Ok(Self)
    }

    fn sync_before_commit(&self) -> io::Result<()> {
        Ok(())
    }

    fn sync_after_commit(&self) {}
}

#[cfg(unix)]
fn parent_path(target: &Path) -> &Path {
    target
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    fn temp_files(target: &Path) -> Vec<PathBuf> {
        let prefix = format!("{}.tmp.", target.file_name().unwrap().to_string_lossy());
        fs::read_dir(target.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
            })
            .collect()
    }

    #[test]
    fn replaces_existing_target_without_touching_legacy_temp() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("state.json");
        let legacy_tmp = dir.path().join("state.json.tmp");
        fs::write(&target, b"old").unwrap();
        fs::write(&legacy_tmp, b"belongs-to-someone-else").unwrap();

        write_atomically(&target, b"new").unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"new");
        assert_eq!(fs::read(&legacy_tmp).unwrap(), b"belongs-to-someone-else");
        assert!(temp_files(&target).is_empty());
    }

    #[test]
    fn preparation_failure_happens_before_commit() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("secret");
        fs::write(&target, b"old-secret").unwrap();

        let err = write_atomically_with(&target, b"new-secret", |_| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "injected chmod failure",
            ))
        })
        .expect_err("preparation must fail");

        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(fs::read(&target).unwrap(), b"old-secret");
        assert_eq!(temp_files(&target).len(), 1);
    }

    #[test]
    fn concurrent_writers_use_independent_temps_and_all_commit() {
        const WRITERS: usize = 16;
        let dir = tempdir().unwrap();
        let target = Arc::new(dir.path().join("shared.json"));
        fs::write(target.as_ref(), b"initial").unwrap();
        let barrier = Arc::new(Barrier::new(WRITERS));

        let threads: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let target = Arc::clone(&target);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    let data = format!("writer-{writer}").into_bytes();
                    write_atomically_with(&target, &data, |_| {
                        barrier.wait();
                        Ok(())
                    })?;
                    Ok::<_, io::Error>(data)
                })
            })
            .collect();

        let payloads: Vec<Vec<u8>> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap().unwrap())
            .collect();
        let final_bytes = fs::read(target.as_ref()).unwrap();
        assert!(payloads.contains(&final_bytes));
        assert!(temp_files(target.as_ref()).is_empty());
    }

    #[test]
    fn create_once_never_replaces_winner() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("unlock");
        assert_eq!(
            create_once_with(&target, b"winner", |_| Ok(())).unwrap(),
            CreateOnce::Created
        );
        assert_eq!(
            create_once_with(&target, b"loser", |_| Ok(())).unwrap(),
            CreateOnce::AlreadyExists
        );
        assert_eq!(fs::read(&target).unwrap(), b"winner");
    }

    #[cfg(windows)]
    #[test]
    fn locked_destination_failure_preserves_existing_target() {
        use std::io::{Read, Seek};
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempdir().unwrap();
        let target = dir.path().join("state.json");
        fs::write(&target, b"stable-old").unwrap();
        let mut guard = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&target)
            .unwrap();

        write_atomically(&target, b"new").expect_err("locked replace must fail");
        guard.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        guard.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"stable-old");
        drop(guard);
        assert_eq!(fs::read(&target).unwrap(), b"stable-old");
    }
}
