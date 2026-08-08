//! Handle-rooted workspace custody for restricted modes.
//!
//! Restricted (`enforce=true`) filesystem side effects must not trust a path
//! string across a TOCTOU gap. Operations open the target (or its parent),
//! revalidate the opened handle's final path against the workspace root, and
//! only then read, write, hash, or delete. Symlink / junction / reparse points
//! are never followed as an authority boundary in restricted mode: a racing
//! replacement that leaves the handle outside the root fails closed before any
//! content is returned or committed.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use crate::{dunce_canonicalize, FsError, FsResult, WorkspaceRoot};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};

/// Maximum components accepted for a single relative workspace path.
const MAX_COMPONENTS: usize = 128;

/// Normalize a caller path into workspace-relative normal components.
///
/// Rejects absolute paths, prefixes, and `..` that would climb above the root
/// of the relative walk (the workspace root is applied by the caller).
pub(crate) fn relative_components(rel: &Path) -> FsResult<Vec<std::ffi::OsString>> {
    if rel.as_os_str().is_empty() {
        return Ok(Vec::new());
    }
    if rel.to_string_lossy().contains('\0') {
        return Err(FsError::InvalidPath(rel.display().to_string()));
    }
    if rel.is_absolute() {
        return Err(FsError::InvalidPath(format!(
            "absolute path not permitted in restricted custody walk: {}",
            rel.display()
        )));
    }

    let mut out: Vec<std::ffi::OsString> = Vec::new();
    for c in rel.components() {
        match c {
            Component::Normal(s) => {
                if s.is_empty() {
                    return Err(FsError::InvalidPath(rel.display().to_string()));
                }
                out.push(s.to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if out.pop().is_none() {
                    return Err(FsError::EscapesWorkspace(rel.to_path_buf()));
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                return Err(FsError::InvalidPath(rel.display().to_string()));
            }
        }
        if out.len() > MAX_COMPONENTS {
            return Err(FsError::InvalidPath(rel.display().to_string()));
        }
    }
    Ok(out)
}

fn path_is_under_root(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn strip_extended_prefix(path: PathBuf) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\UNC\") {
        PathBuf::from(format!(r"\\{stripped}"))
    } else if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path
    }
}

/// Final path of an open handle (platform-native). Used to revalidate custody
/// after open and before any side effect or content return.
pub(crate) fn final_path_of_handle(file: &File) -> std::io::Result<PathBuf> {
    #[cfg(windows)]
    {
        final_path_windows(file)
    }
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let fd = file.as_raw_fd();
        let link = format!("/proc/self/fd/{fd}");
        let path = fs::read_link(&link)?;
        Ok(strip_extended_prefix(path))
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        final_path_unix_fcntl(file)
    }
}

#[cfg(windows)]
fn final_path_windows(file: &File) -> std::io::Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, VOLUME_NAME_DOS,
    };

    let handle = file.as_raw_handle();
    // First probe for required size.
    let needed = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            std::ptr::null_mut(),
            0,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if needed == 0 {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() }.cast_signed(),
        ));
    }
    let mut buf = vec![0u16; needed as usize + 2];
    let buf_len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            buf.as_mut_ptr(),
            buf_len,
            FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
        )
    };
    if written == 0 || (written as usize) >= buf.len() {
        return Err(std::io::Error::from_raw_os_error(
            unsafe { GetLastError() }.cast_signed(),
        ));
    }
    buf.truncate(written as usize);
    let os = std::ffi::OsString::from_wide(&buf);
    Ok(strip_extended_prefix(PathBuf::from(os)))
}

#[cfg(all(unix, not(target_os = "linux")))]
fn final_path_unix_fcntl(file: &File) -> std::io::Result<PathBuf> {
    use std::os::unix::io::AsRawFd;
    // macOS / BSD: F_GETPATH (50 on Darwin).
    const F_GETPATH: i32 = 50;
    let mut buf = [0i8; 4096];
    let rc = unsafe { fcntl_getpath(file.as_raw_fd(), F_GETPATH, buf.as_mut_ptr()) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let bytes = buf
        .iter()
        .map(|&c| c as u8)
        .take_while(|&b| b != 0)
        .collect::<Vec<_>>();
    let path = std::str::from_utf8(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(PathBuf::from(path))
}

#[cfg(all(unix, not(target_os = "linux")))]
unsafe fn fcntl_getpath(fd: i32, cmd: i32, buf: *mut i8) -> i32 {
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
    }
    fcntl(fd, cmd, buf)
}

fn ensure_handle_under_workspace(file: &File, ws: &WorkspaceRoot) -> FsResult<PathBuf> {
    let final_path = final_path_of_handle(file).map_err(|source| FsError::Io {
        path: Some(ws.root().to_path_buf()),
        source,
    })?;
    let final_path = strip_extended_prefix(final_path);
    let root = strip_extended_prefix(ws.root().to_path_buf());
    // Compare against both the configured root and a canonicalized root when possible.
    let root_cmp = dunce_canonicalize(&root).unwrap_or(root);
    let final_cmp = dunce_canonicalize(&final_path).unwrap_or(final_path.clone());
    if !path_is_under_root(&final_cmp, &root_cmp) {
        return Err(FsError::EscapesWorkspace(final_cmp));
    }
    Ok(final_cmp)
}

fn is_reparse_or_symlink(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
        meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn open_existing_nofollow(path: &Path, read: bool, write: bool) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut opts = OpenOptions::new();
        opts.read(read).write(write);
        // O_NOFOLLOW: fail if the final component is a symlink.
        opts.custom_flags(libc_o_nofollow());
        opts.open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        let mut opts = OpenOptions::new();
        opts.read(read).write(write);
        // Open the reparse point itself so a racing symlink/junction is visible
        // on the handle and rejected before content I/O.
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS);
        opts.open(path)
    }
}

#[cfg(unix)]
fn libc_o_nofollow() -> i32 {
    // Linux 0400_000, macOS 0x100, FreeBSD 0x100 — rustix constant via cfg.
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        0o400_000
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    ))]
    {
        0x100
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        0
    }
}

fn open_dir_nofollow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc_o_nofollow())
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    }
}

/// Build a restricted path by walking normal components without following
/// symlink authority. Each intermediate must be a real directory (not a
/// reparse/symlink). The returned path is the joined lexical path under root;
/// callers must still open + revalidate the handle final path.
fn join_enforced_path(ws: &WorkspaceRoot, rel: &Path) -> FsResult<PathBuf> {
    let comps = relative_components(rel)?;
    let root = dunce_canonicalize(ws.root()).unwrap_or_else(|_| ws.root().to_path_buf());
    // Pin the workspace root directory handle for the walk.
    let root_handle = open_dir_nofollow(&root).map_err(|source| FsError::Io {
        path: Some(root.clone()),
        source,
    })?;
    let root_final = ensure_handle_under_workspace(&root_handle, ws)?;
    drop(root_handle);

    let mut cur = root_final;
    for (idx, comp) in comps.iter().enumerate() {
        let next = cur.join(comp);
        let is_last = idx + 1 == comps.len();
        // Prefer symlink_metadata so we observe reparse points before open.
        match fs::symlink_metadata(&next) {
            Ok(meta) => {
                if is_reparse_or_symlink(&meta) {
                    return Err(FsError::SymlinkOrReparse(next));
                }
                if !is_last && !meta.is_dir() {
                    return Err(FsError::NotADirectory(next));
                }
                // Pin intermediate directories so a replacement is harder and so
                // we revalidate identity before descending.
                if is_last {
                    cur = next;
                } else {
                    let dir = open_dir_nofollow(&next).map_err(|source| FsError::Io {
                        path: Some(next.clone()),
                        source,
                    })?;
                    let dir_meta = dir.metadata().map_err(|source| FsError::Io {
                        path: Some(next.clone()),
                        source,
                    })?;
                    if is_reparse_or_symlink(&dir_meta) || !dir_meta.is_dir() {
                        return Err(FsError::SymlinkOrReparse(next));
                    }
                    let pinned = ensure_handle_under_workspace(&dir, ws)?;
                    drop(dir);
                    cur = pinned;
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Missing final/intermediate: keep the lexical join under the
                // pinned root. create_dir_all + parent handle revalidation run
                // at write time before any side effect.
                cur = next;
            }
            Err(source) => {
                return Err(FsError::Io {
                    path: Some(next),
                    source,
                });
            }
        }
    }
    Ok(cur)
}

fn ensure_not_reparse_handle(file: &File, path: &Path) -> FsResult<()> {
    let meta = file.metadata().map_err(|source| FsError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;
    if is_reparse_or_symlink(&meta) {
        return Err(FsError::SymlinkOrReparse(path.to_path_buf()));
    }
    Ok(())
}

/// Workspace root device identity used to reject cross-mount opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RootIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(windows)]
    volume_serial: u32,
}

fn root_identity(ws: &WorkspaceRoot) -> FsResult<RootIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let root_meta = fs::metadata(ws.root()).map_err(|source| FsError::Io {
            path: Some(ws.root().to_path_buf()),
            source,
        })?;
        return Ok(RootIdentity {
            dev: root_meta.dev(),
        });
    }
    #[cfg(windows)]
    {
        // Open the root directory handle to read volume serial via ByHandle info.
        let dir = open_dir_nofollow(ws.root()).map_err(|source| FsError::Io {
            path: Some(ws.root().to_path_buf()),
            source,
        })?;
        let serial = volume_serial_of_handle(&dir).map_err(|source| FsError::Io {
            path: Some(ws.root().to_path_buf()),
            source,
        })?;
        Ok(RootIdentity {
            volume_serial: serial,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err(FsError::InvalidPath(
            "restricted custody root identity unsupported on this platform".into(),
        ))
    }
}

/// Reject cross-mount opens and multi-link hardlinks in restricted mode.
///
/// A hardlink whose final pathname is inside the workspace can still alias an
/// outside inode. Without a portable "list all names for inode" API we fail
/// closed on link count > 1. Mount escapes are rejected via device/volume id.
fn ensure_no_cross_boundary_alias(file: &File, path: &Path, ws: &WorkspaceRoot) -> FsResult<()> {
    let root_id = root_identity(ws)?;
    let meta = file.metadata().map_err(|source| FsError::Io {
        path: Some(path.to_path_buf()),
        source,
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if meta.dev() != root_id.dev {
            return Err(FsError::CrossMount(path.to_path_buf()));
        }
        // nlink > 1 means the inode is reachable via another directory entry.
        // That other name may be outside the workspace; fail closed.
        if meta.nlink() > 1 {
            return Err(FsError::CrossBoundaryHardlink(path.to_path_buf()));
        }
    }

    #[cfg(windows)]
    {
        let info = by_handle_file_info(file).map_err(|source| FsError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        if info.volume_serial != root_id.volume_serial {
            return Err(FsError::CrossMount(path.to_path_buf()));
        }
        if info.number_of_links > 1 {
            return Err(FsError::CrossBoundaryHardlink(path.to_path_buf()));
        }
    }

    let _ = (&root_id, &meta);
    Ok(())
}

#[cfg(windows)]
#[derive(Debug, Clone, Copy)]
struct ByHandleInfo {
    volume_serial: u32,
    number_of_links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(windows)]
fn by_handle_file_info(file: &File) -> std::io::Result<ByHandleInfo> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::HANDLE;
    use windows_sys::Win32::Storage::FileSystem::{
        GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION,
    };

    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    let ok = unsafe {
        GetFileInformationByHandle(
            file.as_raw_handle() as HANDLE,
            std::ptr::from_mut(&mut info),
        )
    };
    if ok == 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(ByHandleInfo {
        volume_serial: info.dwVolumeSerialNumber,
        number_of_links: info.nNumberOfLinks,
        file_index_high: info.nFileIndexHigh,
        file_index_low: info.nFileIndexLow,
    })
}

#[cfg(windows)]
fn volume_serial_of_handle(file: &File) -> std::io::Result<u32> {
    Ok(by_handle_file_info(file)?.volume_serial)
}

/// Open an existing regular file under the workspace for reading.
pub(crate) fn open_regular_file_read(ws: &WorkspaceRoot, rel: &Path) -> FsResult<(File, PathBuf)> {
    if !ws.enforce {
        let path = ws.resolve(rel)?;
        let file = File::open(&path).map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
        return Ok((file, path));
    }

    // Absolute paths in restricted mode must still resolve inside the root.
    let path = if rel.is_absolute() {
        ws.resolve(rel)?
    } else {
        join_enforced_path(ws, rel)?
    };

    let file = open_existing_nofollow(&path, true, false).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            FsError::NotFound(path.clone())
        } else {
            FsError::Io {
                path: Some(path.clone()),
                source,
            }
        }
    })?;
    ensure_not_reparse_handle(&file, &path)?;
    let meta = file.metadata().map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    if !meta.is_file() {
        return Err(FsError::NotAFile(path));
    }
    let final_path = ensure_handle_under_workspace(&file, ws)?;
    // After pathname custody, reject multi-link hardlinks and cross-mount inodes.
    ensure_no_cross_boundary_alias(&file, &final_path, ws)?;
    Ok((file, final_path))
}

/// Stat via opened handle identity (restricted) or path resolve (unrestricted).
pub(crate) fn stat_enforced(
    ws: &WorkspaceRoot,
    rel: &Path,
    hash: bool,
) -> FsResult<crate::FileStat> {
    if !ws.enforce {
        // Unrestricted path uses the classic resolve path in the caller.
        return Err(FsError::InvalidPath(
            "stat_enforced called without enforce".into(),
        ));
    }

    let path = if rel.is_absolute() {
        ws.resolve(rel)?
    } else {
        join_enforced_path(ws, rel)?
    };

    // Use symlink_metadata first so we can report symlink nodes without following.
    let meta = fs::symlink_metadata(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            FsError::NotFound(path.clone())
        } else {
            FsError::Io {
                path: Some(path.clone()),
                source,
            }
        }
    })?;
    let is_symlink = is_reparse_or_symlink(&meta);
    if is_symlink {
        // Restricted mode: surface the symlink node itself, never the target.
        return Ok(crate::FileStat {
            path: path.to_string_lossy().into_owned(),
            is_dir: false,
            is_file: false,
            is_symlink: true,
            size: meta.len(),
            sha256: None,
        });
    }

    if meta.is_dir() {
        let dir = open_dir_nofollow(&path).map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
        ensure_not_reparse_handle(&dir, &path)?;
        let final_path = ensure_handle_under_workspace(&dir, ws)?;
        return Ok(crate::FileStat {
            path: final_path.to_string_lossy().into_owned(),
            is_dir: true,
            is_file: false,
            is_symlink: false,
            size: 0,
            sha256: None,
        });
    }

    let (mut file, final_path) = open_regular_file_read(ws, rel)?;
    let size = file.metadata().map(|m| m.len()).unwrap_or(meta.len());
    let sha256 = if hash {
        Some(hash_open_file(&mut file, &final_path)?)
    } else {
        None
    };
    Ok(crate::FileStat {
        path: final_path.to_string_lossy().into_owned(),
        is_dir: false,
        is_file: true,
        is_symlink: false,
        size,
        sha256,
    })
}

pub(crate) fn hash_open_file(file: &mut File, path: &Path) -> FsResult<String> {
    use sha2::{Digest, Sha256};
    file.seek(SeekFrom::Start(0))
        .map_err(|source| FsError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf).map_err(|source| FsError::Io {
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

/// Read a bounded range from a custody-checked regular file handle.
pub(crate) fn read_range_enforced(
    ws: &WorkspaceRoot,
    rel: &Path,
    offset: u64,
    max_bytes: u64,
) -> FsResult<(Vec<u8>, u64, bool, PathBuf)> {
    let (mut file, final_path) = open_regular_file_read(ws, rel)?;
    let meta = file.metadata().map_err(|source| FsError::Io {
        path: Some(final_path.clone()),
        source,
    })?;
    let total = meta.len();
    if offset >= total {
        return Ok((Vec::new(), total, false, final_path));
    }
    let remaining = total - offset;
    let take = remaining.min(max_bytes);
    file.seek(SeekFrom::Start(offset))
        .map_err(|source| FsError::Io {
            path: Some(final_path.clone()),
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
                    path: Some(final_path),
                    source,
                });
            }
        }
    }
    buf.truncate(read_total);
    let truncated = offset.saturating_add(read_total as u64) < total;
    Ok((buf, total, truncated, final_path))
}

/// Ensure parent directory exists via component-wise mkdir + handle revalidation.
///
/// Never uses a single `create_dir_all` over an untrusted multi-component path:
/// each intermediate directory is created (if missing), opened nofollow, and
/// revalidated against the workspace root before descending. Returns the pinned
/// parent path **and** a held directory handle so the caller can re-check identity
/// immediately before rename (narrows TOCTOU vs drop-then-path-ops).
#[allow(dead_code)] // retained API for callers that only need the pinned path
pub(crate) fn ensure_parent_enforced(ws: &WorkspaceRoot, file_path: &Path) -> FsResult<PathBuf> {
    let (path, _dir) = ensure_parent_held(ws, file_path)?;
    Ok(path)
}

fn ensure_parent_held(ws: &WorkspaceRoot, file_path: &Path) -> FsResult<(PathBuf, File)> {
    let parent = file_path.parent().ok_or_else(|| {
        FsError::InvalidPath(format!("file path has no parent: {}", file_path.display()))
    })?;
    ensure_dir_tree_held(ws, parent)
}

/// Component-wise ensure `dir_path` exists under the workspace; return pinned path + handle.
fn ensure_dir_tree_held(ws: &WorkspaceRoot, dir_path: &Path) -> FsResult<(PathBuf, File)> {
    // Resolve dir_path relative to the workspace root when possible.
    let root = strip_extended_prefix(ws.root().to_path_buf());
    let root_cmp = dunce_canonicalize(&root).unwrap_or(root.clone());
    let target = if dir_path.starts_with(&root_cmp) || dir_path.starts_with(ws.root()) {
        dir_path.to_path_buf()
    } else {
        // Lexical join under root for relative parents produced by join_enforced_path.
        ws.root().join(dir_path)
    };

    let rel = target
        .strip_prefix(&root_cmp)
        .or_else(|_| target.strip_prefix(ws.root()))
        .unwrap_or(Path::new(""));
    let comps = relative_components(rel)?;

    let root_dir = open_dir_nofollow(ws.root()).map_err(|source| FsError::Io {
        path: Some(ws.root().to_path_buf()),
        source,
    })?;
    ensure_not_reparse_handle(&root_dir, ws.root())?;
    let mut cur = ensure_handle_under_workspace(&root_dir, ws)?;
    // Keep the current directory handle open while descending.
    let mut held = root_dir;

    for comp in comps {
        let next = cur.join(&comp);
        match open_dir_nofollow(&next) {
            Ok(dir) => {
                ensure_not_reparse_handle(&dir, &next)?;
                let meta = dir.metadata().map_err(|source| FsError::Io {
                    path: Some(next.clone()),
                    source,
                })?;
                if !meta.is_dir() {
                    return Err(FsError::NotADirectory(next));
                }
                cur = ensure_handle_under_workspace(&dir, ws)?;
                held = dir;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                // Single-component create only — never multi-level create_dir_all.
                fs::create_dir(&next).map_err(|source| FsError::Io {
                    path: Some(next.clone()),
                    source,
                })?;
                let dir = open_dir_nofollow(&next).map_err(|source| FsError::Io {
                    path: Some(next.clone()),
                    source,
                })?;
                ensure_not_reparse_handle(&dir, &next)?;
                let meta = dir.metadata().map_err(|source| FsError::Io {
                    path: Some(next.clone()),
                    source,
                })?;
                if !meta.is_dir() || is_reparse_or_symlink(&meta) {
                    return Err(FsError::SymlinkOrReparse(next));
                }
                cur = ensure_handle_under_workspace(&dir, ws)?;
                held = dir;
            }
            Err(source) => {
                return Err(FsError::Io {
                    path: Some(next),
                    source,
                });
            }
        }
    }
    Ok((cur, held))
}

/// Write bytes via exclusive temp + rename with parent handle held across the side effect.
pub(crate) fn write_file_enforced(
    ws: &WorkspaceRoot,
    rel: &Path,
    data: &[u8],
) -> FsResult<PathBuf> {
    let path = if rel.is_absolute() {
        ws.resolve(rel)?
    } else {
        join_enforced_path(ws, rel)?
    };
    let (parent_final, parent_handle) = ensure_parent_held(ws, &path)?;

    let token = {
        use sha2::{Digest, Sha256};
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
    let tmp_name = format!(".ownmesh-{}.tmp", token.get(..16).unwrap_or(token.as_str()));
    let tmp = parent_final.join(&tmp_name);

    {
        // Create exclusive temp; open without following reparse.
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(libc_o_nofollow());
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
            opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
        }
        let mut f = opts.open(&tmp).map_err(|source| FsError::Io {
            path: Some(tmp.clone()),
            source,
        })?;
        ensure_not_reparse_handle(&f, &tmp)?;
        // Temp must reside under the workspace (parent already checked; re-check handle).
        let _ = ensure_handle_under_workspace(&f, ws)?;
        f.write_all(data).map_err(|source| FsError::Io {
            path: Some(tmp.clone()),
            source,
        })?;
        f.sync_all().ok();
    }

    // Revalidate the *held* parent handle immediately before rename so a racing
    // replacement of an intermediate directory is observed when the OS updates
    // the handle's final path (and fail closed before publishing).
    if let Err(err) = ensure_not_reparse_handle(&parent_handle, &parent_final) {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    let parent_now = match ensure_handle_under_workspace(&parent_handle, ws) {
        Ok(p) => p,
        Err(err) => {
            let _ = fs::remove_file(&tmp);
            return Err(err);
        }
    };
    // Prefer the live parent path for the destination name.
    let dest_name = path.file_name().map_or_else(|| path.clone(), PathBuf::from);
    let dest = parent_now.join(dest_name);

    // Unix: renameat via /proc self paths still uses path strings from held final
    // paths; Windows uses the same parent_now-derived destination. Holding the
    // parent handle across this call is the portable custody narrow.
    let rename_result = rename_nofollow_under_parent(&tmp, &dest, &parent_handle, ws);
    if let Err(source) = rename_result {
        let _ = fs::remove_file(&tmp);
        return Err(FsError::Io {
            path: Some(dest.clone()),
            source,
        });
    }

    // Revalidate the published path: open nofollow and require final path under root.
    match open_existing_nofollow(&dest, true, false) {
        Ok(published) => {
            if let Err(err) = ensure_not_reparse_handle(&published, &dest) {
                let _ = fs::remove_file(&dest);
                return Err(err);
            }
            match ensure_handle_under_workspace(&published, ws) {
                Ok(final_path) => {
                    if let Err(err) = ensure_no_cross_boundary_alias(&published, &final_path, ws) {
                        let _ = fs::remove_file(&dest);
                        return Err(err);
                    }
                    Ok(final_path)
                }
                Err(err) => {
                    let _ = fs::remove_file(&dest);
                    Err(err)
                }
            }
        }
        Err(source) => Err(FsError::Io {
            path: Some(dest),
            source,
        }),
    }
}

/// Rename after parent-handle revalidation. Uses `renameat` on Linux when the
/// parent directory file descriptor is available; falls back to path rename with
/// the already-pinned parent_final-derived paths elsewhere.
fn rename_nofollow_under_parent(
    tmp: &Path,
    dest: &Path,
    parent_handle: &File,
    ws: &WorkspaceRoot,
) -> std::io::Result<()> {
    // Final custody gate on the parent before the side effect.
    let _ = ensure_handle_under_workspace(parent_handle, ws)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()))?;

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;
        let dirfd = parent_handle.as_raw_fd();
        let tmp_name = tmp.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "tmp has no file name")
        })?;
        let dest_name = dest.file_name().ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "dest has no file name")
        })?;
        let tmp_c = std::ffi::CString::new(tmp_name.as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "tmp name contains NUL")
        })?;
        let dest_c = std::ffi::CString::new(dest_name.as_encoded_bytes()).map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "dest name contains NUL")
        })?;
        // renameat(dirfd, tmp, dirfd, dest)
        let rc = unsafe { libc_renameat(dirfd, tmp_c.as_ptr(), dirfd, dest_c.as_ptr()) };
        if rc == 0 {
            return Ok(());
        }
        return Err(std::io::Error::last_os_error());
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = parent_handle;
        fs::rename(tmp, dest)
    }
}

#[cfg(target_os = "linux")]
unsafe fn libc_renameat(
    olddirfd: i32,
    oldpath: *const libc_char,
    newdirfd: i32,
    newpath: *const libc_char,
) -> i32 {
    extern "C" {
        fn renameat(
            olddirfd: i32,
            oldpath: *const libc_char,
            newdirfd: i32,
            newpath: *const libc_char,
        ) -> i32;
    }
    renameat(olddirfd, oldpath, newdirfd, newpath)
}

#[cfg(target_os = "linux")]
type libc_char = i8;

/// Delete a path after handle identity revalidation in restricted mode.
pub(crate) fn delete_enforced(ws: &WorkspaceRoot, rel: &Path, recursive: bool) -> FsResult<()> {
    let path = if rel.is_absolute() {
        ws.resolve(rel)?
    } else {
        join_enforced_path(ws, rel)?
    };

    let meta = fs::symlink_metadata(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            FsError::NotFound(path.clone())
        } else {
            FsError::Io {
                path: Some(path.clone()),
                source,
            }
        }
    })?;

    if is_reparse_or_symlink(&meta) {
        // Removing a symlink node itself is safe (does not follow). Still require
        // the lexical path to sit under the root.
        let parent = path.parent().unwrap_or_else(|| ws.root());
        if parent.exists() {
            if let Ok(dir) = open_dir_nofollow(parent) {
                let _ = ensure_handle_under_workspace(&dir, ws)?;
            }
        }
        fs::remove_file(&path).map_err(|source| FsError::Io {
            path: Some(path),
            source,
        })?;
        return Ok(());
    }

    if meta.is_dir() {
        let dir = open_dir_nofollow(&path).map_err(|source| FsError::Io {
            path: Some(path.clone()),
            source,
        })?;
        ensure_not_reparse_handle(&dir, &path)?;
        let _ = ensure_handle_under_workspace(&dir, ws)?;
        drop(dir);
        if recursive {
            fs::remove_dir_all(&path)
        } else {
            fs::remove_dir(&path)
        }
        .map_err(|source| FsError::Io {
            path: Some(path),
            source,
        })?;
        return Ok(());
    }

    // Regular file: open nofollow, revalidate, then remove by path (best-effort
    // race: if replaced after open, remove_file of a symlink node is still OK).
    let file = open_existing_nofollow(&path, true, false).map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    ensure_not_reparse_handle(&file, &path)?;
    let final_path = ensure_handle_under_workspace(&file, ws)?;
    // Deny deleting multi-link inodes in restricted mode: the other name may be
    // outside the workspace and the delete would mutate shared content identity.
    ensure_no_cross_boundary_alias(&file, &final_path, ws)?;
    drop(file);
    fs::remove_file(&path).map_err(|source| FsError::Io {
        path: Some(path),
        source,
    })
}

/// Open + revalidate a directory handle under the workspace. The returned
/// `File` MUST be held across any subsequent enumeration so a rename/symlink
/// replacement of the directory name cannot retarget the listing.
pub(crate) fn open_dir_enforced(ws: &WorkspaceRoot, rel: &Path) -> FsResult<(File, PathBuf)> {
    let path = if rel.as_os_str().is_empty() {
        dunce_canonicalize(ws.root()).unwrap_or_else(|_| ws.root().to_path_buf())
    } else if rel.is_absolute() {
        ws.resolve(rel)?
    } else {
        join_enforced_path(ws, rel)?
    };
    let dir = open_dir_nofollow(&path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            FsError::NotFound(path.clone())
        } else {
            FsError::Io {
                path: Some(path.clone()),
                source,
            }
        }
    })?;
    ensure_not_reparse_handle(&dir, &path)?;
    let meta = dir.metadata().map_err(|source| FsError::Io {
        path: Some(path.clone()),
        source,
    })?;
    if !meta.is_dir() {
        return Err(FsError::NotADirectory(path));
    }
    let final_path = ensure_handle_under_workspace(&dir, ws)?;
    Ok((dir, final_path))
}

/// List directory after opening + revalidating the directory handle.
///
/// Prefer [`open_dir_enforced`] + [`read_dir_held`] when the handle must remain
/// open across the side-effect boundary. This path-only helper is for callers
/// that only need a revalidated cwd path (e.g. git spawn).
pub(crate) fn resolve_dir_enforced(ws: &WorkspaceRoot, rel: &Path) -> FsResult<PathBuf> {
    let (_dir, path) = open_dir_enforced(ws, rel)?;
    Ok(path)
}

/// Stable open-file identity used to detect path replacement races.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct OpenIdentity {
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index_high: u32,
    #[cfg(windows)]
    file_index_low: u32,
}

fn open_identity(file: &File, path: &Path) -> FsResult<OpenIdentity> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = file.metadata().map_err(|source| FsError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        Ok(OpenIdentity {
            dev: meta.dev(),
            ino: meta.ino(),
        })
    }
    #[cfg(windows)]
    {
        let info = by_handle_file_info(file).map_err(|source| FsError::Io {
            path: Some(path.to_path_buf()),
            source,
        })?;
        Ok(OpenIdentity {
            volume_serial: info.volume_serial,
            file_index_high: info.file_index_high,
            file_index_low: info.file_index_low,
        })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, path);
        Err(FsError::InvalidPath(
            "open identity unsupported on this platform".into(),
        ))
    }
}

/// One directory child observed through a held directory handle.
#[derive(Debug, Clone)]
pub(crate) struct HeldDirChild {
    pub name: std::ffi::OsString,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub size: Option<u64>,
}

/// Enumerate a directory through a retained handle. Never releases the caller's
/// handle. On platforms without true handle-rooted readdir, enumerates via a
/// handle-stable path (Linux `/proc/self/fd`) or path + post-identity check.
pub(crate) fn read_dir_held(dir: &File, path: &Path) -> FsResult<Vec<HeldDirChild>> {
    let before = open_identity(dir, path)?;
    let children = read_dir_held_platform(dir, path)?;
    // Handle must still name the same directory inode after enumeration.
    let after = open_identity(dir, path)?;
    if before != after {
        return Err(FsError::SymlinkOrReparse(path.to_path_buf()));
    }
    // Path-name revalidation: if the directory name was replaced with a
    // symlink/junction while we held the old handle, refuse to return entries
    // that may have been collected from the replacement via any path-based hop.
    match open_dir_nofollow(path) {
        Ok(probe) => {
            if ensure_not_reparse_handle(&probe, path).is_err() {
                return Err(FsError::SymlinkOrReparse(path.to_path_buf()));
            }
            let probe_id = open_identity(&probe, path)?;
            if probe_id != before {
                return Err(FsError::SymlinkOrReparse(path.to_path_buf()));
            }
        }
        Err(_) => {
            // Name no longer opens as a real directory — fail closed.
            return Err(FsError::SymlinkOrReparse(path.to_path_buf()));
        }
    }
    Ok(children)
}

fn read_dir_held_platform(dir: &File, path: &Path) -> FsResult<Vec<HeldDirChild>> {
    #[cfg(windows)]
    {
        let _ = path;
        read_dir_held_windows(dir)
    }
    #[cfg(target_os = "linux")]
    {
        // /proc/self/fd/N is a magic path that always refers to the open file
        // description, so readdir is handle-rooted while `dir` stays open.
        use std::os::unix::io::AsRawFd;
        let magic = PathBuf::from(format!("/proc/self/fd/{}", dir.as_raw_fd()));
        read_dir_path_children(&magic, path)
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        // fdopendir consumes a dup'd fd; original `dir` remains held by caller.
        read_dir_held_unix_fdopendir(dir, path)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = dir;
        read_dir_path_children(path, path)
    }
}

#[cfg_attr(windows, allow(dead_code))]
fn read_dir_path_children(enum_path: &Path, display_path: &Path) -> FsResult<Vec<HeldDirChild>> {
    let rd = fs::read_dir(enum_path).map_err(|source| FsError::Io {
        path: Some(display_path.to_path_buf()),
        source,
    })?;
    let mut out = Vec::new();
    for entry in rd {
        let entry = entry.map_err(|source| FsError::Io {
            path: Some(display_path.to_path_buf()),
            source,
        })?;
        let ft = entry.file_type().map_err(|source| FsError::Io {
            path: Some(entry.path()),
            source,
        })?;
        let meta = entry.metadata().ok();
        out.push(HeldDirChild {
            name: entry.file_name(),
            is_dir: ft.is_dir(),
            is_symlink: ft.is_symlink(),
            size: meta.and_then(|m| if m.is_file() { Some(m.len()) } else { None }),
        });
    }
    Ok(out)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn read_dir_held_unix_fdopendir(dir: &File, path: &Path) -> FsResult<Vec<HeldDirChild>> {
    use std::ffi::CStr;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::io::AsRawFd;

    // Dup so fdopendir/closedir own a distinct descriptor.
    let raw = dir.as_raw_fd();
    let dup = unsafe { libc::dup(raw) };
    if dup < 0 {
        return Err(FsError::Io {
            path: Some(path.to_path_buf()),
            source: std::io::Error::last_os_error(),
        });
    }
    let stream = unsafe { libc::fdopendir(dup) };
    if stream.is_null() {
        let err = std::io::Error::last_os_error();
        unsafe {
            let _ = libc::close(dup);
        }
        return Err(FsError::Io {
            path: Some(path.to_path_buf()),
            source: err,
        });
    }
    let mut out = Vec::new();
    loop {
        // readdir is not thread-safe; ownmeshd serializes FS ops per request.
        let ent = unsafe { libc::readdir(stream) };
        if ent.is_null() {
            break;
        }
        let d_name = unsafe { CStr::from_ptr((*ent).d_name.as_ptr()) };
        let bytes = d_name.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        let name = std::ffi::OsString::from_vec(bytes.to_vec());
        let child_path = path.join(&name);
        let (is_dir, is_symlink, size) = {
            let dtype = unsafe { (*ent).d_type };
            if dtype == libc::DT_DIR {
                (true, false, None)
            } else if dtype == libc::DT_LNK {
                (false, true, None)
            } else if dtype == libc::DT_REG {
                let sz = fs::symlink_metadata(&child_path).ok().map(|m| m.len());
                (false, false, sz)
            } else if dtype == libc::DT_UNKNOWN || dtype == 0 {
                match fs::symlink_metadata(&child_path) {
                    Ok(m) => {
                        let ft = m.file_type();
                        (
                            ft.is_dir(),
                            ft.is_symlink(),
                            if ft.is_file() { Some(m.len()) } else { None },
                        )
                    }
                    Err(_) => (false, false, None),
                }
            } else {
                (false, false, None)
            }
        };
        let _ = child_path;
        out.push(HeldDirChild {
            name,
            is_dir,
            is_symlink,
            size,
        });
    }
    unsafe {
        let _ = libc::closedir(stream);
    }
    Ok(out)
}

#[cfg(windows)]
fn read_dir_held_windows(dir: &File) -> FsResult<Vec<HeldDirChild>> {
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{
        GetLastError, ERROR_NO_MORE_FILES, FALSE, HANDLE, WIN32_ERROR,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FileIdBothDirectoryInfo, FileIdBothDirectoryRestartInfo, GetFileInformationByHandleEx,
        FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_BOTH_DIR_INFO,
    };

    #[allow(clippy::cast_possible_truncation)]
    let handle = dir.as_raw_handle() as HANDLE;
    let mut out = Vec::new();
    // 64 KiB buffer is enough for many entries per syscall without unbounded alloc.
    let mut buf = vec![0u8; 64 * 1024];
    let mut restart = true;
    loop {
        let class = if restart {
            FileIdBothDirectoryRestartInfo
        } else {
            FileIdBothDirectoryInfo
        };
        let buf_len = u32::try_from(buf.len()).unwrap_or(u32::MAX);
        let ok = unsafe {
            GetFileInformationByHandleEx(handle, class, buf.as_mut_ptr().cast(), buf_len)
        };
        if ok == FALSE {
            let err: WIN32_ERROR = unsafe { GetLastError() };
            if err == ERROR_NO_MORE_FILES {
                break;
            }
            return Err(FsError::Io {
                path: None,
                source: std::io::Error::from_raw_os_error(err.cast_signed()),
            });
        }
        restart = false;
        let mut offset = 0usize;
        loop {
            if offset + std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>() > buf.len() {
                break;
            }
            // Copy header via unaligned read — buffer is byte-aligned only.
            let mut header = FILE_ID_BOTH_DIR_INFO {
                NextEntryOffset: 0,
                FileIndex: 0,
                CreationTime: 0,
                LastAccessTime: 0,
                LastWriteTime: 0,
                ChangeTime: 0,
                EndOfFile: 0,
                AllocationSize: 0,
                FileAttributes: 0,
                FileNameLength: 0,
                EaSize: 0,
                ShortNameLength: 0,
                ShortName: [0; 12],
                FileId: 0,
                FileName: [0; 1],
            };
            // SAFETY: offset checked against buffer length above.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    buf.as_ptr().add(offset),
                    std::ptr::from_mut(&mut header).cast::<u8>(),
                    std::mem::size_of::<FILE_ID_BOTH_DIR_INFO>(),
                );
            }
            let name_bytes = usize::try_from(header.FileNameLength).unwrap_or(0);
            let name_start = offset + std::mem::offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
            let name_u16_len = name_bytes / 2;
            if name_start.saturating_add(name_bytes) > buf.len() {
                break;
            }
            // Decode UTF-16LE name without requiring u16 alignment of the byte buffer.
            let mut name_u16 = vec![0u16; name_u16_len];
            for (i, slot) in name_u16.iter_mut().enumerate() {
                let b0 = buf[name_start + i * 2];
                let b1 = buf[name_start + i * 2 + 1];
                *slot = u16::from_le_bytes([b0, b1]);
            }
            let name = std::ffi::OsString::from_wide(&name_u16);
            if name != "." && name != ".." {
                let attrs = header.FileAttributes;
                let is_reparse = attrs & FILE_ATTRIBUTE_REPARSE_POINT != 0;
                let is_dir = attrs & FILE_ATTRIBUTE_DIRECTORY != 0;
                let size = if !is_dir && !is_reparse && header.EndOfFile >= 0 {
                    Some(header.EndOfFile.cast_unsigned())
                } else {
                    None
                };
                out.push(HeldDirChild {
                    name,
                    // Treat reparse points as symlinks, not traversable dirs.
                    is_dir: is_dir && !is_reparse,
                    is_symlink: is_reparse,
                    size,
                });
            }
            if header.NextEntryOffset == 0 {
                break;
            }
            offset = offset.saturating_add(usize::try_from(header.NextEntryOffset).unwrap_or(0));
            if offset >= buf.len() {
                break;
            }
        }
    }
    Ok(out)
}

/// Recursive handle-held walk for restricted listings. Does not follow
/// symlink/reparse children as directories.
pub(crate) fn walk_dir_held<F>(
    ws: &WorkspaceRoot,
    dir: &File,
    path: &Path,
    recursive: bool,
    mut on_entry: F,
) -> FsResult<()>
where
    F: FnMut(crate::DirEntryInfo) -> FsResult<()>,
{
    fn walk_level<F>(
        ws: &WorkspaceRoot,
        dir: &File,
        path: &Path,
        recursive: bool,
        on_entry: &mut F,
    ) -> FsResult<()>
    where
        F: FnMut(crate::DirEntryInfo) -> FsResult<()>,
    {
        let children = read_dir_held(dir, path)?;
        for child in children {
            let child_path = path.join(&child.name);
            let info = crate::DirEntryInfo {
                name: child.name.to_string_lossy().into_owned(),
                path: child_path.to_string_lossy().into_owned(),
                is_dir: child.is_dir,
                is_symlink: child.is_symlink,
                size: child.size,
            };
            on_entry(info)?;
            if recursive && child.is_dir && !child.is_symlink {
                // Open child with nofollow and revalidate under workspace before descent.
                let child_dir = open_dir_nofollow(&child_path).map_err(|source| FsError::Io {
                    path: Some(child_path.clone()),
                    source,
                })?;
                ensure_not_reparse_handle(&child_dir, &child_path)?;
                let child_final = ensure_handle_under_workspace(&child_dir, ws)?;
                walk_level(ws, &child_dir, &child_final, true, on_entry)?;
            }
        }
        Ok(())
    }
    walk_level(ws, dir, path, recursive, &mut on_entry)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn relative_components_reject_escape() {
        let err = relative_components(Path::new("../x")).unwrap_err();
        assert!(matches!(err, FsError::EscapesWorkspace(_)));
    }

    #[test]
    fn read_rejects_symlink_replacement_style_escape() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"top-secret").unwrap();
        fs::write(root.path().join("safe.txt"), b"safe").unwrap();

        let ws = WorkspaceRoot::new(root.path(), true).unwrap();
        let (mut f, _) = open_regular_file_read(&ws, Path::new("safe.txt")).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "safe");

        // Replace safe.txt with a symlink/junction to the outside secret when the
        // platform supports it. Restricted read must fail closed (no secret bytes).
        fs::remove_file(root.path().join("safe.txt")).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                outside.path().join("secret.txt"),
                root.path().join("safe.txt"),
            )
            .unwrap();
            let err = open_regular_file_read(&ws, Path::new("safe.txt")).unwrap_err();
            assert!(
                matches!(
                    err,
                    FsError::SymlinkOrReparse(_)
                        | FsError::EscapesWorkspace(_)
                        | FsError::NotAFile(_)
                ),
                "symlink escape must fail closed: {err:?}"
            );
        }
        #[cfg(windows)]
        {
            // Try a Windows symlink; if the process lacks privilege, skip.
            let link = root.path().join("safe.txt");
            let target = outside.path().join("secret.txt");
            let status = std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    &link.to_string_lossy(),
                    &target.to_string_lossy(),
                ])
                .status();
            if matches!(status, Ok(s) if s.success()) {
                let err = open_regular_file_read(&ws, Path::new("safe.txt")).unwrap_err();
                assert!(
                    matches!(
                        err,
                        FsError::SymlinkOrReparse(_)
                            | FsError::EscapesWorkspace(_)
                            | FsError::NotAFile(_)
                            | FsError::Io { .. }
                    ),
                    "reparse escape must fail closed: {err:?}"
                );
            }
        }
    }

    #[test]
    fn hardlink_to_outside_file_rejected_when_enforced() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        let outside_file = outside.path().join("secret.txt");
        fs::write(&outside_file, b"top-secret").unwrap();

        let inside_link = root.path().join("alias.txt");
        #[cfg(unix)]
        {
            std::fs::hard_link(&outside_file, &inside_link).unwrap();
        }
        #[cfg(windows)]
        {
            // CreateHardLinkW via std::fs::hard_link (stable on modern Rust).
            if let Err(err) = std::fs::hard_link(&outside_file, &inside_link) {
                // Some Windows environments disallow hardlinks across dirs/volumes.
                eprintln!("skip hardlink test: {err}");
                return;
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            return;
        }

        let ws = WorkspaceRoot::new(root.path(), true).unwrap();
        let err = open_regular_file_read(&ws, Path::new("alias.txt")).unwrap_err();
        assert!(
            matches!(
                err,
                FsError::CrossBoundaryHardlink(_) | FsError::CrossMount(_)
            ),
            "outside hardlink must fail closed: {err:?}"
        );
        // Ensure we never returned outside bytes through a successful open.
        assert!(
            fs::read(&inside_link).unwrap() == b"top-secret",
            "fixture hardlink should still resolve on disk"
        );
    }

    #[test]
    fn hardlink_within_workspace_also_fail_closed_when_multi_link() {
        // Restricted policy is fail-closed on nlink>1 (no portable all-names check).
        let root = tempdir().unwrap();
        fs::write(root.path().join("a.txt"), b"shared").unwrap();
        #[cfg(unix)]
        std::fs::hard_link(root.path().join("a.txt"), root.path().join("b.txt")).unwrap();
        #[cfg(windows)]
        {
            if std::fs::hard_link(root.path().join("a.txt"), root.path().join("b.txt")).is_err() {
                return;
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            return;
        }
        let ws = WorkspaceRoot::new(root.path(), true).unwrap();
        let err = open_regular_file_read(&ws, Path::new("a.txt")).unwrap_err();
        assert!(
            matches!(err, FsError::CrossBoundaryHardlink(_)),
            "multi-link inode must fail closed in restricted mode: {err:?}"
        );
    }

    #[test]
    fn write_nested_creates_parents_component_wise_under_root() {
        let root = tempdir().unwrap();
        let ws = WorkspaceRoot::new(root.path(), true).unwrap();
        let final_path =
            write_file_enforced(&ws, Path::new("a/b/c.txt"), b"nested-ok").expect("write");
        assert!(final_path.starts_with(root.path()) || final_path.starts_with(ws.root()));
        assert_eq!(
            fs::read(root.path().join("a/b/c.txt")).unwrap(),
            b"nested-ok"
        );
    }

    #[test]
    fn write_rejects_when_parent_replaced_by_symlink_before_publish() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::create_dir_all(root.path().join("safe")).unwrap();
        let ws = WorkspaceRoot::new(root.path(), true).unwrap();

        // First write establishes custody path.
        write_file_enforced(&ws, Path::new("safe/file.txt"), b"v1").unwrap();

        // Replace parent dir with a symlink/junction pointing outside.
        let _ = fs::remove_file(root.path().join("safe/file.txt"));
        let _ = fs::remove_dir_all(root.path().join("safe"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), root.path().join("safe")).unwrap();
            let err = write_file_enforced(&ws, Path::new("safe/file.txt"), b"pwned").unwrap_err();
            assert!(
                matches!(
                    err,
                    FsError::SymlinkOrReparse(_)
                        | FsError::EscapesWorkspace(_)
                        | FsError::Io { .. }
                ),
                "symlink parent must fail closed: {err:?}"
            );
            // Outside must not receive the payload.
            assert!(
                fs::read_dir(outside.path()).unwrap().next().is_none()
                    || fs::read(outside.path().join("file.txt")).is_err(),
                "must not write outside workspace"
            );
        }
        #[cfg(windows)]
        {
            let link = root.path().join("safe");
            let target = outside.path();
            let status = std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &link.to_string_lossy(),
                    &target.to_string_lossy(),
                ])
                .status();
            if matches!(status, Ok(s) if s.success()) {
                let err =
                    write_file_enforced(&ws, Path::new("safe/file.txt"), b"pwned").unwrap_err();
                assert!(
                    matches!(
                        err,
                        FsError::SymlinkOrReparse(_)
                            | FsError::EscapesWorkspace(_)
                            | FsError::Io { .. }
                    ),
                    "junction parent must fail closed: {err:?}"
                );
            }
        }
    }

    #[test]
    fn list_dir_rename_to_outside_symlink_fails_closed() {
        use crate::list_dir_page;
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("secret.txt"), b"top-secret").unwrap();
        let sub = root.path().join("sub");
        fs::create_dir(&sub).unwrap();
        fs::write(sub.join("inside.txt"), b"safe").unwrap();
        fs::write(outside.path().join("leaked.txt"), b"leak").unwrap();

        let ws = WorkspaceRoot::new(root.path(), true).unwrap();
        let page = list_dir_page(&ws, "sub", false, 50, None).unwrap();
        assert!(page.entries.iter().any(|e| e.name == "inside.txt"));

        // Simulate TOCTOU: rename checked dir out and replace name with symlink/junction.
        let moved = root.path().join("sub-moved");
        fs::rename(&sub, &moved).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(outside.path(), root.path().join("sub")).unwrap();
            let err = list_dir_page(&ws, "sub", false, 50, None).unwrap_err();
            assert!(
                matches!(
                    err,
                    FsError::SymlinkOrReparse(_)
                        | FsError::EscapesWorkspace(_)
                        | FsError::NotADirectory(_)
                ),
                "rename-to-symlink must fail closed: {err:?}"
            );
        }
        #[cfg(windows)]
        {
            let link = root.path().join("sub");
            let ok = std::process::Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &link.to_string_lossy(),
                    &outside.path().to_string_lossy(),
                ])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                eprintln!("skip windows junction list race test (mklink failed)");
                return;
            }
            let err = list_dir_page(&ws, "sub", false, 50, None).unwrap_err();
            assert!(
                matches!(
                    err,
                    FsError::SymlinkOrReparse(_)
                        | FsError::EscapesWorkspace(_)
                        | FsError::NotADirectory(_)
                ),
                "rename-to-junction must fail closed: {err:?}"
            );
        }
    }
}
