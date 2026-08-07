//! Safe archive extraction (zip / tar.gz) with traversal and bomb prevention.

use crate::error::{UpdateError, UpdateResult};
use crate::limits::{
    ALLOWED_DOC_FILES, MAX_ARCHIVE_ENTRIES, MAX_ENTRY_UNCOMPRESSED_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES,
};
use crate::platform::{binary_file_name_for, ArchiveKind, REQUIRED_BINARIES};
use flate2::read::GzDecoder;
use std::collections::{BTreeMap, BTreeSet};
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use tar::{Archive as TarArchive, EntryType};
use zip::ZipArchive;

/// Extract required binaries (and ignore allowed docs) into memory paths.
///
/// Safety properties:
/// - Cap entry count, per-entry uncompressed bytes, and total uncompressed bytes
///   **before** unbounded allocation.
/// - Stream members with bounded reads.
/// - Permit only the five required binaries and declared documentation names.
/// - Reject duplicates, unexpected members, symlinks, devices, and path traversal.
///
/// # Errors
///
/// Returns [`UpdateError::UnsafeArchive`] on traversal, bomb limits, missing members,
/// unexpected content, or IO errors.
pub fn extract_required_binaries(
    archive_bytes: &[u8],
    kind: ArchiveKind,
    os: &str,
) -> UpdateResult<BTreeMap<String, Vec<u8>>> {
    let members = match kind {
        ArchiveKind::TarGz => read_tar_gz(archive_bytes, os)?,
        ArchiveKind::Zip => read_zip(archive_bytes, os)?,
    };

    let mut out = BTreeMap::new();
    for base in REQUIRED_BINARIES {
        let file_name = binary_file_name_for(base, os);
        let bytes = members.get(&file_name).ok_or_else(|| {
            UpdateError::UnsafeArchive(format!("archive missing required binary {file_name}"))
        })?;
        if bytes.is_empty() {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive member {file_name} is empty"
            )));
        }
        out.insert(file_name, bytes.clone());
    }
    Ok(out)
}

fn allowed_member_names(os: &str) -> BTreeSet<String> {
    let mut allowed = BTreeSet::new();
    for base in REQUIRED_BINARIES {
        allowed.insert(binary_file_name_for(base, os));
    }
    for doc in ALLOWED_DOC_FILES {
        allowed.insert((*doc).to_owned());
    }
    allowed
}

fn read_tar_gz(bytes: &[u8], os: &str) -> UpdateResult<BTreeMap<String, Vec<u8>>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = TarArchive::new(decoder);
    // Do not follow links; we reject link entry types explicitly below.
    archive.set_overwrite(false);
    let entries = archive
        .entries()
        .map_err(|err| UpdateError::UnsafeArchive(format!("tar open: {err}")))?;

    let allowed = allowed_member_names(os);
    let mut out = BTreeMap::new();
    let mut entry_count = 0usize;
    let mut total_uncompressed = 0u64;

    for entry in entries {
        entry_count = entry_count.saturating_add(1);
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive entry count exceeds limit {MAX_ARCHIVE_ENTRIES}"
            )));
        }

        let mut entry =
            entry.map_err(|err| UpdateError::UnsafeArchive(format!("tar entry: {err}")))?;
        let header = entry.header().clone();
        let entry_type = header.entry_type();

        // Skip directories and tar metadata headers (no payload we keep).
        if entry_type.is_dir() {
            continue;
        }
        match entry_type {
            EntryType::XHeader
            | EntryType::XGlobalHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink => {
                // Consume metadata payload without retaining it.
                let mut sink = std::io::sink();
                std::io::copy(&mut entry, &mut sink).map_err(|err| {
                    UpdateError::UnsafeArchive(format!("tar metadata read: {err}"))
                })?;
                continue;
            }
            EntryType::Regular | EntryType::Continuous => {}
            EntryType::Symlink | EntryType::Link => {
                return Err(UpdateError::UnsafeArchive(
                    "refusing symlink/hardlink archive member".into(),
                ));
            }
            EntryType::Char | EntryType::Block | EntryType::Fifo | EntryType::GNUSparse => {
                return Err(UpdateError::UnsafeArchive(format!(
                    "refusing special archive member type {entry_type:?}"
                )));
            }
            other => {
                return Err(UpdateError::UnsafeArchive(format!(
                    "refusing unknown archive member type {other:?}"
                )));
            }
        }

        let path = entry
            .path()
            .map_err(|err| UpdateError::UnsafeArchive(format!("tar path: {err}")))?
            .into_owned();
        let name = safe_member_name(&path)?;
        if !allowed.contains(&name) {
            return Err(UpdateError::UnsafeArchive(format!(
                "refusing unexpected archive member {name}"
            )));
        }
        if out.contains_key(&name) {
            return Err(UpdateError::UnsafeArchive(format!(
                "refusing duplicate archive member {name}"
            )));
        }

        let declared = header.size().unwrap_or(0);
        if declared > MAX_ENTRY_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive member {name} exceeds per-entry limit {MAX_ENTRY_UNCOMPRESSED_BYTES}"
            )));
        }
        if total_uncompressed.saturating_add(declared) > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive total uncompressed size exceeds limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"
            )));
        }

        let data = read_bounded(&mut entry, name.as_str(), declared)?;
        total_uncompressed = total_uncompressed.saturating_add(data.len() as u64);
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive total uncompressed size exceeds limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"
            )));
        }
        out.insert(name, data);
    }

    Ok(out)
}

fn read_zip(bytes: &[u8], os: &str) -> UpdateResult<BTreeMap<String, Vec<u8>>> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|err| UpdateError::UnsafeArchive(format!("zip open: {err}")))?;

    if archive.len() > MAX_ARCHIVE_ENTRIES {
        return Err(UpdateError::UnsafeArchive(format!(
            "archive entry count exceeds limit {MAX_ARCHIVE_ENTRIES}"
        )));
    }

    let allowed = allowed_member_names(os);
    let mut out = BTreeMap::new();
    let mut total_uncompressed = 0u64;

    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| UpdateError::UnsafeArchive(format!("zip entry: {err}")))?;

        // Symlink / unix mode checks: zip crate exposes unix_mode when present.
        if let Some(mode) = file.unix_mode() {
            const S_IFMT: u32 = 0o170_000;
            const S_IFLNK: u32 = 0o120_000;
            const S_IFREG: u32 = 0o100_000;
            const S_IFDIR: u32 = 0o040_000;
            let file_type = mode & S_IFMT;
            if file_type == S_IFLNK {
                return Err(UpdateError::UnsafeArchive(
                    "refusing symlink archive member".into(),
                ));
            }
            if file_type != 0 && file_type != S_IFREG && file_type != S_IFDIR {
                return Err(UpdateError::UnsafeArchive(format!(
                    "refusing special zip member mode {mode:#o}"
                )));
            }
        }

        if file.is_dir() {
            continue;
        }

        let raw_name = file.name().to_owned();
        // Zip slip: enclosed_name is None for absolute / traversal names.
        if file.enclosed_name().is_none() {
            return Err(UpdateError::UnsafeArchive(format!(
                "refusing unsafe zip member name {raw_name}"
            )));
        }
        let name = safe_member_name(Path::new(&raw_name))?;
        if !allowed.contains(&name) {
            return Err(UpdateError::UnsafeArchive(format!(
                "refusing unexpected archive member {name}"
            )));
        }
        if out.contains_key(&name) {
            return Err(UpdateError::UnsafeArchive(format!(
                "refusing duplicate archive member {name}"
            )));
        }

        let declared = file.size();
        if declared > MAX_ENTRY_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive member {name} exceeds per-entry limit {MAX_ENTRY_UNCOMPRESSED_BYTES}"
            )));
        }
        if total_uncompressed.saturating_add(declared) > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive total uncompressed size exceeds limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"
            )));
        }

        let data = read_bounded(&mut file, name.as_str(), declared)?;
        total_uncompressed = total_uncompressed.saturating_add(data.len() as u64);
        if total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive total uncompressed size exceeds limit {MAX_TOTAL_UNCOMPRESSED_BYTES}"
            )));
        }
        out.insert(name, data);
    }

    Ok(out)
}

/// Read member bytes with a hard cap; reject expansion past declared/per-entry limits.
fn read_bounded<R: Read>(reader: &mut R, name: &str, declared: u64) -> UpdateResult<Vec<u8>> {
    let mut data = Vec::new();
    let mut buf = vec![0u8; 8 * 1024];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|err| UpdateError::UnsafeArchive(format!("read {name}: {err}")))?;
        if n == 0 {
            break;
        }
        let next = (data.len() as u64).saturating_add(n as u64);
        if next > MAX_ENTRY_UNCOMPRESSED_BYTES {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive member {name} exceeds per-entry limit {MAX_ENTRY_UNCOMPRESSED_BYTES}"
            )));
        }
        if declared > 0 && next > declared {
            return Err(UpdateError::UnsafeArchive(format!(
                "archive member {name} expanded past declared size {declared}"
            )));
        }
        data.extend_from_slice(&buf[..n]);
    }
    Ok(data)
}

/// Accept only a single-component relative file name (no dirs, no absolute, no `..`).
fn safe_member_name(path: &Path) -> UpdateResult<String> {
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => {
                let s = part.to_string_lossy();
                if s.is_empty() || s == "." || s == ".." {
                    return Err(UpdateError::UnsafeArchive(format!(
                        "refusing archive member {}",
                        path.display()
                    )));
                }
                if s.contains('\\') {
                    return Err(UpdateError::UnsafeArchive(format!(
                        "refusing archive member {}",
                        path.display()
                    )));
                }
                components.push(s.into_owned());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(UpdateError::UnsafeArchive(format!(
                    "refusing archive member {}",
                    path.display()
                )));
            }
        }
    }
    // Allow optional single top-level directory wrapper: `ownmesh-…/ownmesh`.
    let name = match components.as_slice() {
        [file] | [_, file] => file.clone(),
        _ => {
            return Err(UpdateError::UnsafeArchive(format!(
                "refusing nested archive member {}",
                path.display()
            )));
        }
    };
    if name.contains('/') || name.contains('\\') || name.contains("..") {
        return Err(UpdateError::UnsafeArchive(format!(
            "refusing archive member name {name}"
        )));
    }
    let _ = PathBuf::from(&name);
    Ok(name)
}
