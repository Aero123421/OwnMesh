//! Safe archive extraction (zip / tar.gz) with traversal and bomb prevention.

use crate::error::{UpdateError, UpdateResult};
use crate::limits::{
    ALLOWED_DOC_FILES, MAX_ARCHIVE_ENTRIES, MAX_ENTRY_UNCOMPRESSED_BYTES,
    MAX_TAR_METADATA_ENTRY_BYTES, MAX_TOTAL_UNCOMPRESSED_BYTES,
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
    let mut entries = archive
        .entries()
        .map_err(|err| UpdateError::UnsafeArchive(format!("tar open: {err}")))?;
    // tar::Entries normally consumes GNU/PAX extension records internally and
    // exposes only the following logical member. Raw iteration is required so
    // every metadata byte reaches our bounded accounting path first.
    entries.raw(true);

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

        // TAR metadata and ignored directory payloads are still decompressed
        // bytes. Charge them to the same archive-wide budget and apply a small
        // independent per-record ceiling before discarding them.
        if entry_type.is_dir() {
            drain_tar_entry_bounded(
                &mut entry,
                "tar directory metadata",
                header.size().unwrap_or(0),
                MAX_TAR_METADATA_ENTRY_BYTES,
                &mut total_uncompressed,
            )?;
            continue;
        }
        match entry_type {
            EntryType::XHeader
            | EntryType::XGlobalHeader
            | EntryType::GNULongName
            | EntryType::GNULongLink => {
                drain_tar_entry_bounded(
                    &mut entry,
                    "tar metadata",
                    header.size().unwrap_or(0),
                    MAX_TAR_METADATA_ENTRY_BYTES,
                    &mut total_uncompressed,
                )?;
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
            return Err(UpdateError::LimitExceeded(format!(
                "archive total uncompressed size exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
            )));
        }

        let data = read_tar_entry_bounded(
            &mut entry,
            name.as_str(),
            declared,
            MAX_ENTRY_UNCOMPRESSED_BYTES,
            &mut total_uncompressed,
            true,
        )?;
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

/// Read a TAR entry with independent per-entry and shared aggregate budgets.
fn read_tar_entry_bounded<R: Read>(
    reader: &mut R,
    label: &str,
    declared: u64,
    per_entry_limit: u64,
    total_uncompressed: &mut u64,
    retain: bool,
) -> UpdateResult<Vec<u8>> {
    if declared > per_entry_limit {
        return Err(UpdateError::LimitExceeded(format!(
            "{label} exceeds per-entry limit {per_entry_limit} bytes"
        )));
    }
    if total_uncompressed.saturating_add(declared) > MAX_TOTAL_UNCOMPRESSED_BYTES {
        return Err(UpdateError::LimitExceeded(format!(
            "archive total uncompressed size exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
        )));
    }

    let mut data = if retain { Vec::new() } else { Vec::with_capacity(0) };
    let mut buf = [0u8; 8 * 1024];
    let mut entry_read = 0u64;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|err| UpdateError::UnsafeArchive(format!("read {label}: {err}")))?;
        if n == 0 {
            break;
        }
        let n = n as u64;
        entry_read = entry_read.checked_add(n).ok_or_else(|| {
            UpdateError::LimitExceeded("tar entry byte counter overflow".into())
        })?;
        if entry_read > per_entry_limit {
            return Err(UpdateError::LimitExceeded(format!(
                "{label} exceeds per-entry limit {per_entry_limit} bytes"
            )));
        }
        if declared > 0 && entry_read > declared {
            return Err(UpdateError::UnsafeArchive(format!(
                "{label} expanded past declared size {declared}"
            )));
        }
        *total_uncompressed = total_uncompressed.checked_add(n).ok_or_else(|| {
            UpdateError::LimitExceeded("archive byte counter overflow".into())
        })?;
        if *total_uncompressed > MAX_TOTAL_UNCOMPRESSED_BYTES {
            return Err(UpdateError::LimitExceeded(format!(
                "archive total uncompressed size exceeds {MAX_TOTAL_UNCOMPRESSED_BYTES} bytes"
            )));
        }
        if retain {
            data.extend_from_slice(&buf[..n as usize]);
        }
    }
    Ok(data)
}

fn drain_tar_entry_bounded<R: Read>(
    reader: &mut R,
    label: &str,
    declared: u64,
    per_entry_limit: u64,
    total_uncompressed: &mut u64,
) -> UpdateResult<()> {
    // Reuse the exact accounting path. Metadata is capped at 64 KiB, so the
    // temporary bounded buffer cannot become attacker-controlled large memory.
    let _ = read_tar_entry_bounded(
        reader,
        label,
        declared,
        per_entry_limit,
        total_uncompressed,
        false,
    )?;
    Ok(())
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


#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{write::GzEncoder, Compression};
    use tar::{Builder, Header};

    fn metadata_archive(entry_type: EntryType, payload_len: usize) -> Vec<u8> {
        let encoder = GzEncoder::new(Vec::new(), Compression::fast());
        let mut builder = Builder::new(encoder);
        let payload = vec![b'x'; payload_len];
        let mut header = Header::new_gnu();
        header.set_entry_type(entry_type);
        header.set_mode(0o600);
        header.set_size(payload.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "metadata", payload.as_slice())
            .expect("append metadata entry");
        let encoder = builder.into_inner().expect("finish tar");
        encoder.finish().expect("finish gzip")
    }

    #[test]
    fn oversized_tar_extension_records_are_bounded_before_discard() {
        for entry_type in [
            EntryType::XHeader,
            EntryType::XGlobalHeader,
            EntryType::GNULongName,
            EntryType::GNULongLink,
        ] {
            let archive = metadata_archive(
                entry_type,
                (MAX_TAR_METADATA_ENTRY_BYTES + 1) as usize,
            );
            let error = read_tar_gz(&archive, "linux").expect_err("metadata must be rejected");
            assert!(matches!(error, UpdateError::LimitExceeded(_)));
            let message = error.to_string();
            assert!(message.contains("tar metadata"));
            assert!(!message.contains(&"x".repeat(128)));
        }
    }

    #[test]
    fn metadata_bytes_share_the_archive_wide_budget() {
        let mut total = MAX_TOTAL_UNCOMPRESSED_BYTES - 8;
        let mut cursor = Cursor::new([0u8; 9]);
        let error = drain_tar_entry_bounded(
            &mut cursor,
            "tar metadata",
            9,
            MAX_TAR_METADATA_ENTRY_BYTES,
            &mut total,
        )
        .expect_err("aggregate metadata budget must be enforced");
        assert!(matches!(error, UpdateError::LimitExceeded(_)));
    }

    #[test]
    fn valid_small_metadata_is_charged_exactly_once() {
        let mut total = 3;
        let mut cursor = Cursor::new([1u8, 2, 3, 4]);
        drain_tar_entry_bounded(
            &mut cursor,
            "tar metadata",
            4,
            MAX_TAR_METADATA_ENTRY_BYTES,
            &mut total,
        )
        .expect("small metadata should fit");
        assert_eq!(total, 7);
    }
}
