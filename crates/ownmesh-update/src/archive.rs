//! Safe archive extraction (zip / tar.gz) with traversal prevention.

use crate::error::{UpdateError, UpdateResult};
use crate::platform::{binary_file_name_for, ArchiveKind, REQUIRED_BINARIES};
use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::{Cursor, Read};
use std::path::{Component, Path, PathBuf};
use tar::Archive as TarArchive;
use zip::ZipArchive;

/// Extract required binaries (and ignore docs) into memory paths.
///
/// # Errors
///
/// Returns [`UpdateError::UnsafeArchive`] on traversal, missing members, or IO errors.
pub fn extract_required_binaries(
    archive_bytes: &[u8],
    kind: ArchiveKind,
    os: &str,
) -> UpdateResult<BTreeMap<String, Vec<u8>>> {
    let members = match kind {
        ArchiveKind::TarGz => read_tar_gz(archive_bytes)?,
        ArchiveKind::Zip => read_zip(archive_bytes)?,
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

fn read_tar_gz(bytes: &[u8]) -> UpdateResult<BTreeMap<String, Vec<u8>>> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = TarArchive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|err| UpdateError::UnsafeArchive(format!("tar open: {err}")))?;
    let mut out = BTreeMap::new();
    for entry in entries {
        let mut entry =
            entry.map_err(|err| UpdateError::UnsafeArchive(format!("tar entry: {err}")))?;
        let path = entry
            .path()
            .map_err(|err| UpdateError::UnsafeArchive(format!("tar path: {err}")))?
            .into_owned();
        let name = safe_member_name(&path)?;
        if entry.header().entry_type().is_dir() {
            continue;
        }
        let mut data = Vec::new();
        entry
            .read_to_end(&mut data)
            .map_err(|err| UpdateError::UnsafeArchive(format!("tar read {name}: {err}")))?;
        out.insert(name, data);
    }
    Ok(out)
}

fn read_zip(bytes: &[u8]) -> UpdateResult<BTreeMap<String, Vec<u8>>> {
    let cursor = Cursor::new(bytes);
    let mut archive = ZipArchive::new(cursor)
        .map_err(|err| UpdateError::UnsafeArchive(format!("zip open: {err}")))?;
    let mut out = BTreeMap::new();
    for index in 0..archive.len() {
        let mut file = archive
            .by_index(index)
            .map_err(|err| UpdateError::UnsafeArchive(format!("zip entry: {err}")))?;
        if file.is_dir() {
            continue;
        }
        let raw_name = file.name().to_owned();
        let name = safe_member_name(Path::new(&raw_name))?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|err| UpdateError::UnsafeArchive(format!("zip read {name}: {err}")))?;
        out.insert(name, data);
    }
    Ok(out)
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
