//! Handle-bound executable preparation and launch.
//!
//! The approval-time pins are path-based durable facts. Preparation opens the
//! invocation and canonical backing, revalidates both against those facts, and
//! then retains the exact image object used by the launcher. No prepared launch
//! re-resolves an attacker-writable invocation. macOS platform binaries are the
//! narrow exception to private-image execution: their verified system backing
//! path is immutable to the daemon and is launched with the approved argv0.

#[cfg(target_os = "linux")]
use super::verify_open_file_metadata_pin;
#[cfg(not(target_os = "linux"))]
use super::{open_file_identity, verify_open_file_pin};
use super::{
    verify_path_entry_pin, CommandKind, ExecError, ExecResult, ExecutablePin, RunRequest,
    ShebangInterpreterPin,
};
#[cfg(target_os = "linux")]
use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::ffi::{CString, OsString};
use std::fs::File;
#[cfg(not(any(target_os = "linux", windows)))]
use std::fs::OpenOptions;
#[cfg(not(any(target_os = "linux", windows)))]
use std::io::{Read, Seek, SeekFrom, Write};
#[cfg(target_os = "linux")]
use std::io::{Seek, SeekFrom};
use std::path::Path;
#[cfg(not(target_os = "linux"))]
use std::path::PathBuf;
use std::process::Stdio;
use tokio::process::Command;

/// A verified executable image whose lifetime spans the OS image-open step.
///
/// This type is deliberately neither cloneable nor serializable. Durable
/// approval state stores [`ExecutablePin`] values; each execution attempt must
/// create a fresh prepared object and consume it exactly once.
pub struct PreparedExecutable {
    approved_argv0: String,
    image: PreparedImage,
}

enum PreparedImage {
    #[cfg(target_os = "linux")]
    Descriptor(File),
    #[cfg(target_os = "linux")]
    Script {
        script: File,
        script_origin: String,
        interpreter: File,
        interpreter_argv0: String,
        interpreter_args: Vec<String>,
    },
    #[cfg(windows)]
    LockedPath(WindowsPathCustody),
    #[cfg(target_os = "macos")]
    RestrictedPath(MacOsRestrictedPathCustody),
    #[cfg(not(any(target_os = "linux", windows)))]
    Snapshot(SnapshotCustody),
}

#[cfg(target_os = "macos")]
struct MacOsRestrictedPathCustody {
    launcher_path: PathBuf,
    // A macOS platform binary cannot be executed from a byte-for-byte private
    // copy on recent macOS releases. The original image and its immutable
    // root-owned ancestor chain stay open while posix_spawn opens the verified
    // backing path. The approved invocation remains argv[0].
    _invocation: File,
    _backing: File,
    _ancestors: Vec<File>,
}

#[cfg(windows)]
struct WindowsPathCustody {
    invocation_path: PathBuf,
    launcher_path: PathBuf,
    batch_wrapper: bool,
    // Target and directory-entry handles are opened without write/delete
    // sharing. CreateProcess may read the image, but an attacker cannot
    // replace either the proxy entry or its backing until spawn has opened it.
    _invocation: File,
    _invocation_entry: File,
    _backing: File,
    _backing_entry: File,
    _launcher: Option<File>,
    _launcher_entry: Option<File>,
    _ancestors: Vec<File>,
}

#[cfg(not(any(target_os = "linux", windows)))]
struct SnapshotCustody {
    path: PathBuf,
    directory: PathBuf,
    // On macOS the create-new image handle plus the owner-only, randomly named
    // directory is the custody boundary through the image-open step.
    _image: File,
    _directory: File,
}

#[cfg(not(any(target_os = "linux", windows)))]
impl Drop for SnapshotCustody {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_dir(&self.directory);
    }
}

/// Open and revalidate the approved invocation/backing relationship, returning
/// an object that can be consumed only by [`run_prepared_command_cancellable`](
/// crate::run_prepared_command_cancellable).
///
/// `staging_root` is required on targets that may use snapshot execution. It
/// must be an already custody-validated owner directory (the daemon runtime
/// dir).
pub fn prepare_executable(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    staging_root: Option<&Path>,
) -> ExecResult<PreparedExecutable> {
    prepare_executable_inner(
        invocation_path,
        invocation_pin,
        backing_pin,
        None,
        None,
        staging_root,
    )
}

/// Prepare an executable plus an explicitly approved interpreter when the
/// platform launch contract requires one (currently Windows `.cmd`/`.bat`).
/// Native executables ignore `interpreter_pin`.
pub fn prepare_executable_with_interpreter(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    interpreter_pin: Option<&ExecutablePin>,
    staging_root: Option<&Path>,
) -> ExecResult<PreparedExecutable> {
    prepare_executable_inner(
        invocation_path,
        invocation_pin,
        backing_pin,
        interpreter_pin,
        None,
        staging_root,
    )
}

/// Prepare a shebang script together with the exact effective interpreter
/// pinned during admission. Linux launches the pinned interpreter image and
/// retains the original verified script in a sealed inherited descriptor.
/// Node maps those sealed bytes to the approved module URL through a bounded
/// loader, preserving its real module directory without trusting the script
/// pathname as source again.
pub fn prepare_executable_with_shebang(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    shebang_pin: Option<&ShebangInterpreterPin>,
    staging_root: Option<&Path>,
) -> ExecResult<PreparedExecutable> {
    prepare_executable_inner(
        invocation_path,
        invocation_pin,
        backing_pin,
        None,
        shebang_pin,
        staging_root,
    )
}

fn validate_preparation_contract(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
) -> ExecResult<()> {
    if !invocation_path.is_absolute()
        || !Path::new(&invocation_pin.path).is_absolute()
        || !Path::new(&backing_pin.path).is_absolute()
    {
        return Err(ExecError::Journal(
            "prepared executable paths must be absolute; request must be re-authorized".into(),
        ));
    }
    if invocation_path != Path::new(&invocation_pin.path) {
        return Err(ExecError::Journal(
            "approved argv0 does not match the invocation pin path".into(),
        ));
    }
    if invocation_pin.policy_kind != backing_pin.policy_kind {
        return Err(ExecError::Journal(
            "invocation/backing policy classification mismatch".into(),
        ));
    }
    Ok(())
}

fn prepare_executable_inner(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    interpreter_pin: Option<&ExecutablePin>,
    shebang_pin: Option<&ShebangInterpreterPin>,
    staging_root: Option<&Path>,
) -> ExecResult<PreparedExecutable> {
    #[cfg(any(target_os = "linux", windows))]
    let _ = staging_root;
    #[cfg(not(windows))]
    let _ = interpreter_pin;
    #[cfg(not(target_os = "linux"))]
    let _ = shebang_pin;
    validate_preparation_contract(invocation_path, invocation_pin, backing_pin)?;

    verify_path_entry_pin(invocation_path, invocation_pin)?;
    verify_path_entry_pin(Path::new(&backing_pin.path), backing_pin)?;

    #[cfg(windows)]
    let invocation_entry = open_windows_entry_custody(invocation_path).map_err(|error| {
        ExecError::Journal(format!(
            "lock approved invocation entry for preparation failed: {error}"
        ))
    })?;
    #[cfg(windows)]
    let mut ancestors = lock_windows_ancestor_chain(invocation_path)?;
    let invocation = open_approved_invocation(invocation_path)?;
    #[cfg(not(target_os = "linux"))]
    let mut invocation = invocation;
    #[cfg(target_os = "linux")]
    {
        // Linux hashes the exact bytes while copying them into the sealed
        // memfd below. Metadata checks here bind the opened invocation to both
        // approved path identities without reading a large runtime three
        // additional times before the same copy.
        verify_open_file_metadata_pin(&invocation, invocation_path, invocation_pin)?;
        verify_open_file_metadata_pin(&invocation, invocation_path, backing_pin)?;
    }
    #[cfg(not(target_os = "linux"))]
    {
        verify_open_file_pin(&mut invocation, invocation_path, invocation_pin)?;
        // The executable object reached through the invocation must be the
        // exact approved backing object, not merely an object with same bytes.
        verify_open_file_pin(&mut invocation, invocation_path, backing_pin)?;
    }

    let backing_path = Path::new(&backing_pin.path);
    #[cfg(windows)]
    let backing_entry = open_windows_entry_custody(backing_path).map_err(|error| {
        ExecError::Journal(format!(
            "lock approved backing entry for preparation failed: {error}"
        ))
    })?;
    #[cfg(windows)]
    ancestors.extend(lock_windows_ancestor_chain(backing_path)?);
    #[cfg(not(target_os = "linux"))]
    let backing = {
        let mut backing = open_execution_target(backing_path).map_err(|error| {
            ExecError::Journal(format!(
                "open approved canonical backing for preparation failed: {error}"
            ))
        })?;
        verify_open_file_pin(&mut backing, backing_path, backing_pin)?;
        if open_file_identity(&invocation)? != open_file_identity(&backing)? {
            return Err(ExecError::Journal(
                "invocation no longer resolves to the approved backing identity".into(),
            ));
        }
        backing
    };

    verify_path_entry_pin(invocation_path, invocation_pin)?;
    verify_path_entry_pin(backing_path, backing_pin)?;

    #[cfg(target_os = "linux")]
    let image = finish_linux_custody(
        invocation_path,
        invocation_pin,
        backing_pin,
        shebang_pin,
        invocation,
    )?;
    #[cfg(windows)]
    let image = finish_windows_custody(
        invocation_path,
        interpreter_pin,
        invocation,
        invocation_entry,
        backing,
        backing_entry,
        ancestors,
    )?;
    #[cfg(target_os = "macos")]
    let image = finish_macos_custody(
        invocation_path,
        invocation_pin,
        backing_pin,
        invocation,
        backing,
        staging_root.ok_or_else(|| {
            ExecError::Journal("prepared executable staging root is required on this OS".into())
        })?,
    )?;
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let image = PreparedImage::Snapshot(stage_verified_image(
        &mut invocation,
        invocation_path,
        backing_pin,
        staging_root.ok_or_else(|| {
            ExecError::Journal("prepared executable staging root is required on this OS".into())
        })?,
    )?);

    Ok(PreparedExecutable {
        approved_argv0: invocation_path.to_string_lossy().into_owned(),
        image,
    })
}

#[cfg(target_os = "linux")]
fn finish_linux_custody(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    shebang_pin: Option<&ShebangInterpreterPin>,
    mut invocation: File,
) -> ExecResult<PreparedImage> {
    let has_shebang = super::file_has_shebang(&mut invocation)?;
    if invocation_pin.policy_kind == super::CommandKind::Structured.as_str()
        && (has_shebang
            || invocation_path
                .to_str()
                .is_some_and(super::script_extension))
    {
        return Err(ExecError::Journal(
            "executable became a script/shebang payload before execution; request must be re-authorized"
                .into(),
        ));
    }
    if has_shebang {
        return prepare_linux_script(invocation, backing_pin, shebang_pin);
    }
    if shebang_pin.is_some() {
        return Err(ExecError::Journal(
            "approved shebang contract no longer matches a native executable".into(),
        ));
    }
    Ok(PreparedImage::Descriptor(stage_linux_memfd(
        &mut invocation,
        backing_pin,
        true,
    )?))
}

#[cfg(target_os = "linux")]
fn stage_linux_memfd(
    source: &mut File,
    backing_pin: &ExecutablePin,
    close_on_exec: bool,
) -> ExecResult<File> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use sha2::{Digest, Sha256};
    use std::io::{Read as _, Write as _};
    use std::os::unix::fs::PermissionsExt;

    let mut base_flags = MemfdFlags::ALLOW_SEALING;
    if close_on_exec {
        base_flags |= MemfdFlags::CLOEXEC;
    }
    let descriptor = match memfd_create("ownmesh-prepared", base_flags | MemfdFlags::EXEC) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::INVAL) => memfd_create("ownmesh-prepared", base_flags)
            .map_err(|error| ExecError::Io(error.into()))?,
        Err(error) => return Err(ExecError::Io(error.into())),
    };
    if backing_pin.len > super::MAX_EXECUTABLE_PIN_BYTES {
        return Err(ExecError::ResourceLimit(format!(
            "executable exceeds {} byte preparation budget: {}",
            super::MAX_EXECUTABLE_PIN_BYTES,
            backing_pin.path
        )));
    }
    let mut image = File::from(descriptor);
    source.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut copied = 0_u64;
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        copied = copied.saturating_add(count as u64);
        if copied > super::MAX_EXECUTABLE_PIN_BYTES {
            return Err(ExecError::ResourceLimit(format!(
                "executable exceeded {} byte preparation budget: {}",
                super::MAX_EXECUTABLE_PIN_BYTES,
                backing_pin.path
            )));
        }
        hasher.update(&buffer[..count]);
        image.write_all(&buffer[..count])?;
    }
    if copied != backing_pin.len {
        return Err(ExecError::Journal(
            "prepared Linux image length does not match the approved pin".into(),
        ));
    }
    let digest = hex::encode(hasher.finalize());
    if digest != backing_pin.content_sha256 {
        return Err(ExecError::Journal(
            "prepared Linux image content does not match the approved executable".into(),
        ));
    }
    image.sync_all()?;
    image.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    fcntl_add_seals(
        &image,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .map_err(|error| ExecError::Io(error.into()))?;
    image.seek(SeekFrom::Start(0))?;
    Ok(image)
}

#[cfg(target_os = "linux")]
fn prepare_linux_script(
    mut script: File,
    script_pin: &ExecutablePin,
    shebang_pin: Option<&ShebangInterpreterPin>,
) -> ExecResult<PreparedImage> {
    let shebang = shebang_pin.ok_or_else(|| {
        ExecError::Journal(
            "shebang script lacks an approved interpreter identity; request must be re-authorized"
                .into(),
        )
    })?;
    if shebang.script_content_sha256 != script_pin.content_sha256 {
        return Err(ExecError::Journal(
            "shebang interpreter was approved for different script content".into(),
        ));
    }
    let Some((parsed_interpreter, parsed_args)) =
        super::parse_shebang_interpreter_from_file(&mut script)?
    else {
        return Err(ExecError::Journal(
            "approved shebang contract no longer matches a script".into(),
        ));
    };
    if parsed_interpreter != Path::new(&shebang.invocation.path) || parsed_args != shebang.args {
        return Err(ExecError::Journal(
            "approved shebang interpreter contract does not match the verified script bytes".into(),
        ));
    }
    super::verify_path_entry_pin(Path::new(&shebang.invocation.path), &shebang.invocation)?;
    super::verify_path_entry_pin(Path::new(&shebang.backing.path), &shebang.backing)?;
    let mut interpreter =
        open_execution_target(Path::new(&shebang.invocation.path)).map_err(|error| {
            ExecError::Journal(format!("open approved shebang interpreter failed: {error}"))
        })?;
    super::verify_open_file_metadata_pin(
        &interpreter,
        Path::new(&shebang.invocation.path),
        &shebang.invocation,
    )?;
    super::verify_open_file_metadata_pin(
        &interpreter,
        Path::new(&shebang.invocation.path),
        &shebang.backing,
    )?;
    super::verify_path_entry_pin(Path::new(&shebang.invocation.path), &shebang.invocation)?;
    super::verify_path_entry_pin(Path::new(&shebang.backing.path), &shebang.backing)?;
    if super::file_has_shebang(&mut interpreter)? {
        return Err(ExecError::Journal(
            "nested shebang interpreter changed before execution".into(),
        ));
    }
    let prepared_interpreter = stage_linux_memfd(&mut interpreter, &shebang.backing, true)?;
    // Script bytes stay in a separately sealed descriptor inherited by the
    // interpreter. Unlike a filesystem lease, memfd seals cannot be timed out
    // or broken by another process. Node receives a loader below that maps the
    // sealed bytes to the approved original module URL, preserving relative
    // imports without reopening the mutable script as source.
    let prepared_script = stage_linux_memfd(&mut script, script_pin, false)?;

    Ok(PreparedImage::Script {
        script: prepared_script,
        script_origin: script_pin.path.clone(),
        interpreter: prepared_interpreter,
        interpreter_argv0: shebang.invocation.path.clone(),
        interpreter_args: shebang.args.clone(),
    })
}

fn open_approved_invocation(path: &Path) -> ExecResult<File> {
    open_execution_target(path).map_err(|error| {
        ExecError::Journal(format!(
            "open approved invocation for preparation failed: {error}"
        ))
    })
}

#[cfg(not(windows))]
fn open_execution_target(path: &Path) -> std::io::Result<File> {
    File::open(path)
}

#[cfg(windows)]
fn open_execution_target(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_SHARE_READ;
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .open(path)
}

#[cfg(windows)]
fn open_windows_entry_custody(path: &Path) -> std::io::Result<File> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };
    std::fs::OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
}

#[cfg(windows)]
fn lock_windows_ancestor_chain(path: &Path) -> ExecResult<Vec<File>> {
    let mut locked = Vec::new();
    let mut ancestor = path.parent();
    while let Some(directory) = ancestor {
        if directory.as_os_str().is_empty() {
            break;
        }
        locked.push(open_windows_entry_custody(directory).map_err(|error| {
            ExecError::Journal(format!(
                "lock executable ancestor {} failed: {error}",
                directory.display()
            ))
        })?);
        let parent = directory.parent();
        if parent == Some(directory) {
            break;
        }
        ancestor = parent;
    }
    Ok(locked)
}

#[cfg(windows)]
fn is_windows_batch(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("cmd") || extension.eq_ignore_ascii_case("bat")
        })
}

#[cfg(windows)]
fn finish_windows_custody(
    invocation_path: &Path,
    interpreter_pin: Option<&ExecutablePin>,
    invocation: File,
    invocation_entry: File,
    backing: File,
    backing_entry: File,
    mut ancestors: Vec<File>,
) -> ExecResult<PreparedImage> {
    let batch_wrapper = is_windows_batch(invocation_path);
    let (launcher_path, launcher, launcher_entry) = if batch_wrapper {
        let pin = interpreter_pin.ok_or_else(|| {
            ExecError::Journal(
                "approved Windows batch invocation lacks its cmd.exe interpreter pin".into(),
            )
        })?;
        let path = PathBuf::from(&pin.path);
        if !path.is_absolute() || pin.policy_kind != CommandKind::RawShell.as_str() {
            return Err(ExecError::Journal(
                "approved Windows batch interpreter pin is invalid".into(),
            ));
        }
        verify_path_entry_pin(&path, pin)?;
        let entry = open_windows_entry_custody(&path).map_err(|error| {
            ExecError::Journal(format!(
                "lock approved Windows batch interpreter entry failed: {error}"
            ))
        })?;
        ancestors.extend(lock_windows_ancestor_chain(&path)?);
        let mut file = open_execution_target(&path).map_err(|error| {
            ExecError::Journal(format!(
                "open approved Windows batch interpreter failed: {error}"
            ))
        })?;
        verify_open_file_pin(&mut file, &path, pin)?;
        verify_path_entry_pin(&path, pin)?;
        (path, Some(file), Some(entry))
    } else {
        (invocation_path.to_path_buf(), None, None)
    };
    Ok(PreparedImage::LockedPath(WindowsPathCustody {
        invocation_path: invocation_path.to_path_buf(),
        launcher_path,
        batch_wrapper,
        _invocation: invocation,
        _invocation_entry: invocation_entry,
        _backing: backing,
        _backing_entry: backing_entry,
        _launcher: launcher,
        _launcher_entry: launcher_entry,
        _ancestors: ancestors,
    }))
}

#[cfg(target_os = "macos")]
fn finish_macos_custody(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    mut invocation: File,
    mut backing: File,
    staging_root: &Path,
) -> ExecResult<PreparedImage> {
    if let Some(ancestors) = macos_restricted_path_custody(
        invocation_path,
        invocation_pin,
        backing_pin,
        &mut invocation,
        &mut backing,
    )? {
        return Ok(PreparedImage::RestrictedPath(MacOsRestrictedPathCustody {
            launcher_path: PathBuf::from(&backing_pin.path),
            _invocation: invocation,
            _backing: backing,
            _ancestors: ancestors,
        }));
    }

    Ok(PreparedImage::Snapshot(stage_verified_image(
        &mut invocation,
        invocation_path,
        backing_pin,
        staging_root,
    )?))
}

#[cfg(target_os = "macos")]
fn macos_restricted_path_custody(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    invocation: &mut File,
    backing: &mut File,
) -> ExecResult<Option<Vec<File>>> {
    use std::os::macos::fs::MetadataExt as MacOsMetadataExt;
    use std::os::unix::fs::MetadataExt as UnixMetadataExt;

    // SF_RESTRICTED is the Darwin system-immutable flag from <sys/stat.h>.
    // Ordinary user-owned executables stay on the independent snapshot path.
    const SF_RESTRICTED: u32 = 0x0008_0000;
    let metadata = backing.metadata()?;
    if MacOsMetadataExt::st_flags(&metadata) & SF_RESTRICTED == 0 {
        return Ok(None);
    }
    if !metadata.is_file()
        || UnixMetadataExt::uid(&metadata) != 0
        || UnixMetadataExt::mode(&metadata) & 0o022 != 0
    {
        return Err(ExecError::Journal(
            "restricted macOS executable lacks root-owned immutable custody".into(),
        ));
    }

    let backing_path = Path::new(&backing_pin.path);
    if std::fs::canonicalize(backing_path)? != backing_path {
        return Err(ExecError::Journal(
            "restricted macOS executable backing path is not canonical".into(),
        ));
    }
    require_macos_path_not_writable(backing_path)?;

    let mut ancestor_paths: Vec<&Path> = backing_path.ancestors().skip(1).collect();
    ancestor_paths.reverse();
    let mut ancestors = Vec::with_capacity(ancestor_paths.len());
    for directory in ancestor_paths {
        let path_metadata = std::fs::symlink_metadata(directory)?;
        if !path_metadata.is_dir()
            || path_metadata.file_type().is_symlink()
            || UnixMetadataExt::uid(&path_metadata) != 0
            || UnixMetadataExt::mode(&path_metadata) & 0o022 != 0
        {
            return Err(ExecError::Journal(format!(
                "restricted macOS executable ancestor lacks root-owned immutable custody: {}",
                directory.display()
            )));
        }
        require_macos_path_not_writable(directory)?;
        let handle = open_macos_directory_custody(directory)?;
        let opened_metadata = handle.metadata()?;
        if UnixMetadataExt::dev(&opened_metadata) != UnixMetadataExt::dev(&path_metadata)
            || UnixMetadataExt::ino(&opened_metadata) != UnixMetadataExt::ino(&path_metadata)
        {
            return Err(ExecError::Journal(format!(
                "restricted macOS executable ancestor changed while opening: {}",
                directory.display()
            )));
        }
        ancestors.push(handle);
    }

    // Revalidate after the full ancestor inspection. From this point the
    // unprivileged daemon cannot replace the SF_RESTRICTED image or any path
    // component used by posix_spawn.
    verify_path_entry_pin(invocation_path, invocation_pin)?;
    verify_open_file_pin(invocation, invocation_path, invocation_pin)?;
    verify_open_file_pin(invocation, invocation_path, backing_pin)?;
    verify_path_entry_pin(backing_path, backing_pin)?;
    verify_open_file_pin(backing, backing_path, backing_pin)?;
    if open_file_identity(invocation)? != open_file_identity(backing)? {
        return Err(ExecError::Journal(
            "restricted macOS invocation changed during custody validation".into(),
        ));
    }

    Ok(Some(ancestors))
}

#[cfg(target_os = "macos")]
fn require_macos_path_not_writable(path: &Path) -> ExecResult<()> {
    use rustix::fs::Access;
    match rustix::fs::access(path, Access::WRITE_OK) {
        Ok(()) => Err(ExecError::Journal(format!(
            "restricted macOS executable custody path is writable by the daemon: {}",
            path.display()
        ))),
        Err(error)
            if error == rustix::io::Errno::ACCESS
                || error == rustix::io::Errno::PERM
                || error == rustix::io::Errno::ROFS =>
        {
            Ok(())
        }
        Err(error) => Err(ExecError::Io(error.into())),
    }
}

#[cfg(target_os = "macos")]
fn open_macos_directory_custody(path: &Path) -> ExecResult<File> {
    use rustix::fs::{open, Mode, OFlags};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::DIRECTORY,
        Mode::empty(),
    )
    .map_err(|error| ExecError::Io(error.into()))?;
    Ok(File::from(descriptor))
}

#[cfg(not(any(target_os = "linux", windows)))]
fn stage_verified_image(
    source: &mut File,
    invocation_path: &Path,
    backing_pin: &ExecutablePin,
    staging_root: &Path,
) -> ExecResult<SnapshotCustody> {
    if !staging_root.is_absolute() {
        return Err(ExecError::Journal(
            "prepared executable staging root must be absolute".into(),
        ));
    }
    let basename = invocation_path.file_name().ok_or_else(|| {
        ExecError::Journal("approved invocation path has no executable basename".into())
    })?;
    let directory = staging_root.join(format!("prepared-{}", uuid::Uuid::new_v4().simple()));
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(&directory)?;
    let path = directory.join(basename);
    let staged = (|| -> ExecResult<(File, File)> {
        source.seek(SeekFrom::Start(0))?;
        let mut output = create_snapshot_file(&path)?;
        let mut total = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            total = total
                .checked_add(u64::try_from(read).unwrap())
                .ok_or_else(|| ExecError::ResourceLimit("snapshot length overflow".into()))?;
            if total > super::MAX_EXECUTABLE_PIN_BYTES {
                return Err(ExecError::ResourceLimit(
                    "prepared executable snapshot exceeds size budget".into(),
                ));
            }
            output.write_all(&buffer[..read])?;
        }
        if total != backing_pin.len {
            return Err(ExecError::Journal(
                "prepared executable snapshot length does not match the approved pin".into(),
            ));
        }
        output.sync_all()?;
        use std::os::unix::fs::PermissionsExt;
        output.set_permissions(std::fs::Permissions::from_mode(0o500))?;
        let digest = super::hash_open_file_bounded(
            &mut output,
            invocation_path,
            backing_pin.len,
            super::MAX_EXECUTABLE_PIN_BYTES,
        )?;
        if digest != backing_pin.content_sha256 {
            return Err(ExecError::Journal(
                "prepared executable snapshot does not match the approved executable".into(),
            ));
        }
        output.seek(SeekFrom::Start(0))?;
        let staged_identity = open_file_identity(&output)?;
        let directory_handle = File::open(&directory)?;
        directory_handle.sync_all()?;
        // Do not retain a writable descriptor across posix_spawn. Apart from
        // unnecessarily broad custody, Unix kernels may reject executing an
        // image that this process still has open for writing (ETXTBSY).
        drop(output);
        let mut image = open_snapshot_file(&path)?;
        if open_file_identity(&image)? != staged_identity {
            return Err(ExecError::Journal(
                "prepared executable snapshot identity changed while reopening read-only".into(),
            ));
        }
        let reopened_digest = super::hash_open_file_bounded(
            &mut image,
            invocation_path,
            backing_pin.len,
            super::MAX_EXECUTABLE_PIN_BYTES,
        )?;
        if reopened_digest != backing_pin.content_sha256 {
            return Err(ExecError::Journal(
                "prepared executable snapshot changed while reopening read-only".into(),
            ));
        }
        image.seek(SeekFrom::Start(0))?;
        Ok((image, directory_handle))
    })();
    let (image, directory_handle) = match staged {
        Ok(handles) => handles,
        Err(error) => {
            let _ = std::fs::remove_file(&path);
            let _ = std::fs::remove_dir(&directory);
            return Err(error);
        }
    };
    Ok(SnapshotCustody {
        path,
        directory,
        _image: image,
        _directory: directory_handle,
    })
}

#[cfg(not(any(target_os = "linux", windows)))]
fn create_snapshot_file(path: &Path) -> ExecResult<File> {
    use std::os::unix::fs::OpenOptionsExt;
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(path)?)
}

#[cfg(not(any(target_os = "linux", windows)))]
fn open_snapshot_file(path: &Path) -> ExecResult<File> {
    use rustix::fs::{open, Mode, OFlags};
    let descriptor = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| ExecError::Io(error.into()))?;
    Ok(File::from(descriptor))
}

pub(super) struct PreparedCommand {
    pub command: Command,
    #[cfg(target_os = "linux")]
    _descriptors: Vec<File>,
    #[cfg(not(target_os = "linux"))]
    _custody: PreparedImage,
}

#[cfg_attr(
    not(any(target_os = "linux", windows)),
    allow(clippy::unnecessary_wraps)
)]
pub(super) fn build_prepared_command(
    req: &RunRequest,
    prepared: PreparedExecutable,
) -> ExecResult<PreparedCommand> {
    let args = effective_args(req);
    #[cfg(target_os = "linux")]
    let (mut command, descriptors) = match prepared.image {
        PreparedImage::Descriptor(image) => {
            let command =
                linux_descriptor_command(&image, &prepared.approved_argv0, &args, &req.env)?;
            (command, vec![image])
        }
        PreparedImage::Script {
            script,
            script_origin,
            interpreter,
            interpreter_argv0,
            interpreter_args,
        } => {
            let interpreter_args = linux_script_args(
                &script,
                &script_origin,
                &interpreter_argv0,
                interpreter_args,
                args,
                &prepared.approved_argv0,
            )?;
            let command = linux_descriptor_command(
                &interpreter,
                &interpreter_argv0,
                &interpreter_args,
                &req.env,
            )?;
            (command, vec![script, interpreter])
        }
    };
    #[cfg(windows)]
    let (mut command, custody) = match prepared.image {
        PreparedImage::LockedPath(locked) => {
            if locked.invocation_path != Path::new(&prepared.approved_argv0) {
                return Err(ExecError::Journal(
                    "locked Windows invocation no longer matches approved argv0".into(),
                ));
            }
            let mut command = Command::new(&locked.launcher_path);
            if locked.batch_wrapper {
                let batch_command_args =
                    super::windows_batch_argv(&locked.invocation_path, &req.args)
                        .map_err(|error| ExecError::Spawn(error.to_string()))?;
                if batch_command_args.first().map(Path::new) != Some(locked.launcher_path.as_path())
                {
                    return Err(ExecError::Journal(
                        "prepared Windows batch launcher no longer matches its approved interpreter"
                            .into(),
                    ));
                }
                command.args(&batch_command_args[1..]);
            } else {
                command.args(&args);
            }
            (command, PreparedImage::LockedPath(locked))
        }
    };
    #[cfg(not(any(target_os = "linux", windows)))]
    let (mut command, custody) = match prepared.image {
        PreparedImage::Snapshot(snapshot) => {
            let mut command = Command::new(&snapshot.path);
            command.arg0(&prepared.approved_argv0);
            command.args(&args);
            (command, PreparedImage::Snapshot(snapshot))
        }
        #[cfg(target_os = "macos")]
        PreparedImage::RestrictedPath(restricted) => {
            let mut command = Command::new(&restricted.launcher_path);
            command.arg0(&prepared.approved_argv0);
            command.args(&args);
            (command, PreparedImage::RestrictedPath(restricted))
        }
    };
    if let Some(cwd) = &req.cwd {
        command.current_dir(cwd);
    }
    #[cfg(not(target_os = "linux"))]
    for (key, value) in &req.env {
        command.env(key, value);
    }
    #[cfg(unix)]
    command.process_group(0);
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    Ok(PreparedCommand {
        command,
        #[cfg(target_os = "linux")]
        _descriptors: descriptors,
        #[cfg(not(target_os = "linux"))]
        _custody: custody,
    })
}

#[cfg(target_os = "linux")]
fn linux_script_args(
    script: &File,
    script_origin: &str,
    interpreter_argv0: &str,
    mut interpreter_args: Vec<String>,
    request_args: Vec<String>,
    approved_script_argv0: &str,
) -> ExecResult<Vec<String>> {
    use std::os::fd::AsRawFd;

    let descriptor_path = format!("/proc/self/fd/{}", script.as_raw_fd());
    let interpreter_name = super::program_basename(interpreter_argv0);
    if interpreter_name.eq_ignore_ascii_case("node")
        || interpreter_name.eq_ignore_ascii_case("nodejs")
    {
        let module_url = linux_file_url(script_origin);
        let target = serde_json::to_string(&module_url)
            .map_err(|error| ExecError::Spawn(format!("encode Node module URL: {error}")))?;
        let source_path = serde_json::to_string(&descriptor_path)
            .map_err(|error| ExecError::Spawn(format!("encode Node script fd: {error}")))?;
        let loader_source = format!(
            "import{{readFileSync}}from'node:fs';const t={target},s=readFileSync({source_path});\
export async function load(u,c,n){{return u===t?{{format:c.format||'module',source:s,shortCircuit:true}}:n(u,c)}}"
        );
        let loader_url = format!(
            "data:text/javascript,{}",
            percent_encode(&loader_source, false)
        );
        let encoded_loader_url = serde_json::to_string(&loader_url)
            .map_err(|error| ExecError::Spawn(format!("encode Node loader URL: {error}")))?;
        let register_source = format!(
            "import{{register}}from'node:module';register({encoded_loader_url},import.meta.url)"
        );
        let register_url = format!(
            "data:text/javascript,{}",
            percent_encode(&register_source, false)
        );
        // The interpreter itself is a sealed memfd, so Node's discovered
        // process.execPath would otherwise be a non-reopenable `(deleted)`
        // name. `/proc/self/exe` remains a kernel-held reference to that same
        // sealed image and preserves secure child-process spawning by CLIs.
        let eval_source = format!("process.execPath='/proc/self/exe';await import({target})");
        interpreter_args.extend([
            "--import".into(),
            register_url,
            "--input-type=module".into(),
            "--eval".into(),
            eval_source,
            "--".into(),
            approved_script_argv0.to_owned(),
        ]);
        interpreter_args.extend(request_args);
        return Ok(interpreter_args);
    }

    interpreter_args.push(descriptor_path);
    interpreter_args.extend(request_args);
    Ok(interpreter_args)
}

#[cfg(target_os = "linux")]
fn linux_file_url(path: &str) -> String {
    format!("file://{}", percent_encode(path, true))
}

#[cfg(target_os = "linux")]
fn percent_encode(value: &str, keep_slash: bool) -> String {
    use std::fmt::Write as _;

    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && byte == b'/')
        {
            encoded.push(char::from(byte));
        } else {
            write!(&mut encoded, "%{byte:02X}").expect("writing to String cannot fail");
        }
    }
    encoded
}

fn effective_args(req: &RunRequest) -> Vec<String> {
    if matches!(req.kind, CommandKind::Structured) {
        return req.args.clone();
    }
    let mut full = req.program.clone();
    if !req.args.is_empty() {
        full.push(' ');
        full.push_str(&req.args.join(" "));
    }
    #[cfg(windows)]
    return vec!["/C".into(), full];
    #[cfg(not(windows))]
    vec!["-c".into(), full]
}

#[cfg(target_os = "linux")]
fn linux_descriptor_command(
    image: &File,
    argv0: &str,
    args: &[String],
    overlay: &std::collections::HashMap<String, String>,
) -> ExecResult<Command> {
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStrExt;
    let mut exec_argv = Vec::with_capacity(args.len() + 1);
    exec_argv.push(
        CString::new(argv0.as_bytes())
            .map_err(|_| ExecError::Spawn("approved argv0 contains an interior NUL".into()))?,
    );
    for arg in args {
        exec_argv
            .push(CString::new(arg.as_bytes()).map_err(|_| {
                ExecError::Spawn("structured argv contains an interior NUL".into())
            })?);
    }
    let mut environment: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
    for (key, value) in overlay {
        environment.insert(OsString::from(key), OsString::from(value));
    }
    let mut env = Vec::with_capacity(environment.len());
    for (key, value) in environment {
        let mut item = key;
        item.push("=");
        item.push(value);
        env.push(CString::new(item.as_os_str().as_bytes()).map_err(|_| {
            ExecError::Spawn("execution environment contains an interior NUL".into())
        })?);
    }
    let fd = image.as_raw_fd();
    // `/bin/false` is never executed: a failing pre-exec callback aborts spawn,
    // and successful `fexecve` replaces the child image from the retained fd.
    let mut command = Command::new("/bin/false");
    // SAFETY: after fork the callback performs only the async-signal-safe
    // `fexecve` syscall through nix. All CString allocation and environment
    // construction happened in the parent before this callback was installed.
    unsafe {
        command.pre_exec(move || match nix::unistd::fexecve(fd, &exec_argv, &env) {
            Ok(never) => match never {},
            Err(error) => Err(std::io::Error::from_raw_os_error(error as i32)),
        });
    }
    Ok(command)
}
