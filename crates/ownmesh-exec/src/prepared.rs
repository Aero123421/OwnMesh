//! Handle-bound executable preparation and launch.
//!
//! The approval-time pins are path-based durable facts. Preparation opens the
//! invocation and canonical backing, revalidates both against those facts, and
//! then retains the exact image object used by the launcher. No prepared launch
//! re-resolves the approved invocation or silently substitutes its backing path.

use super::{
    open_file_identity, verify_open_file_pin, verify_path_entry_pin, CommandKind, ExecError,
    ExecResult, ExecutablePin, RunRequest,
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
    #[cfg(windows)]
    LockedPath(WindowsPathCustody),
    #[cfg(not(any(target_os = "linux", windows)))]
    Snapshot(SnapshotCustody),
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
/// `staging_root` is required on targets without descriptor execution. It must
/// be an already custody-validated owner directory (the daemon runtime dir).
pub fn prepare_executable(
    invocation_path: &Path,
    invocation_pin: &ExecutablePin,
    backing_pin: &ExecutablePin,
    staging_root: Option<&Path>,
) -> ExecResult<PreparedExecutable> {
    prepare_executable_with_interpreter(
        invocation_path,
        invocation_pin,
        backing_pin,
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
    #[cfg(any(target_os = "linux", windows))]
    let _ = staging_root;
    #[cfg(not(windows))]
    let _ = interpreter_pin;
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
    let mut invocation = open_execution_target(invocation_path).map_err(|error| {
        ExecError::Journal(format!(
            "open approved invocation for preparation failed: {error}"
        ))
    })?;
    verify_open_file_pin(&mut invocation, invocation_path, invocation_pin)?;
    // The executable object reached through the invocation must be the exact
    // approved backing object, not merely an object with the same bytes.
    verify_open_file_pin(&mut invocation, invocation_path, backing_pin)?;

    let backing_path = Path::new(&backing_pin.path);
    #[cfg(windows)]
    let backing_entry = open_windows_entry_custody(backing_path).map_err(|error| {
        ExecError::Journal(format!(
            "lock approved backing entry for preparation failed: {error}"
        ))
    })?;
    #[cfg(windows)]
    ancestors.extend(lock_windows_ancestor_chain(backing_path)?);
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

    verify_path_entry_pin(invocation_path, invocation_pin)?;
    verify_path_entry_pin(backing_path, backing_pin)?;

    #[cfg(target_os = "linux")]
    let image = PreparedImage::Descriptor(stage_linux_memfd(&mut invocation, backing_pin)?);
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
    #[cfg(not(any(target_os = "linux", windows)))]
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
fn stage_linux_memfd(source: &mut File, backing_pin: &ExecutablePin) -> ExecResult<File> {
    use rustix::fs::{fcntl_add_seals, memfd_create, MemfdFlags, SealFlags};
    use std::os::unix::fs::PermissionsExt;

    // Linux must keep the descriptor inherited for a shebang script: the
    // kernel passes an fd-backed pathname to the interpreter, and CLOEXEC
    // would close it before that second image-open. The descriptor contains
    // only the sealed approved script image. Native images remain CLOEXEC.
    let source_is_script = super::file_has_shebang(source)?;
    let mut base_flags = MemfdFlags::ALLOW_SEALING;
    if !source_is_script {
        base_flags |= MemfdFlags::CLOEXEC;
    }
    let descriptor = match memfd_create("ownmesh-prepared", base_flags | MemfdFlags::EXEC) {
        Ok(descriptor) => descriptor,
        Err(rustix::io::Errno::INVAL) => memfd_create("ownmesh-prepared", base_flags)
            .map_err(|error| ExecError::Io(error.into()))?,
        Err(error) => return Err(ExecError::Io(error.into())),
    };
    let mut image = File::from(descriptor);
    source.seek(SeekFrom::Start(0))?;
    let copied = std::io::copy(source, &mut image)?;
    if copied != backing_pin.len || copied > super::MAX_EXECUTABLE_PIN_BYTES {
        return Err(ExecError::Journal(
            "prepared Linux image length does not match the approved pin".into(),
        ));
    }
    image.sync_all()?;
    image.set_permissions(std::fs::Permissions::from_mode(0o500))?;
    let digest = super::hash_open_file_bounded(
        &mut image,
        Path::new(&backing_pin.path),
        backing_pin.len,
        super::MAX_EXECUTABLE_PIN_BYTES,
    )?;
    if digest != backing_pin.content_sha256 {
        return Err(ExecError::Journal(
            "prepared Linux image content does not match the approved executable".into(),
        ));
    }
    fcntl_add_seals(
        &image,
        SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL,
    )
    .map_err(|error| ExecError::Io(error.into()))?;
    image.seek(SeekFrom::Start(0))?;
    Ok(image)
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
        let mut buffer = [0_u8; 64 * 1024];
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
        let directory_handle = File::open(&directory)?;
        directory_handle.sync_all()?;
        Ok((output, directory_handle))
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
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(path)?)
}

pub(super) struct PreparedCommand {
    pub command: Command,
    #[cfg(target_os = "linux")]
    _descriptor: File,
    #[cfg(not(target_os = "linux"))]
    _custody: PreparedImage,
}

pub(super) fn build_prepared_command(
    req: &RunRequest,
    prepared: PreparedExecutable,
) -> ExecResult<PreparedCommand> {
    let args = effective_args(req);
    #[cfg(target_os = "linux")]
    let (mut command, descriptor) = match prepared.image {
        PreparedImage::Descriptor(image) => {
            let command =
                linux_descriptor_command(&image, &prepared.approved_argv0, &args, &req.env)?;
            (command, image)
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
                let argv = super::windows_batch_argv(&locked.invocation_path, &req.args)
                    .map_err(|error| ExecError::Spawn(error.to_string()))?;
                if argv.first().map(Path::new) != Some(locked.launcher_path.as_path()) {
                    return Err(ExecError::Journal(
                        "prepared Windows batch launcher no longer matches its approved interpreter"
                            .into(),
                    ));
                }
                command.args(&argv[1..]);
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
        _descriptor: descriptor,
        #[cfg(not(target_os = "linux"))]
        _custody: custody,
    })
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
