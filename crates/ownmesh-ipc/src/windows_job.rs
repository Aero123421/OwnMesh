//! Audited Windows process-tree containment façade.
//!
//! This is the only layer that calls the Job Object / `CreateProcessW` APIs.
//! It always creates the process suspended, assigns it to a
//! `KILL_ON_JOB_CLOSE` job, then leaves resume to the caller. Dropping the
//! returned value before resume, or after a timeout/cancel, closes that job and
//! kills every assigned descendant. No shell, inherited environment, inherited
//! stdin, or caller-selected working directory is accepted here.

use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::path::Path;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, ResumeThread, WaitForSingleObject, CREATE_NO_WINDOW,
    CREATE_SUSPENDED, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};

/// A suspended process that is already assigned to a private kill-on-close Job
/// Object. It is intentionally not cloneable: exactly one owner controls the
/// process-tree lifetime.
pub struct WindowsJobProcess {
    job: Handle,
    process: Handle,
    thread: Option<Handle>,
    stdout: Option<File>,
    stderr: Option<File>,
}

struct Handle(HANDLE);

impl Handle {
    fn new(handle: HANDLE) -> io::Result<Self> {
        if handle.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }

    fn into_raw(self) -> HANDLE {
        let handle = self.0;
        std::mem::forget(self);
        handle
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        // SAFETY: this wrapper owns exactly one successful Win32 handle.
        unsafe { CloseHandle(self.0) };
    }
}

impl WindowsJobProcess {
    /// Resume after assignment succeeded. On error, the still-owned job kills
    /// the suspended child when dropped.
    pub fn resume(&mut self) -> io::Result<()> {
        let thread = self.thread.take().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "process already resumed")
        })?;
        // SAFETY: `thread` is the primary thread handle returned by CreateProcessW.
        let result = unsafe { ResumeThread(thread.0) };
        drop(thread);
        if result == u32::MAX {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Wait no longer than `timeout`; `true` means the primary process exited.
    pub fn wait_timeout(&self, timeout: Duration) -> io::Result<bool> {
        let millis = u32::try_from(timeout.as_millis()).unwrap_or(u32::MAX);
        // SAFETY: `process` remains owned and valid for this call.
        match unsafe { WaitForSingleObject(self.process.0, millis) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            _ => Err(io::Error::last_os_error()),
        }
    }

    /// Terminate every process currently assigned to the Job, then wait for the
    /// primary process for a bounded period. Closing the job remains a second
    /// kill fence even if the explicit termination call fails.
    pub fn terminate_and_wait(&self, timeout: Duration) -> io::Result<()> {
        // SAFETY: `job` is private to this process and is a valid Job handle.
        if unsafe { TerminateJobObject(self.job.0, 1) } == 0 {
            return Err(io::Error::last_os_error());
        }
        if self.wait_timeout(timeout)? {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Windows Job Object did not terminate within bounded wait",
            ))
        }
    }

    /// Take the parent-only stdout pipe. The child has only the write end.
    pub fn take_stdout(&mut self) -> Option<File> {
        self.stdout.take()
    }

    /// Take the parent-only stderr pipe. The child has only the write end.
    pub fn take_stderr(&mut self) -> Option<File> {
        self.stderr.take()
    }

    /// Read the exit code after `wait_timeout` reported completion.
    pub fn exit_code(&self) -> io::Result<i32> {
        let mut code = 0_u32;
        // SAFETY: `process` remains owned and valid for this call.
        if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(code.cast_signed())
    }
}

/// Start a shell-free process in a Job Object, suspended until the caller has
/// installed its output/cancellation bookkeeping. `program` must already be a
/// broker-private staged executable; the caller supplies the staging directory
/// as the safe working directory, never a remote request's cwd.
pub fn spawn_suspended_windows_job(
    program: &Path,
    args: &[String],
    safe_working_directory: &Path,
) -> io::Result<WindowsJobProcess> {
    if !program.is_absolute() || !safe_working_directory.is_absolute() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Windows job program and safe working directory must be absolute",
        ));
    }
    let program_wide = wide_nul(program.as_os_str());
    let cwd_wide = wide_nul(safe_working_directory.as_os_str());
    let mut command_line = quote_windows_arg(program.as_os_str());
    for arg in args {
        command_line.push(' ');
        command_line.push_str(&quote_windows_arg(OsStr::new(arg)));
    }
    let mut command_line_wide = wide_nul(OsStr::new(&command_line));

    // SAFETY: all FFI calls below use initialized structs, valid pointers for
    // their lifetimes, and handles are wrapped exactly once immediately after
    // successful creation. Every failure path closes any acquired handle.
    unsafe {
        let raw_job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
        let job = Handle::new(raw_job)?;
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        if SetInformationJobObject(
            job.0,
            JobObjectExtendedLimitInformation,
            std::ptr::from_ref(&limits).cast(),
            u32::try_from(std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()).unwrap(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }

        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap(),
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 1,
        };
        let (stdout_read, stdout_write) = create_parent_read_pipe(&mut attributes)?;
        let (stderr_read, stderr_write) = create_parent_read_pipe(&mut attributes)?;
        let mut startup: STARTUPINFOW = std::mem::zeroed();
        startup.cb = u32::try_from(std::mem::size_of::<STARTUPINFOW>()).unwrap();
        startup.dwFlags = STARTF_USESTDHANDLES;
        // A zero input handle is deliberate: the child receives no stdin.
        startup.hStdInput = std::ptr::null_mut();
        startup.hStdOutput = stdout_write.0;
        startup.hStdError = stderr_write.0;
        let mut info: PROCESS_INFORMATION = std::mem::zeroed();
        // A single NUL (rather than NULL) gives CreateProcessW a deliberately
        // empty environment block. NULL would inherit broker secrets.
        let empty_environment = [0_u16];
        let created = CreateProcessW(
            program_wide.as_ptr(),
            command_line_wide.as_mut_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            1,
            CREATE_SUSPENDED | CREATE_NO_WINDOW,
            empty_environment.as_ptr().cast(),
            cwd_wide.as_ptr(),
            &startup,
            &mut info,
        );
        drop(stdout_write);
        drop(stderr_write);
        if created == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = Handle::new(info.hProcess)?;
        let thread = Handle::new(info.hThread)?;
        if AssignProcessToJobObject(job.0, process.0) == 0 {
            // Assignment failed: never resume an uncontained child. Explicitly
            // terminate it before handles can be dropped.
            windows_sys::Win32::System::Threading::TerminateProcess(process.0, 1);
            return Err(io::Error::last_os_error());
        }
        let stdout = File::from_raw_handle(stdout_read.into_raw() as RawHandle);
        let stderr = File::from_raw_handle(stderr_read.into_raw() as RawHandle);
        Ok(WindowsJobProcess {
            job,
            process,
            thread: Some(thread),
            stdout: Some(stdout),
            stderr: Some(stderr),
        })
    }
}

unsafe fn create_parent_read_pipe(
    attributes: *mut SECURITY_ATTRIBUTES,
) -> io::Result<(Handle, Handle)> {
    let mut read: HANDLE = std::ptr::null_mut();
    let mut write: HANDLE = std::ptr::null_mut();
    if CreatePipe(&mut read, &mut write, attributes, 0) == 0 {
        return Err(io::Error::last_os_error());
    }
    if windows_sys::Win32::Foundation::SetHandleInformation(read, HANDLE_FLAG_INHERIT, 0) == 0 {
        CloseHandle(read);
        CloseHandle(write);
        return Err(io::Error::last_os_error());
    }
    Ok((Handle(read), Handle(write)))
}

fn wide_nul(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

/// Quote one Windows argv element using the documented CommandLineToArgvW
/// backslash/quote rules. This is structured argv construction, not a shell.
fn quote_windows_arg(value: &OsStr) -> String {
    let value = value.to_string_lossy();
    if !value.is_empty() && !value.contains([' ', '\t', '"']) {
        return value.into_owned();
    }
    let mut quoted = String::from("\"");
    let mut slashes = 0_usize;
    for ch in value.chars() {
        match ch {
            '\\' => slashes += 1,
            '"' => {
                quoted.push_str(&"\\".repeat((slashes * 2) + 1));
                quoted.push('"');
                slashes = 0;
            }
            _ => {
                quoted.push_str(&"\\".repeat(slashes));
                quoted.push(ch);
                slashes = 0;
            }
        }
    }
    quoted.push_str(&"\\".repeat(slashes * 2));
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::{quote_windows_arg, spawn_suspended_windows_job};
    use std::ffi::OsStr;

    #[test]
    fn command_line_quote_handles_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote_windows_arg(OsStr::new("plain")), "plain");
        assert_eq!(quote_windows_arg(OsStr::new("two words")), "\"two words\"");
        assert_eq!(quote_windows_arg(OsStr::new("a\\\"b")), "\"a\\\\\\\"b\"");
        assert_eq!(
            quote_windows_arg(OsStr::new("two words\\")),
            "\"two words\\\\\""
        );
    }

    #[test]
    fn dropping_unresumed_job_never_runs_the_child() {
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("escaped-child-marker");
        let command = std::path::PathBuf::from(
            std::env::var("COMSPEC").unwrap_or_else(|_| r"C:\\Windows\\System32\\cmd.exe".into()),
        );
        let marker_arg = format!("echo escaped > {}", marker.display());
        let job = spawn_suspended_windows_job(
            &command,
            &["/d".into(), "/s".into(), "/c".into(), marker_arg],
            dir.path(),
        )
        .unwrap();
        drop(job);
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            !marker.exists(),
            "unassigned/unresumed child escaped its Job"
        );
    }
}
