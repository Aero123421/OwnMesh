//! Narrow SCM dispatcher facade for the fixed `OwnMeshDaemon` process.
//!
//! This is the only Windows-service `unsafe` surface used by `ownmeshd`.
//! The daemon itself remains `#![forbid(unsafe_code)]`; it supplies a safe
//! foreground callback and polls [`windows_daemon_service_stop_requested`].

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
use std::sync::OnceLock;
use std::time::Duration;
use windows_sys::Win32::System::Services::{
    RegisterServiceCtrlHandlerW, SetServiceStatus, StartServiceCtrlDispatcherW,
    SERVICE_ACCEPT_STOP, SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_START_PENDING,
    SERVICE_STATUS, SERVICE_STATUS_HANDLE, SERVICE_STOPPED, SERVICE_STOP_PENDING,
    SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};

/// Fixed service name bound into the privileged-broker trust policy.
pub const OWN_MESH_DAEMON_SERVICE_NAME: &str = "OwnMeshDaemon";

const ERROR_FAILED_SERVICE_CONTROLLER_CONNECT: i32 = 1063;
const WAIT_HINT: Duration = Duration::from_secs(30);

static SERVICE_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static SERVICE_STATUS_HANDLE_RAW: AtomicIsize = AtomicIsize::new(0);
static STOP_CHECKPOINT: AtomicU32 = AtomicU32::new(0);
static SERVICE_RUNNER: OnceLock<fn() -> Result<(), i32>> = OnceLock::new();

/// Result of asking SCM to host the current process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsServiceDispatcherOutcome {
    /// SCM ran the fixed daemon service and its callback has returned.
    Dispatched,
    /// This is an interactive process, not an SCM-launched service.
    NotService,
}

/// Enter the fixed `OwnMeshDaemon` SCM dispatcher when launched by SCM.
///
/// An interactive process receives `NotService` and must perform its ordinary
/// foreground startup. The service image therefore has no arguments: the
/// same default executable invocation works in both contexts without a
/// mutable service command line.
pub fn run_ownmesh_daemon_service_dispatcher(
    runner: fn() -> Result<(), i32>,
) -> Result<WindowsServiceDispatcherOutcome, String> {
    SERVICE_RUNNER
        .set(runner)
        .map_err(|_| "Windows service dispatcher was initialized more than once".to_owned())?;
    SERVICE_STOP_REQUESTED.store(false, Ordering::Release);
    STOP_CHECKPOINT.store(0, Ordering::Release);

    let mut name = wide(OWN_MESH_DAEMON_SERVICE_NAME);
    let mut table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_mut_ptr()) } == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT) {
            return Ok(WindowsServiceDispatcherOutcome::NotService);
        }
        return Err(format!(
            "Windows SCM dispatcher rejected OwnMeshDaemon: {error}"
        ));
    }
    Ok(WindowsServiceDispatcherOutcome::Dispatched)
}

/// Whether SCM sent a stop control to the fixed daemon service.
#[must_use]
pub fn windows_daemon_service_stop_requested() -> bool {
    SERVICE_STOP_REQUESTED.load(Ordering::Acquire)
}

unsafe extern "system" fn service_control(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        SERVICE_STOP_REQUESTED.store(true, Ordering::Release);
        report_stop_pending();
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(OWN_MESH_DAEMON_SERVICE_NAME);
    let handle = unsafe { RegisterServiceCtrlHandlerW(name.as_ptr(), Some(service_control)) };
    if handle.is_null() {
        return;
    }
    SERVICE_STATUS_HANDLE_RAW.store(handle as isize, Ordering::Release);
    let mut status = service_status(SERVICE_START_PENDING, 0, 1, WAIT_HINT);
    let _ = unsafe { SetServiceStatus(handle, &status) };

    // The runner owns all daemon initialization. Only report RUNNING after
    // the process has reached its normal foreground lifecycle entrypoint.
    status = service_status(SERVICE_RUNNING, SERVICE_ACCEPT_STOP, 0, Duration::ZERO);
    if unsafe { SetServiceStatus(handle, &status) } == 0 {
        SERVICE_STOP_REQUESTED.store(true, Ordering::Release);
    }
    let exit = SERVICE_RUNNER
        .get()
        .copied()
        .map_or(1, |run| run().err().unwrap_or(0));
    let stopped = service_status(SERVICE_STOPPED, 0, 0, Duration::ZERO);
    let mut stopped = stopped;
    stopped.dwWin32ExitCode = u32::try_from(exit).unwrap_or(1);
    let _ = unsafe { SetServiceStatus(handle, &stopped) };
    SERVICE_STATUS_HANDLE_RAW.store(0, Ordering::Release);
}

fn report_stop_pending() {
    let raw = SERVICE_STATUS_HANDLE_RAW.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    let checkpoint = STOP_CHECKPOINT
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    let status = service_status(SERVICE_STOP_PENDING, 0, checkpoint, WAIT_HINT);
    let _ = unsafe { SetServiceStatus(raw as SERVICE_STATUS_HANDLE, &status) };
}

fn service_status(
    state: u32,
    controls: u32,
    checkpoint: u32,
    wait_hint: Duration,
) -> SERVICE_STATUS {
    SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: controls,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: wait_hint.as_millis().try_into().unwrap_or(u32::MAX),
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_daemon_service_name_is_not_configurable() {
        assert_eq!(OWN_MESH_DAEMON_SERVICE_NAME, "OwnMeshDaemon");
        assert_eq!(wide(OWN_MESH_DAEMON_SERVICE_NAME).last(), Some(&0));
    }

    #[test]
    fn stop_status_is_bounded_and_does_not_accept_new_controls() {
        let status = service_status(SERVICE_STOP_PENDING, 0, 1, WAIT_HINT);
        assert_eq!(status.dwControlsAccepted, 0);
        assert_eq!(status.dwWaitHint, 30_000);
    }
}
