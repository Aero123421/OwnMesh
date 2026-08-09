//! Native Windows SCM lifecycle for the fixed privileged-broker service.
//!
//! This is deliberately broker-only: it validates an already-installed
//! `OwnMeshDaemon` SCM identity and does not install or mutate ownmeshd.  The
//! daemon/runtime client integration is a separate authority-bearing change.

use crate::{
    load_or_create_capability_keys, load_or_create_secret, load_windows_daemon_trust_record,
    InstallRecord, InstallStatus, WindowsDurableReplayLedger, WindowsJobRunner,
    WindowsProductionBrokerServer,
};
use ownmesh_ipc::{windows_process_facts, windows_running_service_facts};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SERVICE_EXISTS};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    GetNamedSecurityInfoW, SetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetSecurityDescriptorControl, GetSidSubAuthority, GetSidSubAuthorityCount,
    GetTokenInformation, TokenIntegrityLevel, TokenUser, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::DELETE;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceConfigW, QueryServiceStatusEx, RegisterServiceCtrlHandlerW,
    SetServiceStatus, StartServiceCtrlDispatcherW, StartServiceW, QUERY_SERVICE_CONFIGW,
    SC_MANAGER_CONNECT, SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_STOP,
    SERVICE_AUTO_START, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_QUERY_CONFIG,
    SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS, SERVICE_STATUS_PROCESS,
    SERVICE_STOP, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::OpenProcessToken;

const BROKER_SERVICE: &str = "OwnMeshPrivilegedBroker";
const DAEMON_SERVICE: &str = "OwnMeshDaemon";
const CONFIG_NAME: &str = "broker-service.json";
const TRUST_NAME: &str = "daemon-trust.json";
const LEDGER_NAME: &str = "replay-ledger.json";
const SECRET_NAME: &str = "broker.request.secret";
const SIGNING_NAME: &str = "broker.cap.signing";
const STAGING_NAME: &str = "staged";
const WAIT_LIMIT: Duration = Duration::from_secs(30);
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowsBrokerConfig {
    schema_version: u32,
    broker_service_name: String,
    daemon_service_name: String,
    broker_binary: PathBuf,
    trust_record: PathBuf,
    request_secret: PathBuf,
    signing_key: PathBuf,
    replay_ledger: PathBuf,
    staging_dir: PathBuf,
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn data_root() -> Result<PathBuf, String> {
    std::env::var_os("ProgramData")
        .map(PathBuf::from)
        .map(|root| root.join("OwnMesh").join("broker"))
        .ok_or_else(|| "ProgramData is unavailable; Windows broker paths must be fixed".into())
}

fn binary_path() -> Result<PathBuf, String> {
    std::env::var_os("ProgramFiles")
        .map(PathBuf::from)
        .map(|root| root.join("OwnMesh").join("ownmesh-broker.exe"))
        .ok_or_else(|| {
            "ProgramFiles is unavailable; Windows broker binary path must be fixed".into()
        })
}

fn config_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join(CONFIG_NAME))
}

fn command_line(binary: &Path, config: &Path) -> String {
    format!(
        "\"{}\" run --config \"{}\"",
        binary.display(),
        config.display()
    )
}

fn system_admin_sddl(directory: bool) -> String {
    if directory {
        "D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".into()
    } else {
        "D:P(A;;FA;;;SY)(A;;FA;;;BA)".into()
    }
}

fn apply_system_admin_custody(path: &Path, directory: bool) -> Result<(), String> {
    let sddl = system_admin_sddl(directory);
    let raw = wide(OsStr::new(&sddl));
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            raw.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
        || descriptor.is_null()
    {
        return Err(format!(
            "create SYSTEM/Admin DACL: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        if unsafe {
            windows_sys::Win32::Security::GetSecurityDescriptorDacl(
                descriptor,
                &mut present,
                &mut dacl,
                &mut defaulted,
            )
        } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err("SYSTEM/Admin DACL is malformed".into());
        }
        let name = wide(path.as_os_str());
        let status = unsafe {
            SetNamedSecurityInfoW(
                name.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                dacl,
                ptr::null_mut(),
            )
        };
        if status != 0 {
            return Err(format!(
                "set SYSTEM/Admin custody on {}: {}",
                path.display(),
                std::io::Error::from_raw_os_error(status as i32)
            ));
        }
        verify_system_admin_custody(path)
    })();
    unsafe {
        let _ = LocalFree(descriptor);
    }
    result
}

fn verify_system_admin_custody(path: &Path) -> Result<(), String> {
    let name = wide(path.as_os_str());
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(format!(
            "read SYSTEM/Admin custody on {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let mut control = 0_u16;
    let mut revision = 0_u32;
    let protected =
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
            && control & SE_DACL_PROTECTED != 0;
    unsafe {
        let _ = LocalFree(descriptor);
    }
    if !protected {
        return Err(format!(
            "{} lacks a protected SYSTEM/Admin DACL (fail-closed)",
            path.display()
        ));
    }
    Ok(())
}

fn ensure_custody_dir(path: &Path) -> Result<(), String> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "{} is not a regular non-reparse directory",
                path.display()
            ));
        }
    } else {
        std::fs::create_dir_all(path).map_err(|e| format!("create {}: {e}", path.display()))?;
    }
    apply_system_admin_custody(path, true)
}

fn write_custodied_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "refusing to replace unrecorded Windows custody file {}",
            path.display()
        ));
    }
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    if let Err(error) = apply_system_admin_custody(path, false) {
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a regular non-reparse file",
            path.display()
        ));
    }
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn query_service_pid(name: &str) -> Result<u32, String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err(format!("open SCM: {}", std::io::Error::last_os_error()));
    }
    let service_name = wide(OsStr::new(name));
    let result = (|| {
        let service = unsafe { OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            return Err(format!(
                "open SCM service {name}: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut status = unsafe { std::mem::zeroed::<SERVICE_STATUS_PROCESS>() };
        let mut needed = 0;
        let ok = unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX),
                &mut needed,
            )
        };
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        if ok == 0 || status.dwCurrentState != SERVICE_RUNNING || status.dwProcessId == 0 {
            return Err(format!("{name} must already be a running SCM service"));
        }
        Ok(status.dwProcessId)
    })();
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    result
}

fn process_token_identity(pid: u32) -> Result<(String, String, u32, u32), String> {
    // Install reads a kernel-attested service PID; it never accepts a SID or
    // session/integrity claim from the invoking administrator.
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(format!(
            "open daemon process: {}",
            std::io::Error::last_os_error()
        ));
    }
    let mut token = ptr::null_mut();
    let opened =
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0 && !token.is_null();
    if !opened {
        unsafe {
            let _ = CloseHandle(process);
        };
        return Err(format!(
            "open daemon token: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let mut need = 0_u32;
        unsafe {
            let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut need);
        }
        if need == 0 {
            return Err("query daemon TokenUser size".into());
        }
        let mut bytes = vec![0_u8; need as usize];
        if unsafe {
            GetTokenInformation(token, TokenUser, bytes.as_mut_ptr().cast(), need, &mut need)
        } == 0
        {
            return Err(format!(
                "query daemon TokenUser: {}",
                std::io::Error::last_os_error()
            ));
        }
        let user = unsafe { &*bytes.as_ptr().cast::<TOKEN_USER>() };
        let sid_len = unsafe { GetLengthSid(user.User.Sid) };
        if sid_len == 0 {
            return Err("daemon TokenUser SID is invalid".into());
        }
        let sid_bytes =
            unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), sid_len as usize) };
        let mut sid_text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut sid_text) } == 0
            || sid_text.is_null()
        {
            return Err("render daemon TokenUser SID".into());
        }
        let count = unsafe {
            let mut n = 0usize;
            while *sid_text.add(n) != 0 {
                n += 1;
            }
            n
        };
        let pipe_sid =
            String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(sid_text, count) });
        unsafe {
            let _ = LocalFree(sid_text.cast());
        }
        let mut session = 0_u32;
        if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
            return Err("read daemon session id".into());
        }
        let mut integrity_need = 0_u32;
        unsafe {
            let _ = GetTokenInformation(
                token,
                TokenIntegrityLevel,
                ptr::null_mut(),
                0,
                &mut integrity_need,
            );
        }
        if integrity_need == 0 {
            return Err("query daemon integrity size".into());
        }
        let mut integrity_bytes = vec![0_u8; integrity_need as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenIntegrityLevel,
                integrity_bytes.as_mut_ptr().cast(),
                integrity_need,
                &mut integrity_need,
            )
        } == 0
        {
            return Err("query daemon integrity level".into());
        }
        let label = unsafe { &*integrity_bytes.as_ptr().cast::<TOKEN_MANDATORY_LABEL>() };
        let count = unsafe { GetSidSubAuthorityCount(label.Label.Sid) };
        if count.is_null() || unsafe { *count } == 0 {
            return Err("daemon integrity SID is invalid".into());
        }
        let rid = unsafe { GetSidSubAuthority(label.Label.Sid, u32::from(*count - 1)) };
        if rid.is_null() {
            return Err("daemon integrity RID is unavailable".into());
        }
        Ok((
            pipe_sid,
            format!("sid:{}", hex::encode(sid_bytes)),
            session,
            unsafe { *rid },
        ))
    })();
    unsafe {
        let _ = CloseHandle(token);
        let _ = CloseHandle(process);
    }
    result
}

fn daemon_trust_record() -> Result<crate::WindowsDaemonTrustRecord, String> {
    let pid = query_service_pid(DAEMON_SERVICE)?;
    let scm = windows_running_service_facts(DAEMON_SERVICE, pid).map_err(|e| e.to_string())?;
    if scm.binary_command_line().trim().is_empty() {
        return Err("daemon SCM image command line is empty".into());
    }
    let facts = windows_process_facts(pid).map_err(|e| e.to_string())?;
    let (daemon_pipe_sid, daemon_token_sid, daemon_session_id, daemon_integrity_rid) =
        process_token_identity(pid)?;
    Ok(crate::WindowsDaemonTrustRecord {
        daemon_pipe_sid,
        daemon_token_sid,
        daemon_service_name: DAEMON_SERVICE.into(),
        daemon_session_id,
        daemon_integrity_rid,
        image_path: PathBuf::from(facts.image_path()),
        image_volume_serial: facts.image_volume_serial(),
        image_file_id: hex::encode(facts.image_file_id()),
        image_sha256: hex::encode(facts.image_sha256()),
        service_config_generation: 1,
    })
}

fn create_or_validate_service(binary: &Path, config: &Path) -> Result<(), String> {
    let manager = unsafe {
        OpenSCManagerW(
            ptr::null(),
            ptr::null(),
            SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
        )
    };
    if manager.is_null() {
        return Err(format!(
            "open SCM for broker install: {}",
            std::io::Error::last_os_error()
        ));
    }
    let service_name = wide(OsStr::new(BROKER_SERVICE));
    let display = wide(OsStr::new("OwnMesh Privileged Broker"));
    let command = wide(OsStr::new(&command_line(binary, config)));
    let service = unsafe {
        CreateServiceW(
            manager,
            service_name.as_ptr(),
            display.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | DELETE,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            ptr::null(),
            ptr::null(),
        )
    };
    if service.is_null() {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_EXISTS as i32) {
            unsafe {
                let _ = CloseServiceHandle(manager);
            }
            return Err(format!("create broker service: {error}"));
        }
        // Existing services are never adopted silently.  The fixed config and
        // binary custody record are checked before the idempotent start below.
        let existing = unsafe {
            OpenServiceW(
                manager,
                service_name.as_ptr(),
                SERVICE_QUERY_CONFIG | SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP,
            )
        };
        if existing.is_null() {
            unsafe {
                let _ = CloseServiceHandle(manager);
            }
            return Err("open existing broker service for idempotence".into());
        }
        let actual = query_service_command(existing)?;
        if actual != command_line(binary, config) {
            unsafe {
                let _ = CloseServiceHandle(existing);
                let _ = CloseServiceHandle(manager);
            }
            return Err("existing broker SCM service command differs from fixed custody configuration; refusing adoption".into());
        }
        unsafe {
            let _ = CloseServiceHandle(existing);
        }
    } else {
        unsafe {
            let _ = CloseServiceHandle(service);
        }
    }
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    Ok(())
}

fn query_service_command(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<String, String> {
    let mut needed = 0_u32;
    let _ = unsafe { QueryServiceConfigW(service, ptr::null_mut(), 0, &mut needed) };
    if needed < u32::try_from(std::mem::size_of::<QUERY_SERVICE_CONFIGW>()).unwrap_or(u32::MAX) {
        return Err("query broker SCM command size".into());
    }
    let words = usize::try_from(needed)
        .map_err(|_| "broker SCM command length overflow")?
        .div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if unsafe { QueryServiceConfigW(service, buffer.as_mut_ptr().cast(), needed, &mut needed) } == 0
    {
        return Err(format!(
            "query broker SCM command: {}",
            std::io::Error::last_os_error()
        ));
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let ptr = config.lpBinaryPathName;
    if ptr.is_null() {
        return Err("broker SCM command is absent".into());
    }
    let start = buffer.as_ptr() as usize;
    let end = start
        .checked_add(buffer.len() * std::mem::size_of::<usize>())
        .ok_or("broker SCM command buffer overflow")?;
    let current = ptr as usize;
    if current < start || current >= end {
        return Err("broker SCM command pointer escapes returned buffer".into());
    }
    let units = (end - current) / std::mem::size_of::<u16>();
    let raw = unsafe { std::slice::from_raw_parts(ptr, units) };
    let nul = raw
        .iter()
        .position(|unit| *unit == 0)
        .ok_or("broker SCM command lacks terminator")?;
    String::from_utf16(&raw[..nul]).map_err(|_| "broker SCM command is not UTF-16".into())
}

fn start_and_wait() -> Result<(), String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("open SCM to start broker".into());
    }
    let name = wide(OsStr::new(BROKER_SERVICE));
    let service =
        unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS | SERVICE_START) };
    if service.is_null() {
        unsafe {
            let _ = CloseServiceHandle(manager);
        }
        return Err("open broker service to start".into());
    }
    let _ = unsafe { StartServiceW(service, 0, ptr::null()) };
    let result = wait_service_state(service, SERVICE_RUNNING);
    unsafe {
        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(manager);
    }
    result
}

fn wait_service_state(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
    expected: u32,
) -> Result<(), String> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let mut status = unsafe { std::mem::zeroed::<SERVICE_STATUS_PROCESS>() };
        let mut needed = 0;
        if unsafe {
            QueryServiceStatusEx(
                service,
                SC_STATUS_PROCESS_INFO,
                (&mut status as *mut SERVICE_STATUS_PROCESS).cast(),
                u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX),
                &mut needed,
            )
        } == 0
        {
            return Err("query broker SCM state".into());
        }
        if status.dwCurrentState == expected {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "broker SCM state wait timed out (expected {expected}, got {})",
                status.dwCurrentState
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

pub fn install_windows_broker(_base: &Path) -> Result<InstallRecord, String> {
    let root = data_root()?;
    let config_path = config_path()?;
    let trust_path = root.join(TRUST_NAME);
    let staging = root.join(STAGING_NAME);
    ensure_custody_dir(&root)?;
    ensure_custody_dir(&staging)?;
    let destination = binary_path()?;
    let binary_parent = destination
        .parent()
        .ok_or("Windows broker binary lacks parent")?;
    ensure_custody_dir(binary_parent)?;
    let source = std::env::current_exe().map_err(|e| e.to_string())?;
    if destination.exists() {
        if hash_file(&destination)? != hash_file(&source)? {
            return Err(
                "fixed broker binary differs from invoking binary; refusing overwrite".into(),
            );
        }
    } else {
        std::fs::copy(&source, &destination)
            .map_err(|e| format!("copy broker into SYSTEM/Admin custody: {e}"))?;
        apply_system_admin_custody(&destination, false)?;
    }
    let trust = daemon_trust_record()?;
    if trust_path.exists() {
        verify_system_admin_custody(&trust_path)?;
        let existing = load_windows_daemon_trust_record(&trust_path)?;
        if existing.record() != &trust {
            return Err("existing daemon trust record mismatches live SCM daemon identity; refusing adoption".into());
        }
    } else {
        write_custodied_new(
            &trust_path,
            &serde_json::to_vec_pretty(&trust).map_err(|e| e.to_string())?,
        )?;
    }
    let cfg = WindowsBrokerConfig {
        schema_version: 1,
        broker_service_name: BROKER_SERVICE.into(),
        daemon_service_name: DAEMON_SERVICE.into(),
        broker_binary: destination.clone(),
        trust_record: trust_path.clone(),
        request_secret: root.join(SECRET_NAME),
        signing_key: root.join(SIGNING_NAME),
        replay_ledger: root.join(LEDGER_NAME),
        staging_dir: staging,
    };
    if config_path.exists() {
        verify_system_admin_custody(&config_path)?;
        let existing: WindowsBrokerConfig =
            serde_json::from_slice(&std::fs::read(&config_path).map_err(|e| e.to_string())?)
                .map_err(|e| format!("parse existing Windows broker config: {e}"))?;
        if existing.broker_binary != cfg.broker_binary
            || existing.trust_record != cfg.trust_record
            || existing.daemon_service_name != cfg.daemon_service_name
        {
            return Err("existing Windows broker config mismatch; refusing overwrite".into());
        }
    } else {
        write_custodied_new(
            &config_path,
            &serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
        )?;
    }
    create_or_validate_service(&destination, &config_path)?;
    start_and_wait()?;
    Ok(InstallRecord { installed: true, installed_at_unix: crate::now_unix(), endpoint: ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME.into(), endpoint_kind: "named_pipe".into(), unit_path: Some(BROKER_SERVICE.into()), secret_file: cfg.request_secret.display().to_string(), signing_key_file: cfg.signing_key.display().to_string(), verify_key_file: String::new(), trusted_executable: trust.image_path.display().to_string(), socket_owner_uid: 0, socket_group_gid: 0, socket_mode: 0, allowed_uids: vec![], daemon_uid: 0, daemon_gid: 0, broker_binary: destination.display().to_string(), config_path: config_path.display().to_string(), broker_sha256: hash_file(&destination)?, trusted_executable_sha256: trust.image_sha256, config_sha256: hash_file(&config_path)?, unit_sha256: String::new(), notes: vec!["Windows SCM broker service is installed; support remains pending an opt-in elevated receipt".into()], support: "unsupported".into() })
}

pub fn broker_status_windows(_base: &Path) -> Result<InstallStatus, String> {
    let config = config_path()?;
    if !config.exists() {
        return Ok(InstallStatus {
            installed: false,
            network: "disabled",
            endpoint: None,
            endpoint_kind: "named_pipe".into(),
            secret_present: false,
            signing_key_present: false,
            verify_key_present: false,
            unit_path: Some(BROKER_SERVICE.into()),
            notes: vec!["no Windows broker custody configuration".into()],
            support: "unsupported".into(),
        });
    }
    let custody = verify_system_admin_custody(&config);
    let running = query_service_pid(BROKER_SERVICE).is_ok();
    Ok(InstallStatus {
        installed: custody.is_ok() && running,
        network: "disabled",
        endpoint: Some(ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME.into()),
        endpoint_kind: "named_pipe".into(),
        secret_present: false,
        signing_key_present: false,
        verify_key_present: false,
        unit_path: Some(BROKER_SERVICE.into()),
        notes: if custody.is_ok() && running {
            vec!["Windows broker is running; support stays unsupported until an elevated receipt is captured".into()]
        } else {
            vec![format!(
                "Windows broker custody/service validation failed: {}",
                custody
                    .err()
                    .unwrap_or_else(|| "service is not running".into())
            )]
        },
        support: "unsupported".into(),
    })
}

pub fn uninstall_windows_broker(_base: &Path) -> Result<(), String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("open SCM for broker uninstall".into());
    }
    let name = wide(OsStr::new(BROKER_SERVICE));
    let service = unsafe {
        OpenServiceW(
            manager,
            name.as_ptr(),
            SERVICE_QUERY_STATUS | SERVICE_STOP | DELETE,
        )
    };
    if service.is_null() {
        unsafe {
            let _ = CloseServiceHandle(manager);
        }
        return Ok(());
    }
    let mut ignored = unsafe { std::mem::zeroed::<SERVICE_STATUS>() };
    let _ = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &mut ignored) };
    let _ = wait_service_state(service, SERVICE_STOPPED);
    if unsafe { DeleteService(service) } == 0 {
        unsafe {
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
        }
        return Err("delete broker SCM service".into());
    }
    unsafe {
        let _ = CloseServiceHandle(service);
        let _ = CloseServiceHandle(manager);
    }
    Ok(())
}

fn load_service_config() -> Result<WindowsBrokerConfig, String> {
    let path = config_path()?;
    verify_system_admin_custody(&path)?;
    let cfg: WindowsBrokerConfig =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("parse fixed Windows broker config: {e}"))?;
    if cfg.schema_version != 1
        || cfg.broker_service_name != BROKER_SERVICE
        || cfg.daemon_service_name != DAEMON_SERVICE
        || cfg.trust_record != data_root()?.join(TRUST_NAME)
        || cfg.replay_ledger != data_root()?.join(LEDGER_NAME)
        || cfg.staging_dir != data_root()?.join(STAGING_NAME)
    {
        return Err("Windows broker config differs from fixed production policy".into());
    }
    Ok(cfg)
}

async fn run_windows_broker_service() -> Result<(), String> {
    let cfg = load_service_config()?;
    verify_system_admin_custody(&cfg.trust_record)?;
    let trusted = load_windows_daemon_trust_record(&cfg.trust_record)?;
    let secret = load_or_create_secret(&cfg.request_secret)?;
    let (signing_key, _) = load_or_create_capability_keys(&cfg.signing_key)?;
    let ledger = WindowsDurableReplayLedger::open(&cfg.replay_ledger, 16_384)?;
    let runner = WindowsJobRunner::new(&cfg.staging_dir)?;
    let daemon_pipe_sid = trusted.record().daemon_pipe_sid.clone();
    let server = WindowsProductionBrokerServer::bind(
        &daemon_pipe_sid,
        trusted,
        ledger,
        runner,
        secret,
        signing_key,
    )
    .await?;
    loop {
        tokio::select! {
            result = server.serve_once() => result?,
            _ = tokio::time::sleep(Duration::from_millis(200)) => if STOP_REQUESTED.load(Ordering::Acquire) { return Ok(()); },
        }
    }
}

unsafe extern "system" fn service_control(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        STOP_REQUESTED.store(true, Ordering::Release);
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(OsStr::new(BROKER_SERVICE));
    let handle = RegisterServiceCtrlHandlerW(name.as_ptr(), Some(service_control));
    if handle.is_null() {
        return;
    }
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_RUNNING,
        dwControlsAccepted: SERVICE_ACCEPT_STOP,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 0,
        dwWaitHint: 0,
    };
    let _ = SetServiceStatus(handle, &status);
    let outcome = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .and_then(|runtime| {
            runtime
                .block_on(run_windows_broker_service())
                .map_err(std::io::Error::other)
        });
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    if let Err(error) = outcome {
        status.dwWin32ExitCode = error.raw_os_error().unwrap_or(1) as u32;
    }
    let _ = SetServiceStatus(handle, &status);
}

/// Enter the SCM dispatcher. This may only be called by SCM's process launch;
/// interactive `run --config` is refused by `main`.
pub fn run_windows_service_dispatcher() -> Result<(), String> {
    STOP_REQUESTED.store(false, Ordering::Release);
    let mut service_name = wide(OsStr::new(BROKER_SERVICE));
    let mut table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: service_name.as_mut_ptr(),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW {
            lpServiceName: ptr::null_mut(),
            lpServiceProc: None,
        },
    ];
    if unsafe { StartServiceCtrlDispatcherW(table.as_mut_ptr()) } == 0 {
        return Err(format!(
            "Windows SCM dispatcher rejected broker process: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}
