//! Native Windows SCM lifecycle for the fixed privileged-broker service.
//!
//! The broker is LocalSystem. The normal `ownmeshd` remains a current-user
//! process whose SID and immutable Program Files image are pinned by the
//! installer; no user credential is copied into a system profile.

use crate::windows::WINDOWS_USER_AGENT_TRUST;
use crate::{
    load_windows_daemon_trust_record, InstallRecord, InstallStatus, WindowsBrokerRunner,
    WindowsDurableReplayLedger, WindowsJobRunner, WindowsPeerAuthorizer,
    WindowsProductionBrokerServer, WindowsReplayLedger,
};
use ownmesh_broker_client::{
    BrokerEndpoint, BrokerSecret, CapabilitySigningKey, WindowsBrokerTrust,
};
use ownmesh_ipc::windows_process_facts;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;
use windows_sys::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_SERVICE_EXISTS, GENERIC_READ, GENERIC_WRITE, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SDDL_REVISION_1, SE_FILE_OBJECT,
};
use windows_sys::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetLengthSid,
    GetSecurityDescriptorControl, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenElevation,
    TokenIntegrityLevel, TokenUser, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SE_DACL_PROTECTED, TOKEN_ELEVATION, TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FileIdInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetFinalPathNameByHandleW, BY_HANDLE_FILE_INFORMATION,
    CREATE_NEW, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_ID_INFO, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Com::CoTaskMemFree;
use windows_sys::Win32::System::Pipes::WaitNamedPipeW;
use windows_sys::Win32::System::RemoteDesktop::ProcessIdToSessionId;
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, ControlService, CreateServiceW, DeleteService, OpenSCManagerW,
    OpenServiceW, QueryServiceConfigW, QueryServiceObjectSecurity, QueryServiceStatusEx,
    RegisterServiceCtrlHandlerW, SetServiceObjectSecurity, SetServiceStatus,
    StartServiceCtrlDispatcherW, StartServiceW, QUERY_SERVICE_CONFIGW, SC_MANAGER_CONNECT,
    SC_MANAGER_CREATE_SERVICE, SC_STATUS_PROCESS_INFO, SERVICE_ACCEPT_STOP, SERVICE_ALL_ACCESS,
    SERVICE_AUTO_START, SERVICE_CONTROL_STOP, SERVICE_ERROR_NORMAL, SERVICE_QUERY_STATUS,
    SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
    SERVICE_STATUS_PROCESS, SERVICE_STOPPED, SERVICE_STOP_PENDING, SERVICE_TABLE_ENTRYW,
    SERVICE_WIN32_OWN_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcessToken,
};
use windows_sys::Win32::UI::Shell::{
    FOLDERID_ProgramData, FOLDERID_ProgramFiles, SHGetKnownFolderPath,
};

const BROKER_SERVICE: &str = "OwnMeshPrivilegedBroker";
const CONFIG_NAME: &str = "broker-service.json";
const TRUST_NAME: &str = "daemon-trust.json";
const LEDGER_NAME: &str = "replay-ledger.json";
const SECRET_NAME: &str = "broker.request.secret";
const DAEMON_BINARY_NAME: &str = "ownmeshd.exe";
const CLIENT_SECRET_NAME: &str = "broker.client.secret";
const SIGNING_NAME: &str = "broker.cap.signing";
const STAGING_NAME: &str = "staged";
const WAIT_LIMIT: Duration = Duration::from_secs(30);
const MAX_BROKER_IMAGE_BYTES: u64 = 256 * 1024 * 1024;
const BROKER_SECRET_BYTES: usize = 32;
const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_MARKED_FOR_DELETE: i32 = 1072;
static STOP_REQUESTED: AtomicBool = AtomicBool::new(false);
static SERVICE_STATUS_HANDLE_RAW: AtomicIsize = AtomicIsize::new(0);
static STOP_CHECKPOINT: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
    broker_sha256: String,
    trust_sha256: String,
    secret_sha256: String,
    signing_sha256: String,
}

/// Safe, narrow projection of the Windows custody boundary for ownmeshd.
/// It intentionally exposes only the request-MAC secret, fixed endpoint, and
/// broker server trust; the capability signing key never leaves this crate.
#[derive(Clone)]
pub struct WindowsDaemonBrokerClient {
    endpoint: BrokerEndpoint,
    request_secret: BrokerSecret,
    server_trust: WindowsBrokerTrust,
    trusted_daemon_executable: PathBuf,
}

impl WindowsDaemonBrokerClient {
    #[must_use]
    pub fn endpoint(&self) -> &BrokerEndpoint {
        &self.endpoint
    }

    #[must_use]
    pub fn request_secret(&self) -> &BrokerSecret {
        &self.request_secret
    }

    #[must_use]
    pub fn server_trust(&self) -> &WindowsBrokerTrust {
        &self.server_trust
    }

    #[must_use]
    pub fn trusted_daemon_executable(&self) -> &Path {
        &self.trusted_daemon_executable
    }
}

fn wide(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn data_root() -> Result<PathBuf, String> {
    Ok(known_folder(&FOLDERID_ProgramData)?
        .join("OwnMesh")
        .join("broker"))
}

fn binary_path() -> Result<PathBuf, String> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?
        .join("OwnMesh")
        .join("ownmesh-broker.exe"))
}

fn daemon_binary_path() -> Result<PathBuf, String> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?
        .join("OwnMesh")
        .join(DAEMON_BINARY_NAME))
}

fn client_secret_path() -> Result<PathBuf, String> {
    Ok(known_folder(&FOLDERID_ProgramFiles)?
        .join("OwnMesh")
        .join(CLIENT_SECRET_NAME))
}

fn known_folder(id: &windows_sys::core::GUID) -> Result<PathBuf, String> {
    let mut raw = ptr::null_mut();
    let status = unsafe { SHGetKnownFolderPath(id, 0, ptr::null_mut(), &raw mut raw) };
    if status < 0 || raw.is_null() {
        return Err("resolve fixed Windows Known Folder path".into());
    }
    let len = unsafe {
        let mut value = 0usize;
        while *raw.add(value) != 0 {
            value += 1;
        }
        value
    };
    let path = PathBuf::from(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(raw, len)
    }));
    unsafe {
        CoTaskMemFree(raw.cast());
    }
    if !path.is_absolute() {
        return Err("Windows Known Folder path is not absolute".into());
    }
    Ok(path)
}

fn config_path() -> Result<PathBuf, String> {
    Ok(data_root()?.join(CONFIG_NAME))
}

/// The install transaction must prove elevation before it even resolves a
/// fixed filesystem path.  SCM create access is checked in addition to the
/// token bit because UAC split tokens and service ACL policy can disagree.
fn require_elevated_scm_admin() -> Result<(), String> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0
        || token.is_null()
    {
        return Err("Windows broker install requires an elevated Administrator token".into());
    }
    let result = (|| {
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0_u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&raw mut elevation).cast(),
                u32::try_from(std::mem::size_of::<TOKEN_ELEVATION>()).unwrap_or(u32::MAX),
                &raw mut returned,
            )
        } == 0
            || elevation.TokenIsElevated == 0
        {
            return Err("Windows broker install requires an elevated Administrator token".into());
        }
        let manager = unsafe {
            OpenSCManagerW(
                ptr::null(),
                ptr::null(),
                SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE,
            )
        };
        if manager.is_null() {
            return Err("Windows broker install requires SCM create-service access".into());
        }
        unsafe {
            let _ = CloseServiceHandle(manager);
        }
        Ok(())
    })();
    unsafe {
        let _ = CloseHandle(token);
    }
    result
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
        "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)".into()
    } else {
        "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)".into()
    }
}

/// The descriptor is passed to the kernel as part of creation.  In particular,
/// do not create an inheriting object and repair its ACL afterwards: another
/// principal can race that interval.
struct CreationDescriptor {
    raw: PSECURITY_DESCRIPTOR,
}

impl CreationDescriptor {
    fn new(directory: bool) -> Result<Self, String> {
        let text = wide(OsStr::new(&system_admin_sddl(directory)));
        let mut raw = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                ptr::null_mut(),
            )
        } == 0
            || raw.is_null()
        {
            return Err(format!(
                "create SYSTEM/Admin security descriptor: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { raw })
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: u32::try_from(std::mem::size_of::<SECURITY_ATTRIBUTES>()).unwrap_or(u32::MAX),
            lpSecurityDescriptor: self.raw.cast(),
            bInheritHandle: 0,
        }
    }

    fn service() -> Result<Self, String> {
        // SERVICE_ALL_ACCESS is 0x000F01FF. `FA` is FILE_ALL_ACCESS
        // (0x001F01FF) and would make the service DACL validator reject its
        // own descriptor after an SCM round trip.
        let text = wide(OsStr::new(
            "O:BAD:P(A;;0x000F01FF;;;SY)(A;;0x000F01FF;;;BA)",
        ));
        let mut raw = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                ptr::null_mut(),
            )
        } == 0
            || raw.is_null()
        {
            return Err("create exact broker service security descriptor".into());
        }
        Ok(Self { raw })
    }

    fn daemon_read(directory: bool, daemon_sid: &str) -> Result<Self, String> {
        let flags = if directory { "OICI" } else { "" };
        let text = wide(OsStr::new(&format!(
            "O:BAD:P(A;{flags};FA;;;SY)(A;{flags};FA;;;BA)(A;{flags};0x001200A9;;;{daemon_sid})"
        )));
        let mut raw = ptr::null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &raw mut raw,
                ptr::null_mut(),
            )
        } == 0
            || raw.is_null()
        {
            return Err("create daemon-readable Windows custody descriptor".into());
        }
        Ok(Self { raw })
    }
}

impl Drop for CreationDescriptor {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(self.raw);
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FileIdentity {
    volume: u32,
    index_high: u32,
    index_low: u32,
}

/// A no-delete-share, no-follow handle retained until the transaction ends.
/// It anchors both the object identity and the final path observed by the
/// installer, so a rename/reparse swap cannot make a later step adopt it.
struct CustodyHandle {
    handle: HANDLE,
    identity: FileIdentity,
    final_path: PathBuf,
}

impl Drop for CustodyHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.handle);
        }
    }
}

fn final_path(handle: HANDLE) -> Result<PathBuf, String> {
    let needed = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, 0) };
    if needed == 0 || needed > 32_768 {
        return Err("read final custody path".into());
    }
    let mut words = vec![0_u16; usize::try_from(needed).map_err(|_| "final path overflow")? + 1];
    let written = unsafe {
        GetFinalPathNameByHandleW(
            handle,
            words.as_mut_ptr(),
            u32::try_from(words.len()).unwrap_or(u32::MAX),
            0,
        )
    };
    if written == 0 || usize::try_from(written).unwrap_or(usize::MAX) >= words.len() {
        return Err("read final custody path".into());
    }
    let value = String::from_utf16_lossy(&words[..written as usize]);
    // Win32 returns a verbatim path (usually \\?\); normalise only that API
    // prefix, never resolve a caller supplied path through canonicalize().
    let value = if let Some(stripped) = value.strip_prefix(r"\\?\") {
        stripped.to_owned()
    } else {
        value
    };
    Ok(PathBuf::from(value))
}

fn identity(handle: HANDLE) -> Result<(FileIdentity, u32), String> {
    let mut info = unsafe { std::mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
    if unsafe { GetFileInformationByHandle(handle, &raw mut info) } == 0 {
        return Err("read custody file identity".into());
    }
    Ok((
        FileIdentity {
            volume: info.dwVolumeSerialNumber,
            index_high: info.nFileIndexHigh,
            index_low: info.nFileIndexLow,
        },
        info.dwFileAttributes,
    ))
}

fn open_custody_handle(path: &Path, directory: bool) -> Result<CustodyHandle, String> {
    let name = wide(path.as_os_str());
    let flags = FILE_FLAG_OPEN_REPARSE_POINT
        | if directory {
            FILE_FLAG_BACKUP_SEMANTICS
        } else {
            0
        };
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            flags,
            ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "open no-follow custody handle {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let (id, attributes) = identity(handle)?;
        if attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(format!("{} is a reparse point", path.display()));
        }
        let observed = final_path(handle)?;
        if observed != path {
            return Err(format!(
                "{} final path differs from fixed custody path",
                path.display()
            ));
        }
        Ok(CustodyHandle {
            handle,
            identity: id,
            final_path: observed,
        })
    })();
    if result.is_err() {
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
    result
}

fn revalidate_custody_handle(
    path: &Path,
    anchored: &CustodyHandle,
    directory: bool,
) -> Result<(), String> {
    let now = open_custody_handle(path, directory)?;
    if now.identity != anchored.identity || now.final_path != anchored.final_path {
        return Err(format!(
            "{} custody identity changed during transaction",
            path.display()
        ));
    }
    Ok(())
}

fn revalidate_retained(handles: &[CustodyHandle]) -> Result<(), String> {
    for anchored in handles {
        let metadata = std::fs::symlink_metadata(&anchored.final_path)
            .map_err(|e| format!("revalidate {}: {e}", anchored.final_path.display()))?;
        revalidate_custody_handle(
            &anchored.final_path,
            anchored,
            metadata.file_type().is_dir(),
        )?;
    }
    Ok(())
}

fn verify_custody(path: &Path, daemon_read_sid: Option<&str>) -> Result<(), String> {
    fn sid(value: &str) -> Result<PSID, String> {
        let value = wide(OsStr::new(value));
        let mut parsed = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(value.as_ptr(), &raw mut parsed) } == 0
            || parsed.is_null()
        {
            return Err("parse expected Windows custody SID".into());
        }
        Ok(parsed)
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink()
        || (!metadata.file_type().is_dir() && !metadata.file_type().is_file())
    {
        return Err(format!(
            "{} is reparse/non-regular custody object",
            path.display()
        ));
    }
    let expected_flags = if metadata.file_type().is_dir() {
        0x03
    } else {
        0
    };
    let name = wide(path.as_os_str());
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let status = unsafe {
        GetNamedSecurityInfoW(
            name.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != 0 || descriptor.is_null() {
        return Err(format!(
            "read SYSTEM/Admin custody on {}: {}",
            path.display(),
            std::io::Error::from_raw_os_error(status as i32)
        ));
    }
    let system = sid("S-1-5-18")?;
    let admins = sid("S-1-5-32-544")?;
    let daemon = daemon_read_sid.map(sid).transpose()?;
    let result = (|| {
        let mut control = 0_u16;
        let mut revision = 0_u32;
        if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) }
            == 0
            || control & SE_DACL_PROTECTED == 0
        {
            return Err("custody DACL is not protected".into());
        }
        let mut owner: PSID = ptr::null_mut();
        let mut owner_defaulted = 0;
        if unsafe {
            GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut owner_defaulted)
        } == 0
            || owner.is_null()
            || unsafe { EqualSid(owner, admins) } == 0
        {
            return Err("custody owner is not BUILTIN\\Administrators (fail-closed)".into());
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl = ptr::null_mut();
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err("custody DACL is absent".into());
        }
        let mut info = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
                AclSizeInformation,
            )
        } == 0
            || info.AceCount != if daemon.is_some() { 3 } else { 2 }
        {
            return Err("custody DACL has unexpected ACE count".into());
        }
        for (index, expected) in [system, admins].into_iter().enumerate() {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, u32::try_from(index).unwrap_or(u32::MAX), &raw mut ace) } == 0
                || ace.is_null()
            {
                return Err("custody DACL ACE retrieval failed".into());
            }
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let ace_sid: PSID = (&raw const ace.SidStart).cast_mut().cast();
            if ace.Header.AceType != 0
                || ace.Header.AceFlags != expected_flags
                || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
                || ace.Mask != 0x001f_01ff
                || unsafe { EqualSid(ace_sid, expected) } == 0
            {
                return Err("custody DACL differs from exact SYSTEM/Admin policy".into());
            }
        }
        if let Some(expected) = daemon {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, 2, &raw mut ace) } == 0 || ace.is_null() {
                return Err("daemon-readable custody ACE retrieval failed".into());
            }
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let ace_sid: PSID = (&raw const ace.SidStart).cast_mut().cast();
            if ace.Header.AceType != 0
                || ace.Header.AceFlags != expected_flags
                || u32::from(ace.Header.AceFlags) & INHERITED_ACE != 0
                || ace.Mask != 0x0012_00a9
                || unsafe { EqualSid(ace_sid, expected) } == 0
            {
                return Err("custody DACL differs from exact daemon-read policy".into());
            }
        }
        Ok(())
    })();
    unsafe {
        let _ = LocalFree(system.cast());
        let _ = LocalFree(admins.cast());
        if let Some(daemon) = daemon {
            let _ = LocalFree(daemon.cast());
        }
        let _ = LocalFree(descriptor);
    }
    result.map_err(|error: String| format!("{}: {error}", path.display()))
}

fn verify_system_admin_custody(path: &Path) -> Result<(), String> {
    verify_custody(path, None)
}

fn verify_daemon_read_custody(path: &Path, daemon_sid: &str) -> Result<(), String> {
    verify_custody(path, Some(daemon_sid))
}

/// Return `true` only when this call created the exact directory. Existing
/// objects are verified but never re-ACL'd or otherwise adopted.
fn ensure_custody_dir(path: &Path, retained: &mut Vec<CustodyHandle>) -> Result<bool, String> {
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "{} is not a regular non-reparse directory",
                path.display()
            ));
        }
        verify_system_admin_custody(path)?;
        retained.push(open_custody_handle(path, true)?);
        return Ok(false);
    }
    let descriptor = CreationDescriptor::new(true)?;
    let attributes = descriptor.attributes();
    let name = wide(path.as_os_str());
    if unsafe { CreateDirectoryW(name.as_ptr(), &raw const attributes) } == 0 {
        return Err(format!(
            "create SYSTEM/Admin directory {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let handle = match open_custody_handle(path, true).and_then(|handle| {
        verify_system_admin_custody(path)?;
        Ok(handle)
    }) {
        Ok(handle) => handle,
        Err(error) => {
            let _ = std::fs::remove_dir(path);
            return Err(error);
        }
    };
    retained.push(handle);
    Ok(true)
}

fn ensure_daemon_read_dir(
    path: &Path,
    trusted_parent: &Path,
    daemon_sid: &str,
    retained: &mut Vec<CustodyHandle>,
) -> Result<bool, String> {
    if path.parent() != Some(trusted_parent) {
        return Err("daemon-readable directory must be the fixed Program Files leaf".into());
    }
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err("daemon Program Files path is not a regular directory".into());
        }
        verify_daemon_read_custody(path, daemon_sid)?;
        retained.push(open_custody_handle(path, true)?);
        return Ok(false);
    }
    let descriptor = CreationDescriptor::daemon_read(true, daemon_sid)?;
    let attributes = descriptor.attributes();
    let name = wide(path.as_os_str());
    if unsafe { CreateDirectoryW(name.as_ptr(), &raw const attributes) } == 0 {
        return Err(format!(
            "create daemon-readable directory {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let handle = open_custody_handle(path, true).and_then(|handle| {
        verify_daemon_read_custody(path, daemon_sid)?;
        Ok(handle)
    });
    match handle {
        Ok(handle) => {
            retained.push(handle);
            Ok(true)
        }
        Err(error) => {
            let _ = std::fs::remove_dir(path);
            Err(error)
        }
    }
}

fn ensure_custody_chain(
    path: &Path,
    trusted_base: &Path,
    retained: &mut Vec<CustodyHandle>,
) -> Result<Vec<PathBuf>, String> {
    let mut missing = Vec::new();
    let mut current = path;
    loop {
        match std::fs::symlink_metadata(current) {
            Ok(_) => break,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(current.to_path_buf());
                current = current
                    .parent()
                    .ok_or("Windows custody directory has no parent")?;
            }
            Err(error) => return Err(format!("inspect {}: {error}", current.display())),
        }
    }
    let metadata = std::fs::symlink_metadata(current).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a regular non-reparse directory",
            current.display()
        ));
    }
    if current != trusted_base {
        verify_system_admin_custody(current)?;
    }
    retained.push(open_custody_handle(current, true)?);
    missing.reverse();
    let mut created = Vec::new();
    for directory in missing {
        match ensure_custody_dir(&directory, retained) {
            Ok(true) => created.push(directory),
            Ok(false) => {
                // `ensure_custody_dir` retained no-delete handles for every
                // created leaf. Drop precisely those transaction handles
                // before exact reverse rollback; keeping them would make
                // RemoveDirectory fail on Windows.
                retained.retain(|handle| !created.iter().any(|path| path == &handle.final_path));
                rollback_created_dirs(&created);
                return Err("Windows custody path changed during creation (fail-closed)".into());
            }
            Err(error) => {
                retained.retain(|handle| !created.iter().any(|path| path == &handle.final_path));
                rollback_created_dirs(&created);
                return Err(error);
            }
        }
    }
    Ok(created)
}

fn rollback_created_dirs(created: &[PathBuf]) {
    for directory in created.iter().rev() {
        let _ = std::fs::remove_dir(directory);
    }
}

fn write_custodied_new(
    path: &Path,
    bytes: &[u8],
    retained: &mut Vec<CustodyHandle>,
) -> Result<(), String> {
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "refusing to replace unrecorded Windows custody file {}",
            path.display()
        ));
    }
    let descriptor = CreationDescriptor::new(false)?;
    let attributes = descriptor.attributes();
    let name = wide(path.as_os_str());
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "create SYSTEM/Admin file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    // Transfer this newly-created no-delete handle to std::fs only while the
    // write is in progress; retain a fresh pinned handle afterwards.
    let mut file = unsafe { std::fs::File::from_raw_handle(raw) };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("write {}: {error}", path.display()));
    }
    drop(file);
    verify_system_admin_custody(path)?;
    retained.push(open_custody_handle(path, false)?);
    Ok(())
}

fn write_daemon_read_new(
    path: &Path,
    bytes: &[u8],
    daemon_sid: &str,
    retained: &mut Vec<CustodyHandle>,
) -> Result<(), String> {
    if path.exists() || std::fs::symlink_metadata(path).is_ok() {
        return Err(format!(
            "refusing existing daemon-readable file {}",
            path.display()
        ));
    }
    let descriptor = CreationDescriptor::daemon_read(false, daemon_sid)?;
    let attributes = descriptor.attributes();
    let name = wide(path.as_os_str());
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "create daemon-readable file {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    let mut file = unsafe { std::fs::File::from_raw_handle(raw) };
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("write {}: {error}", path.display()));
    }
    drop(file);
    verify_daemon_read_custody(path, daemon_sid)?;
    retained.push(open_custody_handle(path, false)?);
    Ok(())
}

fn copy_custodied_new(
    source: &Path,
    destination: &Path,
    retained: &mut Vec<CustodyHandle>,
) -> Result<(), String> {
    let expected = hash_file(source)?;
    let descriptor = CreationDescriptor::new(false)?;
    let attributes = descriptor.attributes();
    let name = wide(destination.as_os_str());
    let raw = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            &raw const attributes,
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(format!(
            "create SYSTEM/Admin binary {}: {}",
            destination.display(),
            std::io::Error::last_os_error()
        ));
    }
    let result = (|| {
        let mut target = unsafe { std::fs::File::from_raw_handle(raw) };
        let mut input =
            std::fs::File::open(source).map_err(|e| format!("open broker source: {e}"))?;
        std::io::copy(&mut input, &mut target)
            .map_err(|e| format!("copy broker into custody: {e}"))?;
        target
            .sync_all()
            .map_err(|e| format!("sync broker binary: {e}"))?;
        drop(target);
        if hash_file(destination)? != expected || hash_file(source)? != expected {
            return Err("broker binary changed while copying (fail-closed)".into());
        }
        verify_system_admin_custody(destination)?;
        retained.push(open_custody_handle(destination, false)?);
        Ok(())
    })();
    if result.is_err() {
        // If target consumed raw it has already closed; removal is constrained
        // to the just-created fixed leaf.
        let _ = std::fs::remove_file(destination);
    }
    result
}

fn copy_daemon_read_new(
    source: &Path,
    destination: &Path,
    daemon_sid: &str,
    retained: &mut Vec<CustodyHandle>,
) -> Result<(), String> {
    let expected = hash_file(source)?;
    let source_file =
        std::fs::File::open(source).map_err(|error| format!("open daemon source: {error}"))?;
    let mut bytes = Vec::new();
    source_file
        .take(MAX_BROKER_IMAGE_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read daemon source: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_BROKER_IMAGE_BYTES {
        return Err("daemon source exceeds bounded image size".into());
    }
    write_daemon_read_new(destination, &bytes, daemon_sid, retained)?;
    if hash_file(destination)? != expected || hash_file(source)? != expected {
        return Err("daemon image changed while copying (fail-closed)".into());
    }
    Ok(())
}

fn installed_file_facts(path: &Path) -> Result<(u64, [u8; 16], String), String> {
    let file = std::fs::File::open(path)
        .map_err(|error| format!("open installed daemon image: {error}"))?;
    let mut info = std::mem::MaybeUninit::<FILE_ID_INFO>::uninit();
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            FileIdInfo,
            info.as_mut_ptr().cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).unwrap_or(u32::MAX),
        )
    } == 0
    {
        return Err(format!(
            "read installed daemon FILE_ID_INFO: {}",
            std::io::Error::last_os_error()
        ));
    }
    let info = unsafe { info.assume_init() };
    Ok((
        info.VolumeSerialNumber,
        info.FileId.Identifier,
        hash_file(path)?,
    ))
}

fn hash_file(path: &Path) -> Result<String, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(format!(
            "{} is not a regular non-reparse file",
            path.display()
        ));
    }
    if metadata.len() > MAX_BROKER_IMAGE_BYTES {
        return Err(format!(
            "{} exceeds broker image byte ceiling",
            path.display()
        ));
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if opened.len() != metadata.len() || opened.len() > MAX_BROKER_IMAGE_BYTES {
        return Err("broker image changed or exceeded bound while opening (fail-closed)".into());
    }
    let mut digest = Sha256::new();
    let mut buffer = vec![0_u8; 64 * 1024];
    let mut read = 0_u64;
    loop {
        let count = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if count == 0 {
            break;
        }
        read = read
            .checked_add(u64::try_from(count).unwrap_or(u64::MAX))
            .ok_or("broker image length overflow")?;
        if read > MAX_BROKER_IMAGE_BYTES {
            return Err("broker image exceeds byte ceiling while hashing".into());
        }
        digest.update(&buffer[..count]);
    }
    if read != opened.len() {
        return Err("broker image length changed while hashing (fail-closed)".into());
    }
    Ok(hex::encode(digest.finalize()))
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
                (&raw mut status).cast(),
                u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX),
                &raw mut needed,
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
        unsafe { OpenProcessToken(process, TOKEN_QUERY, &raw mut token) } != 0 && !token.is_null();
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
            let _ = GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &raw mut need);
        }
        if need == 0 {
            return Err("query daemon TokenUser size".into());
        }
        let mut bytes = vec![0_u8; need as usize];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                bytes.as_mut_ptr().cast(),
                need,
                &raw mut need,
            )
        } == 0
        {
            return Err(format!(
                "query daemon TokenUser: {}",
                std::io::Error::last_os_error()
            ));
        }
        if bytes.len() < std::mem::size_of::<TOKEN_USER>() {
            return Err("daemon TokenUser buffer is too short".into());
        }
        let user = unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<TOKEN_USER>()) };
        let sid_len = unsafe { GetLengthSid(user.User.Sid) };
        if sid_len == 0 {
            return Err("daemon TokenUser SID is invalid".into());
        }
        let sid_bytes =
            unsafe { std::slice::from_raw_parts(user.User.Sid.cast::<u8>(), sid_len as usize) };
        let mut sid_text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &raw mut sid_text) } == 0
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
        if unsafe { ProcessIdToSessionId(pid, &raw mut session) } == 0 {
            return Err("read daemon session id".into());
        }
        let mut integrity_need = 0_u32;
        unsafe {
            let _ = GetTokenInformation(
                token,
                TokenIntegrityLevel,
                ptr::null_mut(),
                0,
                &raw mut integrity_need,
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
                &raw mut integrity_need,
            )
        } == 0
        {
            return Err("query daemon integrity level".into());
        }
        if integrity_bytes.len() < std::mem::size_of::<TOKEN_MANDATORY_LABEL>() {
            return Err("daemon integrity buffer is too short".into());
        }
        let label = unsafe {
            std::ptr::read_unaligned(integrity_bytes.as_ptr().cast::<TOKEN_MANDATORY_LABEL>())
        };
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
    let image = daemon_binary_path()?;
    let pid = unsafe { GetCurrentProcessId() };
    let (daemon_pipe_sid, daemon_token_sid, _, _) = process_token_identity(pid)?;
    if daemon_pipe_sid == "S-1-5-18" {
        return Err("Windows current-user agent trust cannot use LocalSystem".into());
    }
    verify_daemon_read_custody(
        image
            .parent()
            .ok_or("installed daemon image has no parent")?,
        &daemon_pipe_sid,
    )?;
    verify_daemon_read_custody(&image, &daemon_pipe_sid)?;
    let canonical = std::fs::canonicalize(&image)
        .map_err(|error| format!("canonicalize installed ownmeshd image: {error}"))?;
    let (image_volume_serial, image_file_id, image_sha256) = installed_file_facts(&canonical)?;
    Ok(crate::WindowsDaemonTrustRecord {
        daemon_pipe_sid,
        daemon_token_sid,
        daemon_service_name: WINDOWS_USER_AGENT_TRUST.into(),
        daemon_session_id: 0,
        daemon_integrity_rid: 0x2000,
        image_path: canonical,
        image_volume_serial,
        image_file_id: hex::encode(image_file_id),
        image_sha256,
        service_config_generation: 1,
    })
}

fn create_or_validate_service(binary: &Path, config: &Path) -> Result<bool, String> {
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
    let local_system = wide(OsStr::new("LocalSystem"));
    let service = unsafe {
        CreateServiceW(
            manager,
            service_name.as_ptr(),
            display.as_ptr(),
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            command.as_ptr(),
            ptr::null(),
            ptr::null_mut(),
            ptr::null(),
            local_system.as_ptr(),
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
        let existing = unsafe { OpenServiceW(manager, service_name.as_ptr(), SERVICE_ALL_ACCESS) };
        if existing.is_null() {
            unsafe {
                let _ = CloseServiceHandle(manager);
            }
            return Err("open existing broker service for idempotence".into());
        }
        if let Err(error) = validate_service_config(existing, binary, config)
            .and_then(|()| validate_service_custody(existing))
        {
            unsafe {
                let _ = CloseServiceHandle(existing);
                let _ = CloseServiceHandle(manager);
            }
            return Err(error);
        }
        unsafe {
            let _ = CloseServiceHandle(existing);
        }
    } else {
        let validation = set_service_custody(service)
            .and_then(|()| validate_service_config(service, binary, config))
            .and_then(|()| validate_service_custody(service));
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        validation?;
    }
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    Ok(!service.is_null())
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ServiceConfigSnapshot {
    command: String,
    service_type: u32,
    start_type: u32,
    error_control: u32,
    load_order_group_empty: bool,
    tag_id: u32,
    dependencies_empty: bool,
    account: String,
}

fn service_config_matches_broker_policy(
    actual: &ServiceConfigSnapshot,
    binary: &Path,
    config: &Path,
) -> bool {
    actual.command == command_line(binary, config)
        && actual.service_type == SERVICE_WIN32_OWN_PROCESS
        && actual.start_type == SERVICE_AUTO_START
        && actual.error_control == SERVICE_ERROR_NORMAL
        && actual.load_order_group_empty
        && actual.tag_id == 0
        && actual.dependencies_empty
        && actual.account.eq_ignore_ascii_case("LocalSystem")
}

fn query_service_config(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<ServiceConfigSnapshot, String> {
    fn returned_string(
        ptr: *mut u16,
        start: usize,
        end: usize,
        label: &str,
    ) -> Result<String, String> {
        if ptr.is_null() {
            return Ok(String::new());
        }
        let current = ptr as usize;
        if current < start || current >= end {
            return Err(format!(
                "broker SCM {label} pointer escapes returned buffer"
            ));
        }
        let raw = unsafe {
            std::slice::from_raw_parts(ptr, (end - current) / std::mem::size_of::<u16>())
        };
        let nul = raw
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| format!("broker SCM {label} lacks terminator"))?;
        String::from_utf16(&raw[..nul]).map_err(|_| format!("broker SCM {label} is not UTF-16"))
    }
    fn empty_multisz(ptr: *mut u16, start: usize, end: usize) -> Result<bool, String> {
        if ptr.is_null() {
            return Ok(true);
        }
        let current = ptr as usize;
        if current < start || current >= end {
            return Err("broker SCM dependency pointer escapes returned buffer".into());
        }
        let raw = unsafe {
            std::slice::from_raw_parts(ptr, (end - current) / std::mem::size_of::<u16>())
        };
        Ok(raw.len() >= 2 && raw[0] == 0 && raw[1] == 0)
    }

    let mut needed = 0_u32;
    let _ = unsafe { QueryServiceConfigW(service, ptr::null_mut(), 0, &raw mut needed) };
    if needed < u32::try_from(std::mem::size_of::<QUERY_SERVICE_CONFIGW>()).unwrap_or(u32::MAX) {
        return Err("query broker SCM command size".into());
    }
    let words = usize::try_from(needed)
        .map_err(|_| "broker SCM command length overflow")?
        .div_ceil(std::mem::size_of::<usize>());
    let mut buffer = vec![0_usize; words];
    if unsafe { QueryServiceConfigW(service, buffer.as_mut_ptr().cast(), needed, &raw mut needed) }
        == 0
    {
        return Err(format!(
            "query broker SCM command: {}",
            std::io::Error::last_os_error()
        ));
    }
    let config = unsafe { &*buffer.as_ptr().cast::<QUERY_SERVICE_CONFIGW>() };
    let start = buffer.as_ptr() as usize;
    let end = start
        .checked_add(buffer.len() * std::mem::size_of::<usize>())
        .ok_or("broker SCM command buffer overflow")?;
    Ok(ServiceConfigSnapshot {
        command: returned_string(config.lpBinaryPathName, start, end, "command")?,
        service_type: config.dwServiceType,
        start_type: config.dwStartType,
        error_control: config.dwErrorControl,
        load_order_group_empty: returned_string(
            config.lpLoadOrderGroup,
            start,
            end,
            "load-order group",
        )?
        .is_empty(),
        tag_id: config.dwTagId,
        dependencies_empty: empty_multisz(config.lpDependencies, start, end)?,
        account: returned_string(config.lpServiceStartName, start, end, "account")?,
    })
}

fn validate_service_config(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
    binary: &Path,
    config: &Path,
) -> Result<(), String> {
    let actual = query_service_config(service)?;
    if !service_config_matches_broker_policy(&actual, binary, config) {
        return Err("existing broker SCM service differs from exact OwnMesh LocalSystem policy; refusing adoption".into());
    }
    Ok(())
}

fn set_service_custody(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<(), String> {
    let descriptor = CreationDescriptor::service()?;
    if unsafe {
        SetServiceObjectSecurity(
            service,
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor.raw,
        )
    } == 0
    {
        return Err("set exact SYSTEM/Admin broker service DACL".into());
    }
    Ok(())
}

fn validate_service_custody(
    service: windows_sys::Win32::System::Services::SC_HANDLE,
) -> Result<(), String> {
    let mut needed = 0_u32;
    let _ = unsafe {
        QueryServiceObjectSecurity(
            service,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            0,
            &raw mut needed,
        )
    };
    if needed == 0 || needed > 64 * 1024 {
        return Err("query broker service security descriptor".into());
    }
    let mut bytes = vec![0_u8; needed as usize];
    if unsafe {
        QueryServiceObjectSecurity(
            service,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            bytes.as_mut_ptr().cast(),
            needed,
            &raw mut needed,
        )
    } == 0
    {
        return Err("read broker service security descriptor".into());
    }
    // Reuse the exact SDDL's owner/DACL comparison by proving the descriptor
    // has a protected DACL and the only two full-control principals. This also
    // rejects an interactive/shared service that happens to have our command.
    let descriptor = bytes.as_mut_ptr().cast::<std::ffi::c_void>();
    let mut control = 0_u16;
    let mut revision = 0_u32;
    if unsafe { GetSecurityDescriptorControl(descriptor, &raw mut control, &raw mut revision) } == 0
        || control & SE_DACL_PROTECTED == 0
    {
        return Err("broker service DACL is not protected".into());
    }
    let admins = {
        let text = wide(OsStr::new("S-1-5-32-544"));
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut sid) } == 0 {
            return Err("parse Administrators SID".into());
        }
        sid
    };
    let system = {
        let text = wide(OsStr::new("S-1-5-18"));
        let mut sid = ptr::null_mut();
        if unsafe { ConvertStringSidToSidW(text.as_ptr(), &raw mut sid) } == 0 {
            unsafe {
                let _ = LocalFree(admins.cast());
            }
            return Err("parse SYSTEM SID".into());
        }
        sid
    };
    let result = (|| {
        let mut owner = ptr::null_mut();
        let mut defaulted = 0;
        if unsafe { GetSecurityDescriptorOwner(descriptor, &raw mut owner, &raw mut defaulted) }
            == 0
            || owner.is_null()
            || unsafe { EqualSid(owner, admins) } == 0
        {
            return Err("broker service owner is not BUILTIN\\Administrators".into());
        }
        let mut present = 0;
        let mut dacl = ptr::null_mut();
        if unsafe {
            GetSecurityDescriptorDacl(
                descriptor,
                &raw mut present,
                &raw mut dacl,
                &raw mut defaulted,
            )
        } == 0
            || present == 0
            || dacl.is_null()
        {
            return Err("broker service DACL is absent".into());
        }
        let mut info = unsafe { std::mem::zeroed::<ACL_SIZE_INFORMATION>() };
        if unsafe {
            GetAclInformation(
                dacl,
                (&raw mut info).cast(),
                u32::try_from(std::mem::size_of::<ACL_SIZE_INFORMATION>()).unwrap_or(u32::MAX),
                AclSizeInformation,
            )
        } == 0
            || info.AceCount != 2
        {
            return Err("broker service DACL is not exact".into());
        }
        for (index, expected) in [system, admins].into_iter().enumerate() {
            let mut ace = ptr::null_mut();
            if unsafe { GetAce(dacl, u32::try_from(index).unwrap_or(u32::MAX), &raw mut ace) } == 0
                || ace.is_null()
            {
                return Err("read broker service DACL ACE".into());
            }
            let ace = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let ace_sid: PSID = (&raw const ace.SidStart).cast_mut().cast();
            if ace.Header.AceType != 0
                || ace.Header.AceFlags != 0
                || ace.Mask != SERVICE_ALL_ACCESS
                || unsafe { EqualSid(ace_sid, expected) } == 0
            {
                return Err("broker service DACL differs from exact SYSTEM/Admin policy".into());
            }
        }
        Ok(())
    })();
    unsafe {
        let _ = LocalFree(system.cast());
        let _ = LocalFree(admins.cast());
    }
    result
}

fn start_and_attest(binary: &Path, expected_hash: &str) -> Result<(), String> {
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
    result?;
    let pid = query_service_pid(BROKER_SERVICE)?;
    let facts = windows_process_facts(pid)
        .map_err(|error| format!("attest running broker service PID: {error}"))?;
    if Path::new(facts.image_path()) != binary || hex::encode(facts.image_sha256()) != expected_hash
    {
        return Err("running broker service PID image differs from exact installed broker".into());
    }
    wait_named_pipe_ready(ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME)
}

fn wait_named_pipe_ready(pipe_name: &str) -> Result<(), String> {
    let pipe = wide(OsStr::new(pipe_name));
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if unsafe { WaitNamedPipeW(pipe.as_ptr(), 200) } != 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "broker named pipe did not become ready after SCM reported RUNNING: {}",
                std::io::Error::last_os_error()
            ));
        }
    }
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
                (&raw mut status).cast(),
                u32::try_from(std::mem::size_of::<SERVICE_STATUS_PROCESS>()).unwrap_or(u32::MAX),
                &raw mut needed,
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

fn wait_service_absent(
    manager: windows_sys::Win32::System::Services::SC_HANDLE,
    name: &[u16],
) -> Result<(), String> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
        if service.is_null() {
            match std::io::Error::last_os_error().raw_os_error() {
                Some(ERROR_SERVICE_DOES_NOT_EXIST) => return Ok(()),
                Some(ERROR_SERVICE_MARKED_FOR_DELETE) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(200));
                    continue;
                }
                _ => return Err("broker SCM service did not become absent after delete".into()),
            }
        }
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        if Instant::now() >= deadline {
            return Err("broker SCM service remains present after delete".into());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn fixed_windows_artifacts_present() -> Result<bool, String> {
    let root = data_root()?;
    Ok(root.exists()
        || binary_path()?.exists()
        || daemon_binary_path()?.exists()
        || client_secret_path()?.exists()
        || root.join(CONFIG_NAME).exists()
        || root.join(TRUST_NAME).exists()
        || root.join(SECRET_NAME).exists()
        || root.join(SIGNING_NAME).exists()
        || root.join(LEDGER_NAME).exists()
        || root.join(STAGING_NAME).exists())
}

fn broker_service_exists() -> Result<bool, String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("open SCM for Windows broker custody probe".into());
    }
    let name = wide(OsStr::new(BROKER_SERVICE));
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS) };
    let result = if service.is_null() {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(false),
            Some(ERROR_SERVICE_MARKED_FOR_DELETE) => Ok(true),
            _ => Err("probe broker SCM service".into()),
        }
    } else {
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        Ok(true)
    };
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    result
}

fn rollback_created_service() -> Result<(), String> {
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("open SCM for broker rollback".into());
    }
    let name = wide(OsStr::new(BROKER_SERVICE));
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_ALL_ACCESS) };
    let result = if service.is_null() {
        match std::io::Error::last_os_error().raw_os_error() {
            Some(ERROR_SERVICE_DOES_NOT_EXIST) => Ok(()),
            _ => Err("open transaction-created broker service for rollback".into()),
        }
    } else {
        let mut ignored = unsafe { std::mem::zeroed::<SERVICE_STATUS>() };
        let _ = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &raw mut ignored) };
        let stopped = wait_service_state(service, SERVICE_STOPPED);
        let deleted = stopped.and_then(|()| {
            if unsafe { DeleteService(service) } == 0 {
                Err("delete transaction-created broker service during rollback".into())
            } else {
                Ok(())
            }
        });
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        deleted.and_then(|()| wait_service_absent(manager, &name))
    };
    unsafe {
        let _ = CloseServiceHandle(manager);
    }
    result
}

fn rollback_transaction_artifacts(
    created_files: &[PathBuf],
    created_dirs: &[PathBuf],
) -> Result<(), String> {
    for file in created_files.iter().rev() {
        std::fs::remove_file(file).map_err(|error| {
            format!(
                "rollback transaction-created file {}: {error}",
                file.display()
            )
        })?;
    }
    for directory in created_dirs.iter().rev() {
        std::fs::remove_dir(directory).map_err(|error| {
            format!(
                "rollback transaction-created directory {}: {error}",
                directory.display()
            )
        })?;
    }
    Ok(())
}

fn with_windows_install_preflight<T>(
    preflight: impl FnOnce() -> Result<(), String>,
    install: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    preflight()?;
    install()
}

pub fn install_windows_broker(_base: &Path) -> Result<InstallRecord, String> {
    // This is intentionally the first operation: a non-admin invocation must
    // not create a ProgramData/ProgramFiles directory or alter any DACL.
    with_windows_install_preflight(
        require_elevated_scm_admin,
        install_windows_broker_after_preflight,
    )
}

fn install_windows_broker_after_preflight() -> Result<InstallRecord, String> {
    let program_data = known_folder(&FOLDERID_ProgramData)?;
    let program_files = known_folder(&FOLDERID_ProgramFiles)?;
    let root = program_data.join("OwnMesh").join("broker");
    let config_path = config_path()?;
    let trust_path = root.join(TRUST_NAME);
    let staging = root.join(STAGING_NAME);
    let destination = program_files.join("OwnMesh").join("ownmesh-broker.exe");
    let daemon_destination = program_files.join("OwnMesh").join(DAEMON_BINARY_NAME);
    let client_secret = program_files.join("OwnMesh").join(CLIENT_SECRET_NAME);
    let binary_parent = destination
        .parent()
        .ok_or("Windows broker binary lacks parent")?;
    let mut retained = Vec::<CustodyHandle>::new();
    // Anchor the KnownFolder roots before walking their fixed OwnMesh leaves;
    // later revalidation catches a mount/junction or rename swap in either
    // ancestry chain without granting custody to the roots themselves.
    retained.push(open_custody_handle(&program_data, true)?);
    retained.push(open_custody_handle(&program_files, true)?);
    let mut created_dirs = ensure_custody_chain(&root, &program_data, &mut retained)?;
    let mut created_files = Vec::<PathBuf>::new();
    let mut created_service = false;
    let outcome = (|| {
        let (daemon_pipe_sid, _, _, _) = process_token_identity(unsafe { GetCurrentProcessId() })?;
        if daemon_pipe_sid == "S-1-5-18" {
            return Err(
                "Windows broker must be installed for a non-System interactive user".into(),
            );
        }
        if ensure_custody_dir(&staging, &mut retained)? {
            created_dirs.push(staging.clone());
        }
        if ensure_daemon_read_dir(
            binary_parent,
            &program_files,
            &daemon_pipe_sid,
            &mut retained,
        )? {
            created_dirs.push(binary_parent.to_path_buf());
        }
        let source = std::env::current_exe().map_err(|e| e.to_string())?;
        let created_binary = if destination.exists() {
            verify_system_admin_custody(&destination)?;
            retained.push(open_custody_handle(&destination, false)?);
            if hash_file(&destination)? != hash_file(&source)? {
                return Err(
                    "fixed broker binary differs from invoking binary; refusing overwrite".into(),
                );
            }
            false
        } else {
            copy_custodied_new(&source, &destination, &mut retained)?;
            created_files.push(destination.clone());
            true
        };
        let daemon_source = source.with_file_name(DAEMON_BINARY_NAME);
        if !daemon_source.is_file() {
            return Err("ownmeshd.exe must be installed beside ownmesh-broker.exe".into());
        }
        let created_daemon = if daemon_destination.exists() {
            verify_daemon_read_custody(&daemon_destination, &daemon_pipe_sid)?;
            retained.push(open_custody_handle(&daemon_destination, false)?);
            if hash_file(&daemon_destination)? != hash_file(&daemon_source)? {
                return Err("fixed ownmeshd image differs from invoking release".into());
            }
            false
        } else {
            copy_daemon_read_new(
                &daemon_source,
                &daemon_destination,
                &daemon_pipe_sid,
                &mut retained,
            )?;
            created_files.push(daemon_destination.clone());
            true
        };
        let trust = daemon_trust_record()?;
        let created_trust = if trust_path.exists() {
            verify_system_admin_custody(&trust_path)?;
            retained.push(open_custody_handle(&trust_path, false)?);
            if load_windows_daemon_trust_record(&trust_path)?.record() != &trust {
                return Err("existing daemon trust record mismatches live SCM daemon identity; refusing adoption".into());
            }
            false
        } else {
            write_custodied_new(
                &trust_path,
                &serde_json::to_vec_pretty(&trust).map_err(|e| e.to_string())?,
                &mut retained,
            )?;
            created_files.push(trust_path.clone());
            true
        };
        let secret_path = root.join(SECRET_NAME);
        let created_secret = if secret_path.exists() {
            verify_system_admin_custody(&secret_path)?;
            retained.push(open_custody_handle(&secret_path, false)?);
            if std::fs::read(&secret_path)
                .map_err(|e| e.to_string())?
                .len()
                != BROKER_SECRET_BYTES
            {
                return Err("existing Windows broker request secret is malformed".into());
            }
            false
        } else {
            let secret = BrokerSecret::generate();
            write_custodied_new(&secret_path, secret.as_bytes(), &mut retained)?;
            created_files.push(secret_path.clone());
            true
        };
        let secret_bytes = std::fs::read(&secret_path).map_err(|error| error.to_string())?;
        let created_client_secret = if client_secret.exists() {
            verify_daemon_read_custody(&client_secret, &daemon_pipe_sid)?;
            retained.push(open_custody_handle(&client_secret, false)?);
            if std::fs::read(&client_secret).map_err(|error| error.to_string())? != secret_bytes {
                return Err("Windows daemon client secret differs from broker secret".into());
            }
            false
        } else {
            write_daemon_read_new(
                &client_secret,
                &secret_bytes,
                &daemon_pipe_sid,
                &mut retained,
            )?;
            created_files.push(client_secret.clone());
            true
        };
        let signing_path = root.join(SIGNING_NAME);
        let created_signing = if signing_path.exists() {
            verify_system_admin_custody(&signing_path)?;
            retained.push(open_custody_handle(&signing_path, false)?);
            CapabilitySigningKey::from_bytes(
                &std::fs::read(&signing_path).map_err(|e| e.to_string())?,
            )
            .map_err(|e| format!("existing Windows broker signing key: {e}"))?;
            false
        } else {
            let signing = CapabilitySigningKey::generate();
            write_custodied_new(&signing_path, &signing.to_bytes(), &mut retained)?;
            created_files.push(signing_path.clone());
            true
        };
        let ledger_path = root.join(LEDGER_NAME);
        let created_ledger = if ledger_path.exists() {
            verify_system_admin_custody(&ledger_path)?;
            retained.push(open_custody_handle(&ledger_path, false)?);
            false
        } else {
            // Match WindowsDurableReplayLedger's empty durable schema so the
            // service never has to create its first state file with defaults.
            write_custodied_new(
                &ledger_path,
                br#"{"version":1,"entries":{}}"#,
                &mut retained,
            )?;
            created_files.push(ledger_path.clone());
            true
        };
        let cfg = WindowsBrokerConfig {
            schema_version: 2,
            broker_service_name: BROKER_SERVICE.into(),
            daemon_service_name: WINDOWS_USER_AGENT_TRUST.into(),
            broker_binary: destination.clone(),
            trust_record: trust_path.clone(),
            request_secret: secret_path.clone(),
            signing_key: signing_path.clone(),
            replay_ledger: ledger_path,
            staging_dir: staging.clone(),
            broker_sha256: hash_file(&destination)?,
            trust_sha256: hash_file(&trust_path)?,
            secret_sha256: hash_file(&secret_path)?,
            signing_sha256: hash_file(&signing_path)?,
        };
        let created_config = if config_path.exists() {
            verify_system_admin_custody(&config_path)?;
            retained.push(open_custody_handle(&config_path, false)?);
            let existing: WindowsBrokerConfig =
                serde_json::from_slice(&std::fs::read(&config_path).map_err(|e| e.to_string())?)
                    .map_err(|e| format!("parse existing Windows broker config: {e}"))?;
            if existing != cfg {
                return Err("existing Windows broker config mismatch; refusing overwrite".into());
            }
            false
        } else {
            write_custodied_new(
                &config_path,
                &serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?,
                &mut retained,
            )?;
            created_files.push(config_path.clone());
            true
        };
        revalidate_retained(&retained)?;
        created_service = create_or_validate_service(&destination, &config_path)?;
        revalidate_retained(&retained)?;
        if let Err(error) = start_and_attest(&destination, &cfg.broker_sha256) {
            let _ = (
                created_config,
                created_trust,
                created_binary,
                created_daemon,
                created_secret,
                created_client_secret,
                created_signing,
                created_ledger,
            );
            return Err(error);
        }
        Ok(InstallRecord { installed: true, installed_at_unix: crate::now_unix(), endpoint: ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME.into(), endpoint_kind: "named_pipe".into(), unit_path: Some(BROKER_SERVICE.into()), secret_file: client_secret.display().to_string(), signing_key_file: cfg.signing_key.display().to_string(), verify_key_file: String::new(), trusted_executable: trust.image_path.display().to_string(), socket_owner_uid: 0, socket_group_gid: 0, socket_mode: 0, allowed_uids: vec![], daemon_uid: 0, daemon_gid: 0, broker_binary: destination.display().to_string(), config_path: config_path.display().to_string(), broker_sha256: hash_file(&destination)?, trusted_executable_sha256: trust.image_sha256, config_sha256: hash_file(&config_path)?, unit_sha256: String::new(), notes: vec!["Windows LocalSystem broker with current-user SID and immutable ownmeshd image trust".into()], support: "supported".into() })
    })();
    match outcome {
        Ok(record) => Ok(record),
        Err(error) => {
            if created_service {
                if let Err(rollback) = rollback_created_service() {
                    return Err(format!(
                        "broker install failed: {error}; transaction-created SCM service could not be removed safely: {rollback}; preserving transaction artifacts"
                    ));
                }
            }
            // Retained no-delete handles are a transaction fence, not a cleanup
            // mechanism. Release them before removing only objects this call made.
            drop(retained);
            if let Err(rollback) = rollback_transaction_artifacts(&created_files, &created_dirs) {
                return Err(format!(
                    "broker install failed: {error}; SCM rollback completed but artifact rollback failed: {rollback}"
                ));
            }
            Err(error)
        }
    }
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
    let attested: Result<(), String> = (|| {
        let raw = std::fs::read(&config).map_err(|e| format!("read Windows broker config: {e}"))?;
        let cfg = load_service_config()?;
        if raw != serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?
            || hash_file(&cfg.broker_binary)? != cfg.broker_sha256
            || hash_file(&cfg.trust_record)? != cfg.trust_sha256
            || hash_file(&cfg.request_secret)? != cfg.secret_sha256
            || hash_file(&cfg.signing_key)? != cfg.signing_sha256
        {
            return Err("Windows broker custody hashes differ from config".into());
        }
        for path in [
            &cfg.broker_binary,
            &cfg.trust_record,
            &cfg.request_secret,
            &cfg.signing_key,
            &cfg.replay_ledger,
        ] {
            verify_system_admin_custody(path)?;
        }
        verify_system_admin_custody(&cfg.staging_dir)?;
        let trusted = load_windows_daemon_trust_record(&cfg.trust_record)?;
        verify_daemon_read_custody(&daemon_binary_path()?, &trusted.record().daemon_pipe_sid)?;
        verify_daemon_read_custody(&client_secret_path()?, &trusted.record().daemon_pipe_sid)?;
        if std::fs::read(client_secret_path()?).map_err(|error| error.to_string())?
            != std::fs::read(&cfg.request_secret).map_err(|error| error.to_string())?
        {
            return Err("Windows daemon client secret differs from broker secret".into());
        }
        let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
        if manager.is_null() {
            return Err("open SCM for Windows broker status".into());
        }
        let name = wide(OsStr::new(BROKER_SERVICE));
        let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_ALL_ACCESS) };
        if service.is_null() {
            unsafe {
                let _ = CloseServiceHandle(manager);
            }
            return Err("open broker SCM service for status".into());
        }
        let service_result = validate_service_config(service, &cfg.broker_binary, &config)
            .and_then(|()| validate_service_custody(service));
        unsafe {
            let _ = CloseServiceHandle(service);
            let _ = CloseServiceHandle(manager);
        }
        service_result?;
        let pid = query_service_pid(BROKER_SERVICE)?;
        let facts =
            windows_process_facts(pid).map_err(|e| format!("attest broker service PID: {e}"))?;
        if Path::new(facts.image_path()) != cfg.broker_binary
            || hex::encode(facts.image_sha256()) != cfg.broker_sha256
        {
            return Err("broker service PID image differs from fixed binary".into());
        }
        let pipe = wide(OsStr::new(
            ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME,
        ));
        if unsafe { WaitNamedPipeW(pipe.as_ptr(), 0) } == 0 {
            return Err("broker named pipe is not live".into());
        }
        Ok(())
    })();
    let installed = attested.is_ok();
    Ok(InstallStatus {
        installed,
        network: "disabled",
        endpoint: Some(ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME.into()),
        endpoint_kind: "named_pipe".into(),
        secret_present: false,
        signing_key_present: false,
        verify_key_present: false,
        unit_path: Some(BROKER_SERVICE.into()),
        notes: if installed {
            vec!["Windows broker is running with current-user SID and immutable image trust".into()]
        } else {
            vec![format!(
                "Windows broker custody/service validation failed: {}",
                attested
                    .err()
                    .unwrap_or_else(|| "service is not running".into())
            )]
        },
        support: if installed {
            "supported"
        } else {
            "unsupported"
        }
        .into(),
    })
}

pub fn uninstall_windows_broker(_base: &Path) -> Result<(), String> {
    // The complete custody proof is deliberately collected before stopping the
    // service. A foreign/tampered install must leave *everything* untouched.
    require_elevated_scm_admin()?;
    let config_path = config_path()?;
    if !config_path.exists() {
        // Idempotence is safe only for the known empty state; never sweep a
        // same-named service or a residual ProgramData tree without its record.
        if fixed_windows_artifacts_present()? || broker_service_exists()? {
            return Err("Windows broker residual/foreign artifact exists without its custody record; refusing uninstall".into());
        }
        return Ok(());
    }
    let raw_config =
        std::fs::read(&config_path).map_err(|e| format!("read Windows broker config: {e}"))?;
    let cfg = load_service_config()?;
    let canonical_config = serde_json::to_vec_pretty(&cfg).map_err(|e| e.to_string())?;
    if raw_config != canonical_config
        || hash_file(&cfg.broker_binary)? != cfg.broker_sha256
        || hash_file(&cfg.trust_record)? != cfg.trust_sha256
        || hash_file(&cfg.request_secret)? != cfg.secret_sha256
        || hash_file(&cfg.signing_key)? != cfg.signing_sha256
    {
        return Err("Windows broker config, trust record, or binary hash mismatches custody record; refusing uninstall".into());
    }
    verify_system_admin_custody(&cfg.broker_binary)?;
    verify_system_admin_custody(&cfg.trust_record)?;
    for file in [&cfg.request_secret, &cfg.signing_key, &cfg.replay_ledger] {
        if file.exists() {
            verify_system_admin_custody(file)?;
        }
    }
    if cfg.staging_dir.exists() {
        verify_system_admin_custody(&cfg.staging_dir)?;
        if std::fs::read_dir(&cfg.staging_dir)
            .map_err(|e| format!("inspect Windows broker staging: {e}"))?
            .next()
            .is_some()
        {
            return Err(
                "Windows broker staging contains unrecorded artifacts; refusing uninstall".into(),
            );
        }
    }
    // The trust record is tied to a live SCM-attested daemon, rather than only
    // being syntactically valid JSON left by a previous process.
    let trusted = load_windows_daemon_trust_record(&cfg.trust_record)?;
    if trusted.record() != &daemon_trust_record()? {
        return Err(
            "Windows daemon trust identity differs from live SCM daemon; refusing uninstall".into(),
        );
    }
    let manager = unsafe { OpenSCManagerW(ptr::null(), ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return Err("open SCM for broker uninstall".into());
    }
    let name = wide(OsStr::new(BROKER_SERVICE));
    let service = unsafe { OpenServiceW(manager, name.as_ptr(), SERVICE_ALL_ACCESS) };
    if service.is_null() {
        let absent =
            std::io::Error::last_os_error().raw_os_error() == Some(ERROR_SERVICE_DOES_NOT_EXIST);
        unsafe {
            let _ = CloseServiceHandle(manager);
        }
        if !absent {
            return Err("open broker SCM service for uninstall".into());
        }
        // Idempotent recovery: the prior uninstall may have reached SCM
        // deletion and crashed before removing the exact, pre-validated files.
        // Continue with artifact cleanup below; never treat service absence as
        // permission to sweep a record we have not already proved belongs to us.
    } else {
        if let Err(error) = validate_service_config(service, &cfg.broker_binary, &config_path)
            .and_then(|()| validate_service_custody(service))
        {
            unsafe {
                let _ = CloseServiceHandle(service);
                let _ = CloseServiceHandle(manager);
            }
            return Err(error);
        }
        let mut ignored = unsafe { std::mem::zeroed::<SERVICE_STATUS>() };
        let _ = unsafe { ControlService(service, SERVICE_CONTROL_STOP, &raw mut ignored) };
        if let Err(error) = wait_service_state(service, SERVICE_STOPPED) {
            unsafe {
                let _ = CloseServiceHandle(service);
                let _ = CloseServiceHandle(manager);
            }
            return Err(error);
        }
        if unsafe { DeleteService(service) } == 0 {
            unsafe {
                let _ = CloseServiceHandle(service);
                let _ = CloseServiceHandle(manager);
            }
            return Err("delete broker SCM service".into());
        }
        unsafe {
            let _ = CloseServiceHandle(service);
        }
        // SCM deletion is asynchronous. A marked-for-delete service is still
        // present; wait until SCM reports ERROR_SERVICE_DOES_NOT_EXIST before
        // any file removal.
        let absence = wait_service_absent(manager, &name);
        unsafe {
            let _ = CloseServiceHandle(manager);
        }
        absence?;
    }

    for (file, hash) in [
        (&cfg.request_secret, Some(cfg.secret_sha256.as_str())),
        (&cfg.signing_key, Some(cfg.signing_sha256.as_str())),
        (&cfg.replay_ledger, None),
        (&cfg.trust_record, Some(cfg.trust_sha256.as_str())),
        (&cfg.broker_binary, Some(cfg.broker_sha256.as_str())),
        (&config_path, None),
    ] {
        if file.exists() {
            verify_system_admin_custody(file)?;
            if let Some(expected) = hash {
                if hash_file(file)? != expected {
                    return Err(format!(
                        "{} changed after uninstall preflight",
                        file.display()
                    ));
                }
            }
            std::fs::remove_file(file).map_err(|e| {
                format!(
                    "remove owned Windows broker artifact {}: {e}",
                    file.display()
                )
            })?;
        }
    }
    for file in [client_secret_path()?, daemon_binary_path()?] {
        if file.exists() {
            verify_daemon_read_custody(&file, &trusted.record().daemon_pipe_sid)?;
            std::fs::remove_file(&file).map_err(|error| {
                format!(
                    "remove daemon-readable artifact {}: {error}",
                    file.display()
                )
            })?;
        }
    }
    if cfg.staging_dir.exists() {
        verify_system_admin_custody(&cfg.staging_dir)?;
        std::fs::remove_dir(&cfg.staging_dir)
            .map_err(|e| format!("remove owned staging directory: {e}"))?;
    }
    for directory in [
        data_root()?,
        data_root()?
            .parent()
            .ok_or("broker root has no parent")?
            .to_path_buf(),
    ] {
        if directory.exists() {
            verify_system_admin_custody(&directory)?;
            let _ = std::fs::remove_dir(&directory); // remove only empty exact custody directories
        }
    }
    let binary_parent = binary_path()?
        .parent()
        .ok_or("broker image has no parent")?
        .to_path_buf();
    if binary_parent.exists() {
        verify_daemon_read_custody(&binary_parent, &trusted.record().daemon_pipe_sid)?;
        let _ = std::fs::remove_dir(binary_parent);
    }
    Ok(())
}

fn load_service_config() -> Result<WindowsBrokerConfig, String> {
    let path = config_path()?;
    verify_system_admin_custody(&path)?;
    let cfg: WindowsBrokerConfig =
        serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
            .map_err(|e| format!("parse fixed Windows broker config: {e}"))?;
    if cfg.schema_version != 2
        || cfg.broker_service_name != BROKER_SERVICE
        || cfg.daemon_service_name != WINDOWS_USER_AGENT_TRUST
        || cfg.broker_binary != binary_path()?
        || cfg.trust_record != data_root()?.join(TRUST_NAME)
        || cfg.request_secret != data_root()?.join(SECRET_NAME)
        || cfg.signing_key != data_root()?.join(SIGNING_NAME)
        || cfg.replay_ledger != data_root()?.join(LEDGER_NAME)
        || cfg.staging_dir != data_root()?.join(STAGING_NAME)
        || cfg.broker_sha256.len() != 64
        || cfg.trust_sha256.len() != 64
        || cfg.secret_sha256.len() != 64
        || cfg.signing_sha256.len() != 64
    {
        return Err("Windows broker config differs from fixed production policy".into());
    }
    Ok(cfg)
}

/// Reattest the complete fixed Windows custody boundary immediately before an
/// ownmeshd elevated request. This safe facade stays in the existing native
/// Windows module so the daemon crate remains `#![forbid(unsafe_code)]`.
pub fn load_windows_daemon_broker_client(
    current_exe: &Path,
) -> Result<WindowsDaemonBrokerClient, String> {
    let live = daemon_trust_record()?;
    let running = std::fs::canonicalize(current_exe)
        .map_err(|error| format!("canonicalize running ownmeshd image: {error}"))?;
    let trusted = std::fs::canonicalize(&live.image_path)
        .map_err(|error| format!("canonicalize trusted ownmeshd image: {error}"))?;
    if running != trusted {
        return Err("running ownmeshd image differs from Windows trust record".into());
    }
    let facts = windows_process_facts(unsafe { GetCurrentProcessId() })
        .map_err(|error| format!("attest running ownmeshd process: {error}"))?;
    if !facts
        .image_path()
        .eq_ignore_ascii_case(trusted.to_string_lossy().as_ref())
        || facts.image_volume_serial() != live.image_volume_serial
        || hex::encode(facts.image_file_id()) != live.image_file_id
        || hex::encode(facts.image_sha256()) != live.image_sha256
    {
        return Err("running ownmeshd process image differs from installed trust facts".into());
    }
    facts
        .revalidate_process_birth()
        .map_err(|error| error.to_string())?;
    facts
        .revalidate_image()
        .map_err(|error| error.to_string())?;
    let secret_path = client_secret_path()?;
    verify_daemon_read_custody(&secret_path, &live.daemon_pipe_sid)?;
    let secret = BrokerSecret::from_bytes(
        std::fs::read(&secret_path)
            .map_err(|error| format!("read Windows broker request secret: {error}"))?,
    );
    if secret.as_bytes().len() != BROKER_SECRET_BYTES {
        return Err("Windows broker request secret has unexpected length".into());
    }
    let broker_binary = binary_path()?;
    let server_trust = WindowsBrokerTrust::new(BROKER_SERVICE, &broker_binary)
        .map_err(|error| format!("load fixed Windows broker server trust: {error}"))?;
    Ok(WindowsDaemonBrokerClient {
        endpoint: BrokerEndpoint::NamedPipe(
            ownmesh_ipc::LocalListener::SECURE_BROKER_PIPE_NAME.into(),
        ),
        request_secret: secret,
        server_trust,
        trusted_daemon_executable: trusted,
    })
}

fn report_windows_stop_pending() {
    let raw = SERVICE_STATUS_HANDLE_RAW.load(Ordering::Acquire);
    if raw == 0 {
        return;
    }
    let checkpoint = STOP_CHECKPOINT
        .fetch_add(1, Ordering::AcqRel)
        .saturating_add(1);
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_STOP_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: checkpoint,
        dwWaitHint: WAIT_LIMIT.as_millis().try_into().unwrap_or(u32::MAX),
    };
    // SAFETY: the SCM callback publishes the handle only while `service_main`
    // owns it, and clears it immediately before returning from that function.
    let _ = unsafe { SetServiceStatus(raw as SERVICE_STATUS_HANDLE, &raw const status) };
}

pub(crate) async fn shutdown_and_drain_windows_broker<A, L, R>(
    server: &Arc<WindowsProductionBrokerServer<A, L, R>>,
    connections: &mut JoinSet<Result<(), String>>,
) -> Result<(), String>
where
    A: WindowsPeerAuthorizer + 'static,
    L: WindowsReplayLedger + 'static,
    R: WindowsBrokerRunner + 'static,
{
    // This must happen on every exit path, including a broken pipe factory or
    // a handler panic. Dropping a JoinSet aborts async handlers but does not
    // stop their `spawn_blocking` Windows Job calls.
    server.begin_shutdown();
    report_windows_stop_pending();
    let deadline = Instant::now() + WAIT_LIMIT;
    let mut panic_error = None;
    while !connections.is_empty() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            connections.abort_all();
            return Err("Windows broker Jobs did not terminate before SCM stop deadline".into());
        }
        let slice = remaining.min(Duration::from_secs(1));
        match tokio::time::timeout(slice, connections.join_next()).await {
            Ok(Some(Ok(Ok(()) | Err(_)))) => {
                // Connection-local failures (notably a peer that disconnected
                // during its response write) are already fenced by the runner
                // and must not stop unrelated service traffic.
            }
            Ok(Some(Err(error))) => {
                // Keep draining after a panic: the durable reservation remains
                // Reserved/uncertain and `cancel_all` has fenced every Job.
                panic_error.get_or_insert_with(|| {
                    format!("Windows broker connection task panicked: {error}")
                });
            }
            Ok(None) => break,
            Err(_) => report_windows_stop_pending(),
        }
    }
    if let Some(error) = panic_error {
        Err(error)
    } else {
        Ok(())
    }
}

async fn run_windows_broker_service(
    ready: std::sync::mpsc::SyncSender<Result<(), String>>,
) -> Result<(), String> {
    let setup = async {
        let cfg = load_service_config()?;
        verify_system_admin_custody(&cfg.trust_record)?;
        let trusted = load_windows_daemon_trust_record(&cfg.trust_record)?;
        verify_system_admin_custody(&cfg.request_secret)?;
        verify_system_admin_custody(&cfg.signing_key)?;
        let secret_bytes = std::fs::read(&cfg.request_secret)
            .map_err(|e| format!("read Windows broker secret: {e}"))?;
        if secret_bytes.len() != BROKER_SECRET_BYTES
            || hash_file(&cfg.request_secret)? != cfg.secret_sha256
        {
            return Err("Windows broker request secret differs from exact custody record".into());
        }
        let secret = BrokerSecret::from_bytes(secret_bytes);
        let signing_key = CapabilitySigningKey::from_bytes(
            &std::fs::read(&cfg.signing_key)
                .map_err(|e| format!("read Windows broker signing key: {e}"))?,
        )
        .map_err(|e| format!("read Windows broker signing key: {e}"))?;
        if hash_file(&cfg.signing_key)? != cfg.signing_sha256 {
            return Err("Windows broker signing key differs from exact custody record".into());
        }
        let ledger = WindowsDurableReplayLedger::open(&cfg.replay_ledger, 16_384)?;
        let runner = WindowsJobRunner::new(&cfg.staging_dir)?;
        let daemon_pipe_sid = trusted.record().daemon_pipe_sid.clone();
        WindowsProductionBrokerServer::bind(
            &daemon_pipe_sid,
            trusted,
            ledger,
            runner,
            secret,
            signing_key,
        )
        .await
    }
    .await;
    let server = match setup {
        Ok(server) => server,
        Err(error) => {
            let _ = ready.send(Err(error.clone()));
            return Err(error);
        }
    };
    if ready.send(Ok(())).is_err() {
        return Err(
            "SCM service startup observer disconnected before broker pipe readiness".into(),
        );
    }
    let server = Arc::new(server);
    let mut connections = JoinSet::new();
    let mut stop_poll = tokio::time::interval(Duration::from_millis(200));
    let serve_result = loop {
        tokio::select! {
            joined = connections.join_next(), if !connections.is_empty() => {
                if let Some(Err(error)) = joined {
                    // Do not return early: all surviving Jobs must first be
                    // fenced and drained by the common shutdown path below.
                    break Err(format!("Windows broker connection task panicked: {error}"));
                }
            }
            accepted = server.accept_connection() => {
                match accepted {
                    Ok(connection) => match server.try_acquire_connection_permit() {
                        Ok(permit) => {
                            let server = Arc::clone(&server);
                            connections.spawn(async move {
                                server.serve_connection_with_permit(connection, permit).await
                            });
                        }
                        Err(_) => {
                            // Admission is full. Closing this unactioned pipe is
                            // bounded; never spawn a task merely to wait for a
                            // peer that may refuse to read a `busy` response.
                            drop(connection);
                        }
                    },
                    Err(error) => break Err(error),
                }
            }
            _ = stop_poll.tick() => if STOP_REQUESTED.load(Ordering::Acquire) { break Ok(()); },
        }
    };
    let drain_result = shutdown_and_drain_windows_broker(&server, &mut connections).await;
    match (serve_result, drain_result) {
        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

unsafe extern "system" fn service_control(control: u32) {
    if control == SERVICE_CONTROL_STOP {
        STOP_REQUESTED.store(true, Ordering::Release);
        report_windows_stop_pending();
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
    let name = wide(OsStr::new(BROKER_SERVICE));
    let handle = RegisterServiceCtrlHandlerW(name.as_ptr(), Some(service_control));
    if handle.is_null() {
        return;
    }
    SERVICE_STATUS_HANDLE_RAW.store(handle as isize, Ordering::Release);
    STOP_CHECKPOINT.store(0, Ordering::Release);
    let mut status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: SERVICE_START_PENDING,
        dwControlsAccepted: 0,
        dwWin32ExitCode: 0,
        dwServiceSpecificExitCode: 0,
        dwCheckPoint: 1,
        dwWaitHint: WAIT_LIMIT.as_millis().try_into().unwrap_or(u32::MAX),
    };
    let _ = SetServiceStatus(handle, &raw const status);
    let outcome = (|| -> Result<(), String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|error| format!("create Windows broker service runtime: {error}"))?;
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let worker = runtime.spawn(run_windows_broker_service(ready_tx));
        match ready_rx.recv_timeout(WAIT_LIMIT) {
            Ok(Ok(())) => {
                status.dwCurrentState = SERVICE_RUNNING;
                status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
                status.dwCheckPoint = 0;
                status.dwWaitHint = 0;
                if unsafe { SetServiceStatus(handle, &raw const status) } == 0 {
                    return Err("report broker pipe readiness to SCM".into());
                }
            }
            Ok(Err(error)) => return Err(error),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return Err("broker pipe did not bind before SCM startup deadline".into());
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                return Err("broker startup worker exited before pipe readiness".into());
            }
        }
        runtime
            .block_on(worker)
            .map_err(|error| format!("join Windows broker service worker: {error}"))?
    })();
    status.dwCurrentState = SERVICE_STOPPED;
    status.dwControlsAccepted = 0;
    if outcome.is_err() {
        status.dwWin32ExitCode = 1;
    }
    let _ = SetServiceStatus(handle, &raw const status);
    SERVICE_STATUS_HANDLE_RAW.store(0, Ordering::Release);
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_preflight_leaves_programdata_and_programfiles_test_paths_absent() {
        let temp = tempfile::tempdir().unwrap();
        let program_data = temp
            .path()
            .join("ProgramData")
            .join("OwnMesh")
            .join("broker");
        let program_files = temp.path().join("ProgramFiles").join("OwnMesh");
        let result = with_windows_install_preflight(
            || Err("requires elevation".into()),
            || {
                std::fs::create_dir_all(&program_data).unwrap();
                std::fs::create_dir_all(&program_files).unwrap();
                Ok(())
            },
        );
        assert!(result.is_err());
        assert!(
            !program_data.exists(),
            "denied preflight created ProgramData path"
        );
        assert!(
            !program_files.exists(),
            "denied preflight created ProgramFiles path"
        );
    }

    #[test]
    fn oversized_broker_image_is_rejected_without_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.exe");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_BROKER_IMAGE_BYTES + 1).unwrap();
        assert!(hash_file(&path).unwrap_err().contains("ceiling"));
    }

    fn exact_broker_service_config(binary: &Path, config: &Path) -> ServiceConfigSnapshot {
        ServiceConfigSnapshot {
            command: command_line(binary, config),
            service_type: SERVICE_WIN32_OWN_PROCESS,
            start_type: SERVICE_AUTO_START,
            error_control: SERVICE_ERROR_NORMAL,
            load_order_group_empty: true,
            tag_id: 0,
            dependencies_empty: true,
            account: "LocalSystem".into(),
        }
    }

    #[test]
    fn broker_service_policy_rejects_each_foreign_scm_field() {
        let binary = Path::new(r"C:\Program Files\OwnMesh\ownmesh-broker.exe");
        let config = Path::new(r"C:\ProgramData\OwnMesh\broker\broker-service.json");
        let exact = exact_broker_service_config(binary, config);
        assert!(service_config_matches_broker_policy(&exact, binary, config));

        let mut changed = exact.clone();
        changed.load_order_group_empty = false;
        assert!(!service_config_matches_broker_policy(
            &changed, binary, config
        ));
        changed = exact.clone();
        changed.tag_id = 1;
        assert!(!service_config_matches_broker_policy(
            &changed, binary, config
        ));
        changed = exact.clone();
        changed.dependencies_empty = false;
        assert!(!service_config_matches_broker_policy(
            &changed, binary, config
        ));
        changed = exact.clone();
        changed.account = "NT AUTHORITY\\NetworkService".into();
        assert!(!service_config_matches_broker_policy(
            &changed, binary, config
        ));
        changed = exact.clone();
        changed.start_type = 3;
        assert!(!service_config_matches_broker_policy(
            &changed, binary, config
        ));
    }

    #[test]
    fn creation_descriptors_parse_to_their_exact_object_masks() {
        fn masks(descriptor: &CreationDescriptor) -> Vec<u32> {
            let mut present = 0;
            let mut defaulted = 0;
            let mut dacl = ptr::null_mut();
            assert_ne!(
                unsafe {
                    GetSecurityDescriptorDacl(
                        descriptor.raw,
                        &raw mut present,
                        &raw mut dacl,
                        &raw mut defaulted,
                    )
                },
                0
            );
            assert_eq!(present, 1);
            assert!(!dacl.is_null());
            (0..2)
                .map(|index| {
                    let mut ace = ptr::null_mut();
                    assert_ne!(unsafe { GetAce(dacl, index, &raw mut ace) }, 0);
                    unsafe { (*ace.cast::<ACCESS_ALLOWED_ACE>()).Mask }
                })
                .collect()
        }

        let file = CreationDescriptor::new(false).unwrap();
        let service = CreationDescriptor::service().unwrap();
        assert_eq!(masks(&file), vec![0x001f_01ff; 2]);
        assert_eq!(masks(&service), vec![SERVICE_ALL_ACCESS; 2]);
    }

    #[test]
    fn generated_request_secret_has_the_exact_required_length() {
        assert_eq!(
            BrokerSecret::generate().as_bytes().len(),
            BROKER_SECRET_BYTES
        );
    }
}
