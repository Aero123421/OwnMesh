//! Narrow macOS Unix-socket peer attestation facade.
//!
//! `LOCAL_PEERTOKEN` binds the accepted socket to an audit token containing
//! the effective UID/GID, PID, and PID-version. `proc_pidpath_audittoken`
//! resolves the executable for that exact token, so PID reuse cannot redirect
//! the lookup to a later process.

use crate::{IpcError, IpcResult};
use std::ffi::CStr;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};

const SOL_LOCAL: libc::c_int = 0;
const LOCAL_PEERTOKEN: libc::c_int = 0x006;
const PROC_PIDPATHINFO_SIZE: usize = 4096;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct AuditToken {
    value: [u32; 8],
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath_audittoken(
        token: *mut AuditToken,
        buffer: *mut libc::c_void,
        buffer_size: u32,
    ) -> libc::c_int;
}

/// Kernel-derived identity of the client connected to one Unix socket.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MacOsUnixPeerFacts {
    token: AuditToken,
    pid: i32,
    effective_uid: u32,
    effective_gid: u32,
    pid_version: u32,
    image_path: PathBuf,
}

impl MacOsUnixPeerFacts {
    #[must_use]
    pub const fn pid(&self) -> i32 {
        self.pid
    }

    #[must_use]
    pub const fn effective_uid(&self) -> u32 {
        self.effective_uid
    }

    #[must_use]
    pub const fn effective_gid(&self) -> u32 {
        self.effective_gid
    }

    #[must_use]
    pub const fn pid_version(&self) -> u32 {
        self.pid_version
    }

    #[must_use]
    pub fn image_path(&self) -> &Path {
        &self.image_path
    }

    /// Re-resolve the exact audit token immediately before a privileged spawn.
    pub fn revalidate(&self) -> IpcResult<()> {
        let current = image_path_for_token(self.token)?;
        if current != self.image_path {
            return Err(IpcError::Unauthorized(
                "macOS peer image changed after accept (fail-closed)".into(),
            ));
        }
        Ok(())
    }
}

/// Read the immutable audit token attached to an accepted local socket.
pub fn macos_unix_peer_facts(stream: &tokio::net::UnixStream) -> IpcResult<MacOsUnixPeerFacts> {
    let mut token = AuditToken { value: [0; 8] };
    let mut length = libc::socklen_t::try_from(std::mem::size_of::<AuditToken>())
        .map_err(|_| IpcError::Unauthorized("macOS audit-token size overflow".into()))?;
    // SAFETY: `stream` owns a valid connected socket; token and length point to
    // writable objects of the exact sizes passed to getsockopt.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            std::ptr::from_mut(&mut token).cast(),
            std::ptr::from_mut(&mut length),
        )
    };
    if status != 0 || usize::try_from(length).ok() != Some(std::mem::size_of::<AuditToken>()) {
        return Err(IpcError::Unauthorized(format!(
            "macOS LOCAL_PEERTOKEN retrieval failed (fail-closed): {}",
            std::io::Error::last_os_error()
        )));
    }
    // audit_token_t layout: auid, euid, egid, ruid, rgid, pid, asid, pidversion.
    let pid = i32::try_from(token.value[5])
        .map_err(|_| IpcError::Unauthorized("macOS peer PID overflow".into()))?;
    if pid <= 0 || token.value[7] == 0 {
        return Err(IpcError::Unauthorized(
            "macOS peer PID or PID-version is missing (fail-closed)".into(),
        ));
    }
    let image_path = image_path_for_token(token)?;
    Ok(MacOsUnixPeerFacts {
        token,
        pid,
        effective_uid: token.value[1],
        effective_gid: token.value[2],
        pid_version: token.value[7],
        image_path,
    })
}

fn image_path_for_token(mut token: AuditToken) -> IpcResult<PathBuf> {
    let mut buffer = [0_u8; PROC_PIDPATHINFO_SIZE];
    // SAFETY: libproc writes at most buffer.len() bytes. The audit token is a
    // local copy and remains valid for the duration of the call.
    let written = unsafe {
        proc_pidpath_audittoken(
            std::ptr::from_mut(&mut token),
            buffer.as_mut_ptr().cast(),
            u32::try_from(buffer.len()).unwrap_or(u32::MAX),
        )
    };
    if written <= 0 {
        return Err(IpcError::Unauthorized(format!(
            "macOS audit-token executable resolution failed (fail-closed): {}",
            std::io::Error::last_os_error()
        )));
    }
    let nul = buffer.iter().position(|byte| *byte == 0).ok_or_else(|| {
        IpcError::Unauthorized("macOS executable path lacks terminator (fail-closed)".into())
    })?;
    let path = CStr::from_bytes_with_nul(&buffer[..=nul])
        .map_err(|_| IpcError::Unauthorized("macOS executable path is malformed".into()))?
        .to_str()
        .map_err(|_| IpcError::Unauthorized("macOS executable path is not UTF-8".into()))?;
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        IpcError::Unauthorized(format!(
            "canonicalize macOS peer executable (fail-closed): {error}"
        ))
    })?;
    if !canonical.is_absolute() {
        return Err(IpcError::Unauthorized(
            "macOS peer executable is not absolute (fail-closed)".into(),
        ));
    }
    Ok(canonical)
}
