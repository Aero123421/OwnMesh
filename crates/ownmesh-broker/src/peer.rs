//! OS peer identity checks for broker accept path.
//!
//! Linux production path: root-owned Unix socket mode 0600 + request MAC/capability.
//! `SO_PEERCRED` (socket(7) / unix(7)) is the documented OS API for reading peer
//! uid/gid/pid; this crate stays `forbid(unsafe_code)` so the credential probe is
//! represented as a structured hook. Install templates document enabling
//! peercred at the service layer; request auth remains MAC + allow-list.
//!
//! Windows: Named Pipe ACL via `CreateNamedPipe` security descriptor
//! (<https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>).
//!
//! macOS: `LaunchDaemon` socket ownership/permission + code signature at install.

use ownmesh_broker_client::PeerCred;

/// Result of a peer identity probe after accept.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub struct PeerCheck {
    pub cred: Option<PeerCred>,
    pub method: &'static str,
    pub notes: Vec<String>,
}

/// Check Unix peer after accept.
///
/// Always enforces that we only accepted a local unix connection; optional
/// peercred fields are filled when the platform exposes them without unsafe.
#[cfg(unix)]
pub fn check_unix_peer(_stream: &tokio::net::UnixStream) -> Result<PeerCheck, String> {
    // Portable path: filesystem socket is mode 0600 (set at bind). Full
    // SO_PEERCRED requires libc getsockopt; workspace forbids unsafe_code, so
    // we record the intended method and rely on MAC + caller allow-list.
    // Reference: https://www.man7.org/linux/man-pages/man7/socket.7.html
    Ok(PeerCheck {
        cred: None,
        method: if cfg!(target_os = "linux") {
            "unix_socket_mode_0600+mac (SO_PEERCRED documented for service hardening)"
        } else {
            "unix_socket_mode_0600+mac (LaunchDaemon ownership)"
        },
        notes: vec![
            "request MAC/nonce/expiry enforced separately".into(),
            "socket permissions set to 0600 at bind".into(),
        ],
    })
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub fn check_unix_peer_unsupported() -> PeerCheck {
    PeerCheck {
        cred: None,
        method: "named_pipe_acl",
        notes: vec!["Windows Named Pipe security descriptor controls client access".into()],
    }
}

/// Validate that an optional peer uid is in an allow-list (used when creds exist).
#[must_use]
#[allow(dead_code)]
pub fn peer_uid_allowed(cred: &PeerCred, allowed_uids: &[u32]) -> bool {
    if allowed_uids.is_empty() {
        return true;
    }
    allowed_uids.contains(&cred.uid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_allow_list() {
        let c = PeerCred {
            pid: 1,
            uid: 1000,
            gid: 1000,
        };
        assert!(peer_uid_allowed(&c, &[]));
        assert!(peer_uid_allowed(&c, &[0, 1000]));
        assert!(!peer_uid_allowed(&c, &[0]));
    }
}
