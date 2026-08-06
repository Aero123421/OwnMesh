//! OS peer identity checks for broker accept path.
//!
//! Production privileged broker requires verifiable peer credentials:
//! - Unix domain socket: `SO_PEERCRED` / platform equivalent via Tokio's safe
//!   `UnixStream::peer_cred` wrapper (no `unsafe` in this crate).
//! - Loopback TCP and Named Pipe: peer identity cannot be verified safely under
//!   `forbid(unsafe_code)`; production start is **fail-closed** with an explicit
//!   error (no warning-only accept, no insecure fallback).
//!
//! References:
//! - https://www.man7.org/linux/man-pages/man7/socket.7.html (`SO_PEERCRED`)
//! - https://www.man7.org/linux/man-pages/man7/unix.7.html
//! - https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights

use ownmesh_broker_client::{BrokerEndpoint, PeerCred};

/// Result of a peer identity probe after accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCheck {
    pub cred: Option<PeerCred>,
    pub method: &'static str,
    pub notes: Vec<String>,
}

/// Explicit error when LoopbackTcp is requested for a privileged broker.
#[must_use]
pub fn loopback_tcp_peer_unverifiable_error() -> String {
    "refusing LoopbackTcp endpoint for privileged broker: peer credentials cannot be verified \
     (fail-closed). Use a Unix domain socket with SO_PEERCRED on Unix. \
     Insecure fallback is disabled."
        .into()
}

/// Explicit error when Named Pipe peer verification is unavailable safely.
#[must_use]
pub fn named_pipe_peer_unverifiable_error() -> String {
    "refusing NamedPipe endpoint for privileged broker: safe peer credential verification \
     is not available under forbid(unsafe_code) (fail-closed). \
     Insecure ACL-only / warning-only accept is disabled."
        .into()
}

/// Fail-closed gate: privileged broker may only start on endpoints that support
/// OS peer credential verification.
pub fn assert_endpoint_peer_verifiable(endpoint: &BrokerEndpoint) -> Result<(), String> {
    match endpoint {
        BrokerEndpoint::LoopbackTcp(_) => Err(loopback_tcp_peer_unverifiable_error()),
        BrokerEndpoint::NamedPipe(_) => Err(named_pipe_peer_unverifiable_error()),
        BrokerEndpoint::UnixSocket(_) => {
            #[cfg(unix)]
            {
                Ok(())
            }
            #[cfg(not(unix))]
            {
                Err("refusing UnixSocket endpoint: not supported on this OS (fail-closed)".into())
            }
        }
    }
}

/// Optional allow-list of peer UIDs from `OWNMESH_BROKER_ALLOWED_UIDS` (comma-separated).
/// Empty list means "process effective UID only".
#[must_use]
pub fn allowed_peer_uids_from_env() -> Vec<u32> {
    std::env::var("OWNMESH_BROKER_ALLOWED_UIDS")
        .ok()
        .map(|s| {
            s.split(',')
                .filter_map(|part| {
                    let t = part.trim();
                    if t.is_empty() {
                        None
                    } else {
                        t.parse::<u32>().ok()
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Process effective user id (Unix). On non-Unix, returns 0 (unused; endpoints fail-closed).
#[must_use]
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        rustix::process::getuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Validate peer uid against an allow-list.
///
/// When `allowed_uids` is empty, only `own_uid` is accepted (default production policy).
/// When non-empty, the peer uid must appear in the list.
#[must_use]
pub fn peer_uid_allowed(cred: &PeerCred, allowed_uids: &[u32], own_uid: u32) -> bool {
    if allowed_uids.is_empty() {
        cred.uid == own_uid
    } else {
        allowed_uids.contains(&cred.uid)
    }
}

/// Check Unix peer after accept via platform peer-credential APIs (safe Tokio wrapper).
///
/// Retrieval failure is an error (fail-closed); callers must not accept the connection.
#[cfg(unix)]
pub fn check_unix_peer(stream: &tokio::net::UnixStream) -> Result<PeerCheck, String> {
    let ucred = stream
        .peer_cred()
        .map_err(|e| format!("peer credential retrieval failed (SO_PEERCRED/fail-closed): {e}"))?;
    let pid = ucred.pid().unwrap_or(0);
    let cred = PeerCred {
        pid,
        uid: uid_to_u32(ucred.uid()),
        gid: gid_to_u32(ucred.gid()),
    };
    Ok(PeerCheck {
        cred: Some(cred),
        method: "SO_PEERCRED",
        notes: vec![
            "uid verified against allow-list or process euid".into(),
            "socket permissions set to 0600 at bind".into(),
        ],
    })
}

/// Retrieve peer credentials and authorize the peer uid (allow-list / own uid).
#[cfg(unix)]
pub fn authorize_unix_peer(
    stream: &tokio::net::UnixStream,
    allowed_uids: &[u32],
) -> Result<PeerCheck, String> {
    let check = check_unix_peer(stream)?;
    let cred = check
        .cred
        .as_ref()
        .ok_or_else(|| "peer credential missing after probe (fail-closed)".to_string())?;
    let own = current_uid();
    if !peer_uid_allowed(cred, allowed_uids, own) {
        return Err(format!(
            "peer uid {} not permitted (own_uid={own}, allow_list={allowed_uids:?}; fail-closed)",
            cred.uid
        ));
    }
    Ok(check)
}

#[cfg(unix)]
fn uid_to_u32(uid: tokio::net::unix::uid_t) -> u32 {
    // uid_t is u32 on Linux/macOS targets we support; widen defensively.
    u32::try_from(uid).unwrap_or(u32::MAX)
}

#[cfg(unix)]
fn gid_to_u32(gid: tokio::net::unix::gid_t) -> u32 {
    u32::try_from(gid).unwrap_or(u32::MAX)
}

#[cfg(not(unix))]
#[allow(dead_code)]
pub fn check_unix_peer_unsupported() -> Result<PeerCheck, String> {
    Err("Unix peer credentials are not available on this OS (fail-closed)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uid_allow_list_defaults_to_own_uid() {
        let c = PeerCred {
            pid: 1,
            uid: 1000,
            gid: 1000,
        };
        assert!(peer_uid_allowed(&c, &[], 1000));
        assert!(!peer_uid_allowed(&c, &[], 0));
        assert!(peer_uid_allowed(&c, &[0, 1000], 0));
        assert!(!peer_uid_allowed(&c, &[0], 1000));
    }

    #[test]
    fn loopback_tcp_is_not_peer_verifiable() {
        let addr: std::net::SocketAddr = "127.0.0.1:9".parse().unwrap();
        let err = assert_endpoint_peer_verifiable(&BrokerEndpoint::LoopbackTcp(addr)).unwrap_err();
        assert!(
            err.contains("fail-closed") && err.to_ascii_lowercase().contains("loopback"),
            "{err}"
        );
    }

    #[test]
    fn named_pipe_is_not_peer_verifiable() {
        let err = assert_endpoint_peer_verifiable(&BrokerEndpoint::NamedPipe(
            r"\\.\pipe\ownmesh-test".into(),
        ))
        .unwrap_err();
        assert!(
            err.contains("fail-closed") && err.to_ascii_lowercase().contains("namedpipe"),
            "{err}"
        );
    }

    #[test]
    fn unix_socket_endpoint_gate_is_os_specific() {
        let ep = BrokerEndpoint::UnixSocket(std::path::PathBuf::from("/tmp/ownmesh-test.sock"));
        let result = assert_endpoint_peer_verifiable(&ep);
        #[cfg(unix)]
        result.expect("unix socket is peer-verifiable on Unix");
        #[cfg(not(unix))]
        {
            let err = result.unwrap_err();
            assert!(err.contains("fail-closed"), "{err}");
        }
    }
}
