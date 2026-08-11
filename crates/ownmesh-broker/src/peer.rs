//! OS-derived peer identity and trusted-ownmeshd policy checks.
//!
//! Privileged production serving is supported only where the broker can obtain
//! the connecting PID/UID and independently resolve that PID's executable. The
//! executable supplied by a request or CLI is never authoritative.

use ownmesh_broker_client::{BrokerEndpoint, PeerBind, PeerCred, PeerProcessBindV2};
use std::path::{Path, PathBuf};

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl std::fmt::Display for FileIdentity {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "dev={};ino={}", self.device, self.inode)
    }
}

/// Exact policy required before the broker may mint a capability for ownmeshd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedPeerPolicy {
    trusted_executable: PathBuf,
    allowed_uids: Vec<u32>,
    /// Linux device/inode pinned when loaded from the trusted filesystem.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    trusted_file_id: Option<FileIdentity>,
}

impl TrustedPeerPolicy {
    /// Construct a policy from an already canonical, trusted executable path.
    pub fn new(trusted_executable: PathBuf, mut allowed_uids: Vec<u32>) -> Result<Self, String> {
        if !trusted_executable.is_absolute() {
            return Err(
                "trusted ownmeshd executable must be an absolute path (fail-closed)".into(),
            );
        }
        if trusted_executable.as_os_str().is_empty() {
            return Err("trusted ownmeshd executable is required (fail-closed)".into());
        }
        allowed_uids.sort_unstable();
        allowed_uids.dedup();
        if allowed_uids.is_empty() {
            return Err(
                "at least one explicit allowed ownmeshd UID is required (fail-closed)".into(),
            );
        }
        Ok(Self {
            trusted_executable,
            allowed_uids,
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            trusted_file_id: None,
        })
    }

    #[must_use]
    pub fn trusted_executable(&self) -> &Path {
        &self.trusted_executable
    }

    #[must_use]
    pub fn allowed_uids(&self) -> &[u32] {
        &self.allowed_uids
    }

    /// Evaluate exact PID/UID/executable policy without granting mint authority.
    /// This is public so policy can be tested independently of OS stream setup.
    pub fn check_bind(&self, peer: &PeerBind) -> Result<(), String> {
        if peer.pid <= 0 {
            return Err("trusted ownmeshd PID is missing (fail-closed)".into());
        }
        if !self.allowed_uids.contains(&peer.uid) {
            return Err(format!(
                "ownmeshd uid {} is not in explicit allow-list {:?} (fail-closed)",
                peer.uid, self.allowed_uids
            ));
        }
        if peer.exe_path.trim().is_empty() {
            return Err("OS could not resolve ownmeshd executable (fail-closed)".into());
        }
        let expected = self.trusted_executable.to_string_lossy();
        if peer.exe_path != expected {
            return Err(format!(
                "peer executable mismatch: OS resolved {:?}, trusted {:?} (fail-closed)",
                peer.exe_path, expected
            ));
        }
        Ok(())
    }

    /// Resolve a synthetic helper PID entirely through the OS and authorize it.
    /// Unsupported OSes fail closed; no executable or UID CLI claim is accepted.
    pub fn authorize_process(&self, pid: i32) -> Result<AuthorizedPeer, String> {
        #[cfg(target_os = "linux")]
        {
            let pinned = self.trusted_file_id.ok_or_else(|| {
                "trusted executable policy is not pinned to root-controlled file identity (fail-closed)"
                    .to_string()
            })?;
            let current_before = trusted_executable_identity(&self.trusted_executable)?;
            if current_before != pinned {
                return Err("trusted ownmeshd executable identity changed (fail-closed)".into());
            }

            let resolved = resolve_linux_process(pid)?;

            // `read_link(/proc/<pid>/exe)` only yields a pathname. Metadata on the
            // proc magic link follows it to the executable inode actually held by
            // the process, which must be the exact inode pinned by this policy.
            validate_process_executable_identity(pid, resolved.executable_file_id, pinned)?;
            let current_after = trusted_executable_identity(&self.trusted_executable)?;
            if current_after != pinned {
                return Err(
                    "trusted ownmeshd executable identity changed during authorization (fail-closed)"
                        .into(),
                );
            }
            self.check_bind(&resolved.peer)?;
            return Ok(AuthorizedPeer {
                peer: resolved.peer,
                process_start_time: resolved.start_time,
                image_identity: resolved.executable_file_id.to_string(),
            });
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = pid;
            Err(
                "OS PID/UID identity resolution is unsupported on this platform (fail-closed)"
                    .into(),
            )
        }
    }

    #[cfg(target_os = "macos")]
    fn authorize_macos_socket_peer(
        &self,
        facts: &ownmesh_ipc::MacOsUnixPeerFacts,
    ) -> Result<AuthorizedPeer, String> {
        let pinned = self.trusted_file_id.ok_or_else(|| {
            "trusted macOS executable is not pinned to root-controlled file identity (fail-closed)"
                .to_string()
        })?;
        let current_before = trusted_executable_identity(&self.trusted_executable)?;
        if current_before != pinned {
            return Err("trusted macOS ownmeshd executable identity changed (fail-closed)".into());
        }
        facts.revalidate().map_err(|error| error.to_string())?;
        let process_image = trusted_executable_identity(facts.image_path())?;
        if process_image != pinned {
            return Err(
                "macOS peer executable file identity differs from trusted ownmeshd (fail-closed)"
                    .into(),
            );
        }
        let peer = PeerBind::new(
            facts.pid(),
            facts.effective_uid(),
            facts.image_path().to_string_lossy(),
        );
        self.check_bind(&peer)?;
        let current_after = trusted_executable_identity(&self.trusted_executable)?;
        if current_after != pinned {
            return Err(
                "trusted macOS ownmeshd executable changed during authorization (fail-closed)"
                    .into(),
            );
        }
        Ok(AuthorizedPeer {
            peer,
            process_start_time: u64::from(facts.pid_version()),
            image_identity: process_image.to_string(),
        })
    }
}

/// A peer that passed exact PID/UID/executable policy checks.
///
/// The inner binding is private so production minting can require this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedPeer {
    peer: PeerBind,
    /// Linux `/proc/<pid>/stat` field 22 captured when authorization was granted.
    /// This is retained separately from the externally bound PID so a later PID
    /// reuse cannot compare equal during request-time refresh.
    process_start_time: u64,
    /// Kernel-derived identity of the executable held by the peer process.
    image_identity: String,
}

impl AuthorizedPeer {
    #[must_use]
    pub fn peer_bind(&self) -> &PeerBind {
        &self.peer
    }

    #[must_use]
    pub fn process_start_time(&self) -> u64 {
        self.process_start_time
    }

    /// V2 token binding facts derived from the accepted OS peer only.
    #[must_use]
    pub fn process_bind_v2(&self) -> PeerProcessBindV2 {
        PeerProcessBindV2 {
            pid: self.peer.pid,
            uid: self.peer.uid,
            executable_path: self.peer.exe_path.clone(),
            process_birth_id: self.process_start_time,
            image_identity: self.image_identity.clone(),
        }
    }

    #[allow(dead_code)]
    pub(crate) fn validate_refresh(&self, refreshed: &Self) -> Result<(), String> {
        if refreshed.process_start_time != self.process_start_time {
            return Err(
                "peer PID was reused after accept (process start time changed; fail-closed)".into(),
            );
        }
        if refreshed.peer != self.peer {
            return Err("peer identity changed after accept (fail-closed)".into());
        }
        Ok(())
    }
}

/// Result of a peer identity probe after accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerCheck {
    pub cred: PeerCred,
    /// Executable path independently resolved from the OS PID interface.
    pub exe_path: String,
    pub method: &'static str,
    pub notes: Vec<String>,
}

impl PeerCheck {
    #[must_use]
    pub fn peer_bind(&self) -> PeerBind {
        PeerBind::from_peer_cred(&self.cred, self.exe_path.clone())
    }
}

#[must_use]
pub fn loopback_tcp_peer_unverifiable_error() -> String {
    "refusing LoopbackTcp endpoint for privileged broker: peer credentials cannot be verified \
     (fail-closed). Use a Linux Unix socket with SO_PEERCRED and /proc PID executable resolution. \
     Insecure fallback is disabled."
        .into()
}

#[must_use]
pub fn named_pipe_peer_unverifiable_error() -> String {
    "refusing NamedPipe endpoint for privileged broker: safe peer credential verification \
     is not available under forbid(unsafe_code) (fail-closed). \
     Insecure ACL-only / warning-only accept is disabled."
        .into()
}

pub fn assert_endpoint_peer_verifiable(endpoint: &BrokerEndpoint) -> Result<(), String> {
    if endpoint_supports_peer_cred_enforcement(endpoint) {
        Ok(())
    } else {
        Err(peer_enforcement_unsupported_reason(endpoint))
    }
}

/// Production Unix peers are supported on Linux (`SO_PEERCRED` + `/proc`) and
/// macOS (`LOCAL_PEERTOKEN` + audit-token-bound libproc image resolution).
#[must_use]
pub fn endpoint_supports_peer_cred_enforcement(endpoint: &BrokerEndpoint) -> bool {
    matches!(endpoint, BrokerEndpoint::UnixSocket(_))
        && cfg!(any(target_os = "linux", target_os = "macos"))
}

#[must_use]
pub fn peer_enforcement_unsupported_reason(endpoint: &BrokerEndpoint) -> String {
    match endpoint {
        BrokerEndpoint::LoopbackTcp(_) => loopback_tcp_peer_unverifiable_error(),
        BrokerEndpoint::NamedPipe(_) => named_pipe_peer_unverifiable_error(),
        BrokerEndpoint::UnixSocket(_) =>
            "refusing UnixSocket endpoint: exact PID executable resolution is unsupported on this OS (fail-closed)".into(),
    }
}

/// Process effective user id. Non-Unix platforms are unsupported for serving.
#[must_use]
pub fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        rustix::process::geteuid().as_raw()
    }
    #[cfg(not(unix))]
    {
        0
    }
}

#[must_use]
pub fn peer_uid_allowed(cred: &PeerCred, allowed_uids: &[u32], _own_uid: u32) -> bool {
    !allowed_uids.is_empty() && allowed_uids.contains(&cred.uid)
}

/// Independently resolve a PID's executable. Unsupported OSes return an error.
pub fn resolve_peer_exe(pid: i32) -> Result<String, String> {
    if pid <= 0 {
        return Err("peer PID must be positive (fail-closed)".into());
    }
    #[cfg(target_os = "linux")]
    {
        let link = std::fs::read_link(format!("/proc/{pid}/exe"))
            .map_err(|e| format!("cannot resolve /proc/{pid}/exe (fail-closed): {e}"))?;
        let canonical = std::fs::canonicalize(&link).map_err(|e| {
            format!(
                "cannot canonicalize OS-resolved executable {} (fail-closed): {e}",
                link.display()
            )
        })?;
        return Ok(canonical.to_string_lossy().into_owned());
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err("OS PID executable resolution is unsupported on this platform (fail-closed)".into())
    }
}

/// Resolve PID, effective UID and executable entirely from OS process metadata.
pub fn resolve_process_peer(pid: i32) -> Result<PeerBind, String> {
    #[cfg(target_os = "linux")]
    {
        return resolve_linux_process(pid).map(|resolved| resolved.peer);
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        Err("OS PID/UID identity resolution is unsupported on this platform (fail-closed)".into())
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ResolvedLinuxProcess {
    peer: PeerBind,
    start_time: u64,
    executable_file_id: FileIdentity,
}

#[cfg(target_os = "linux")]
fn resolve_linux_process(pid: i32) -> Result<ResolvedLinuxProcess, String> {
    if pid <= 0 {
        return Err("peer PID must be positive (fail-closed)".into());
    }
    let start_before = linux_process_start_time(pid)?;
    let executable_file_id_before = linux_process_executable_identity(pid)?;
    let exe = resolve_peer_exe(pid)?;
    let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .map_err(|e| format!("cannot inspect /proc/{pid}/status (fail-closed): {e}"))?;
    let uid_line = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| format!("effective UID missing from /proc/{pid}/status (fail-closed)"))?;
    let uid = uid_line
        .split_whitespace()
        .nth(2)
        .ok_or_else(|| format!("effective UID malformed in /proc/{pid}/status (fail-closed)"))?
        .parse::<u32>()
        .map_err(|e| format!("effective UID malformed in /proc/{pid}/status: {e}"))?;
    let exe_after = resolve_peer_exe(pid)?;
    let executable_file_id_after = linux_process_executable_identity(pid)?;
    let start_after = linux_process_start_time(pid)?;
    if start_before != start_after
        || exe != exe_after
        || executable_file_id_before != executable_file_id_after
    {
        return Err(
            "process identity changed while resolving PID/UID/executable (fail-closed)".into(),
        );
    }
    Ok(ResolvedLinuxProcess {
        peer: PeerBind::new(pid, uid, exe),
        start_time: start_before,
        executable_file_id: executable_file_id_before,
    })
}

/// Obtain the identity of the executable inode held by the process. Unlike
/// `read_link`, `metadata` follows the `/proc/<pid>/exe` magic link.
#[cfg(target_os = "linux")]
fn linux_process_executable_identity(pid: i32) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let proc_exe = format!("/proc/{pid}/exe");
    let metadata = std::fs::metadata(&proc_exe)
        .map_err(|e| format!("cannot inspect {proc_exe} target identity (fail-closed): {e}"))?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(target_os = "linux")]
fn linux_process_start_time(pid: i32) -> Result<u64, String> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .map_err(|e| format!("cannot inspect /proc/{pid}/stat (fail-closed): {e}"))?;
    let after_comm = stat
        .rsplit_once(')')
        .map(|(_, rest)| rest)
        .ok_or_else(|| format!("malformed /proc/{pid}/stat (fail-closed)"))?;
    // The remainder begins at field 3 (state); starttime is field 22.
    after_comm
        .split_whitespace()
        .nth(19)
        .ok_or_else(|| format!("start time missing from /proc/{pid}/stat (fail-closed)"))?
        .parse::<u64>()
        .map_err(|e| format!("start time malformed in /proc/{pid}/stat: {e}"))
}

/// Canonicalize and validate the configured ownmeshd executable trust anchor.
/// It must be a root-owned regular file not writable by group or other.
pub fn load_trusted_peer_policy(
    executable: &Path,
    allowed_uids: Vec<u32>,
) -> Result<TrustedPeerPolicy, String> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let canonical = std::fs::canonicalize(executable).map_err(|e| {
            format!(
                "cannot canonicalize trusted ownmeshd executable {}: {e}",
                executable.display()
            )
        })?;
        let file_id = trusted_executable_identity(&canonical)?;
        let mut policy = TrustedPeerPolicy::new(canonical, allowed_uids)?;
        policy.trusted_file_id = Some(file_id);
        Ok(policy)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (executable, allowed_uids);
        Err("trusted executable enforcement is unsupported on this OS (fail-closed)".into())
    }
}

#[cfg(target_os = "linux")]
fn validate_process_executable_identity(
    pid: i32,
    actual: FileIdentity,
    trusted: FileIdentity,
) -> Result<(), String> {
    if actual != trusted {
        return Err(format!(
            "peer executable file identity mismatch: /proc/{pid}/exe is device/inode {actual:?}, trusted executable is {trusted:?} (fail-closed)"
        ));
    }
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn trusted_executable_identity(path: &Path) -> Result<FileIdentity, String> {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(format!(
            "trusted ownmeshd executable {} must be a root-owned regular non-symlink file not writable by group/other (fail-closed)",
            path.display()
        ));
    }
    validate_root_controlled_ancestors(
        path.parent()
            .ok_or_else(|| "trusted executable requires root-controlled ancestry".to_string())?,
    )?;
    Ok(FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_root_controlled_ancestors(start: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mut current = Some(start);
    while let Some(path) = current {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| format!("inspect trusted path ancestor {}: {e}", path.display()))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "trusted path ancestor {} must be a root-owned directory not writable by group/other (fail-closed)",
                path.display()
            ));
        }
        current = path.parent();
    }
    Ok(())
}

#[cfg(unix)]
pub fn check_unix_peer(stream: &tokio::net::UnixStream) -> Result<PeerCheck, String> {
    #[cfg(target_os = "macos")]
    {
        let facts =
            ownmesh_ipc::macos_unix_peer_facts(stream).map_err(|error| error.to_string())?;
        return Ok(PeerCheck {
            cred: PeerCred {
                pid: facts.pid(),
                uid: facts.effective_uid(),
                gid: facts.effective_gid(),
            },
            exe_path: facts.image_path().to_string_lossy().into_owned(),
            method: "LOCAL_PEERTOKEN+proc_pidpath_audittoken",
            notes: vec![
                "pid/uid/gid/PID-version obtained from the socket audit token".into(),
                "executable resolved for that exact audit token".into(),
            ],
        });
    }
    #[cfg(not(target_os = "macos"))]
    {
        let ucred = stream.peer_cred().map_err(|e| {
            format!("peer credential retrieval failed (SO_PEERCRED/fail-closed): {e}")
        })?;
        let pid = ucred.pid().unwrap_or(0);
        if pid <= 0 {
            return Err("peer pid missing from SO_PEERCRED (fail-closed)".into());
        }
        // tokio::net::unix::{uid_t,gid_t} are u32 on every Unix target we ship.
        let cred = PeerCred {
            pid,
            uid: ucred.uid(),
            gid: ucred.gid(),
        };
        let exe_path = resolve_peer_exe(pid)?;
        Ok(PeerCheck {
            cred,
            exe_path,
            method: "SO_PEERCRED+/proc/pid/exe",
            notes: vec![
                "pid/uid independently obtained from peer credentials".into(),
                "executable independently resolved from peer PID".into(),
            ],
        })
    }
}

#[cfg(unix)]
pub fn authorize_unix_peer(
    stream: &tokio::net::UnixStream,
    policy: &TrustedPeerPolicy,
) -> Result<AuthorizedPeer, String> {
    #[cfg(target_os = "macos")]
    {
        let facts =
            ownmesh_ipc::macos_unix_peer_facts(stream).map_err(|error| error.to_string())?;
        return policy.authorize_macos_socket_peer(&facts);
    }
    #[cfg(not(target_os = "macos"))]
    {
        let check = check_unix_peer(stream)?;
        let socket_peer = check.peer_bind();
        let authorized = policy.authorize_process(socket_peer.pid)?;
        if authorized.peer_bind() != &socket_peer {
            return Err("socket peer identity changed during authorization (fail-closed)".into());
        }
        Ok(authorized)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn absolute_test_path(name: &str) -> PathBuf {
        #[cfg(windows)]
        {
            PathBuf::from(format!(r"C:\OwnMesh\{name}.exe"))
        }
        #[cfg(not(windows))]
        {
            PathBuf::from(format!("/usr/lib/ownmesh/{name}"))
        }
    }

    #[test]
    fn policy_requires_explicit_uid_and_exact_nonempty_executable() {
        let exe = absolute_test_path("ownmeshd");
        assert!(TrustedPeerPolicy::new(exe.clone(), vec![]).is_err());
        let policy = TrustedPeerPolicy::new(exe.clone(), vec![1000]).unwrap();
        let exact = PeerBind::new(9, 1000, exe.to_string_lossy());
        assert!(policy.check_bind(&exact).is_ok());
        assert!(policy.check_bind(&PeerBind::new(9, 1000, "")).is_err());
        assert!(policy
            .check_bind(&PeerBind::new(
                9,
                1000,
                absolute_test_path("attacker").to_string_lossy()
            ))
            .is_err());
        assert!(policy
            .check_bind(&PeerBind::new(9, 1001, exe.to_string_lossy()))
            .is_err());
        assert!(policy
            .check_bind(&PeerBind::new(0, 1000, exe.to_string_lossy()))
            .is_err());
    }

    #[test]
    fn uid_policy_never_uses_empty_as_implicit_current_uid() {
        let cred = PeerCred {
            pid: 1,
            uid: 1000,
            gid: 1000,
        };
        assert!(!peer_uid_allowed(&cred, &[], 1000));
        assert!(peer_uid_allowed(&cred, &[1000], 0));
    }

    #[test]
    fn authorized_peer_identity_retains_process_start_time() {
        let peer = PeerBind::new(42, 1000, absolute_test_path("ownmeshd").to_string_lossy());
        let accepted = AuthorizedPeer {
            peer: peer.clone(),
            process_start_time: 10,
            image_identity: "dev=1;ino=1".into(),
        };
        let reused_pid = AuthorizedPeer {
            peer,
            process_start_time: 11,
            image_identity: "dev=1;ino=1".into(),
        };

        assert_eq!(accepted.peer_bind(), reused_pid.peer_bind());
        assert_ne!(
            accepted.process_start_time(),
            reused_pid.process_start_time(),
            "the request-time refresh must distinguish a reused PID"
        );
        let error = accepted
            .validate_refresh(&reused_pid)
            .expect_err("request-time refresh must reject reuse of the accepted PID");
        assert!(error.contains("PID was reused"), "{error}");
        assert_ne!(accepted, reused_pid);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn mismatched_proc_executable_inode_is_rejected() {
        let trusted = FileIdentity {
            device: 10,
            inode: 20,
        };
        let actual = FileIdentity {
            device: 10,
            inode: 21,
        };

        let error = validate_process_executable_identity(42, actual, trusted)
            .expect_err("pathname equality cannot override a different executable inode");
        assert!(error.contains("/proc/42/exe"), "{error}");
        assert!(error.contains("fail-closed"), "{error}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn proc_executable_probe_follows_magic_link_to_held_inode() {
        use std::os::unix::fs::MetadataExt;

        let pid = i32::try_from(std::process::id()).unwrap();
        let resolved = resolve_linux_process(pid).unwrap();
        let current_exe = std::env::current_exe().unwrap();
        let expected = std::fs::metadata(&current_exe).unwrap();
        let proc_exe = format!("/proc/{pid}/exe");

        assert!(std::fs::symlink_metadata(&proc_exe)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            resolved.executable_file_id,
            FileIdentity {
                device: expected.dev(),
                inode: expected.ino(),
            },
            "the probe must identify the executable file held by the process"
        );
        assert!(resolved.start_time > 0);
    }

    #[test]
    fn unverifiable_transport_gates_are_fail_closed() {
        let tcp = BrokerEndpoint::LoopbackTcp("127.0.0.1:9".parse().unwrap());
        assert!(assert_endpoint_peer_verifiable(&tcp).is_err());
        let pipe = BrokerEndpoint::NamedPipe(r"\\.\pipe\ownmesh-test".into());
        assert!(assert_endpoint_peer_verifiable(&pipe).is_err());
    }
}
