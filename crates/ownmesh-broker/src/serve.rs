//! Broker accept loop and elevated execution.

use crate::now_unix;
use crate::peer::AuthorizedPeer;
use ownmesh_broker_client::{
    verify_request, verify_request_mac, BrokerEndpoint, BrokerRequest, BrokerResponse,
    BrokerSecret, CapabilitySigningKey, CapabilityToken, CapabilityVerifyKey, ElevatedCommand,
    PeerBind, ReplayCache, DEFAULT_CAPABILITY_TTL_SECS, ELEVATED_CAPABILITY_SCOPE,
};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex as AsyncMutex;

/// Default relative name for the capability signing key (broker-only).
pub const CAPABILITY_SIGNING_FILE: &str = "broker.cap.signing";
/// Default relative name for the capability verify key (distributable).
pub const CAPABILITY_VERIFY_FILE: &str = "broker.cap.verify";
/// Maximum retained bytes for each elevated stdout/stderr stream.  Readers
/// continue draining after the cap so a noisy child cannot deadlock on a full
/// pipe; callers receive an explicit truncation marker instead of an unbounded
/// response allocation.
const MAX_ELEVATED_OUTPUT_BYTES: usize = 256 * 1024;

/// Runtime broker state.
pub struct BrokerState {
    pub secret: BrokerSecret,
    /// Broker-only mint key — never the request MAC secret.
    pub signing_key: CapabilitySigningKey,
    pub verify_key: CapabilityVerifyKey,
    pub replay: ReplayCache,
}

/// Explicit Unix socket custody settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixSocketSecurity {
    pub owner_uid: u32,
    pub group_gid: u32,
    pub mode: u32,
}

impl UnixSocketSecurity {
    pub fn validate(self) -> Result<Self, String> {
        if self.mode != 0o600 {
            return Err(format!(
                "broker socket mode must be exactly 0600 so only its owner UID has DAC access; got {:o}",
                self.mode
            ));
        }
        Ok(self)
    }
}

/// Prove that the same single daemon UID owns the socket and request-MAC secret.
/// The configured socket GID is still applied, but exact mode 0600 grants it no access.
pub fn validate_daemon_dac_policy(
    security: UnixSocketSecurity,
    allowed_uids: &[u32],
) -> Result<u32, String> {
    security.validate()?;
    if allowed_uids.len() != 1 || allowed_uids[0] != security.owner_uid {
        return Err(format!(
            "broker DAC policy requires exactly one allowed UID equal to socket owner UID {}; got {:?}",
            security.owner_uid, allowed_uids
        ));
    }
    Ok(security.owner_uid)
}

/// Serve configuration. Every trust-boundary value is explicit.
#[derive(Debug, Clone)]
pub struct BrokerServeConfig {
    pub endpoint: BrokerEndpoint,
    /// Request-MAC shared secret file (may be readable by ownmeshd).
    pub secret_file: PathBuf,
    /// Capability Ed25519 signing key file in a broker-private parent.
    pub signing_key_file: PathBuf,
    /// Canonical trusted ownmeshd executable.
    pub trusted_executable: PathBuf,
    /// Explicit allowed ownmeshd UIDs.
    pub allowed_uids: Vec<u32>,
    pub socket_security: UnixSocketSecurity,
    /// Optional path to write the bound endpoint (tests/diagnostics).
    pub addr_file: Option<PathBuf>,
}

/// Reject any non-loopback TCP bind (networkless design).
pub fn enforce_bind_is_networkless(addr: SocketAddr) -> Result<(), String> {
    if !addr.ip().is_loopback() {
        return Err(format!(
            "broker must bind to loopback only (networkless design); refused {addr}"
        ));
    }
    Ok(())
}

/// Default signing-key path under a broker-private parent, never beside the
/// ownmeshd-readable request-MAC secret.
#[must_use]
pub fn default_signing_key_path(secret_file: &Path) -> PathBuf {
    secret_file
        .parent()
        .map(|p| p.join("private").join(CAPABILITY_SIGNING_FILE))
        .unwrap_or_else(|| PathBuf::from("private").join(CAPABILITY_SIGNING_FILE))
}

/// Default distributable verify-key path beside the request secret (never secret material).
#[must_use]
pub fn default_verify_key_path(secret_file: &Path) -> PathBuf {
    secret_file
        .parent()
        .map(|p| p.join(CAPABILITY_VERIFY_FILE))
        .unwrap_or_else(|| PathBuf::from(CAPABILITY_VERIFY_FILE))
}

/// Load or create the shared **request MAC** secret file.
pub fn load_or_create_secret(path: &Path) -> Result<BrokerSecret, String> {
    if path.exists() {
        let metadata = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(format!(
                "broker secret {} must be a regular non-symlink file (fail-closed)",
                path.display()
            ));
        }
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        if bytes.len() < 32 {
            return Err("secret file too short".into());
        }
        Ok(BrokerSecret::from_bytes(bytes))
    } else {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let secret = BrokerSecret::generate();
        write_new_private_file(path, secret.as_bytes(), 0o600)?;
        Ok(secret)
    }
}

/// Platform-independent metadata used by custody policy tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyMetadata {
    pub owner_uid: u32,
    pub mode: u32,
    pub is_expected_type: bool,
}

/// Platform-independent socket metadata projection for fail-closed validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketCustodyMetadata {
    pub owner_uid: u32,
    pub group_gid: u32,
    pub mode: u32,
    pub is_socket: bool,
    pub is_symlink: bool,
}

pub fn validate_request_secret_custody_metadata(
    secret: CustodyMetadata,
    daemon_uid: u32,
) -> Result<(), String> {
    if !secret.is_expected_type || secret.owner_uid != daemon_uid || secret.mode & 0o777 != 0o600 {
        return Err(format!(
            "request-MAC secret must be a regular non-symlink file owned by daemon UID {daemon_uid} with mode 0600"
        ));
    }
    Ok(())
}

pub fn validate_daemon_directory_custody_metadata(
    directory: CustodyMetadata,
    daemon_uid: u32,
) -> Result<(), String> {
    if !directory.is_expected_type
        || directory.owner_uid != 0
        || directory.mode & 0o022 != 0
        || (daemon_uid != 0 && directory.mode & 0o001 == 0)
    {
        return Err(format!(
            "daemon UID {daemon_uid} requires root-owned, non-writable, other-searchable directory ancestry"
        ));
    }
    Ok(())
}

pub fn validate_verify_key_custody_metadata(verify: CustodyMetadata) -> Result<(), String> {
    if !verify.is_expected_type || verify.owner_uid != 0 || verify.mode & 0o777 != 0o644 {
        return Err(
            "capability verify key must be a root-owned regular non-symlink file with mode 0644"
                .into(),
        );
    }
    Ok(())
}

pub fn validate_socket_custody_metadata(
    socket: SocketCustodyMetadata,
    expected: UnixSocketSecurity,
) -> Result<(), String> {
    expected.validate()?;
    if !socket.is_socket
        || socket.is_symlink
        || socket.owner_uid != expected.owner_uid
        || socket.group_gid != expected.group_gid
        || socket.mode & 0o777 != expected.mode
    {
        return Err(format!(
            "broker endpoint must be a non-symlink Unix socket with owner={}:{} mode={:04o}",
            expected.owner_uid, expected.group_gid, expected.mode
        ));
    }
    Ok(())
}

pub fn validate_signing_custody_metadata(
    parent: CustodyMetadata,
    key: CustodyMetadata,
) -> Result<(), String> {
    if !parent.is_expected_type || parent.owner_uid != 0 || parent.mode & 0o022 != 0 {
        return Err(
            "signing-key parent must be a root-owned directory not writable by group/other".into(),
        );
    }
    if !key.is_expected_type || key.owner_uid != 0 || key.mode & 0o777 != 0o600 {
        return Err("signing key must be a root-owned regular file with mode 0600".into());
    }
    Ok(())
}

/// Load or create the broker-only capability signing key.
///
/// On Unix this operation requires effective UID 0. The immediate parent is
/// root-owned mode 0711 (lookup permits identity checks, never key reads); the
/// key itself remains root-owned mode 0600.
pub fn load_or_create_capability_keys(
    signing_path: &Path,
) -> Result<(CapabilitySigningKey, CapabilityVerifyKey), String> {
    prepare_signing_parent(signing_path)?;
    let signing_key = if signing_path.exists() {
        validate_signing_key_custody(signing_path)?;
        let bytes = std::fs::read(signing_path).map_err(|e| e.to_string())?;
        CapabilitySigningKey::from_bytes(&bytes).map_err(|e| e.to_string())?
    } else {
        let key = CapabilitySigningKey::generate();
        write_new_private_file(signing_path, &key.to_bytes(), 0o600)?;
        set_root_owner(signing_path)?;
        validate_signing_key_custody(signing_path)?;
        key
    };
    let verify_key = signing_key.verify_key();
    let private_parent = signing_path
        .parent()
        .ok_or_else(|| "signing key requires a broker-private parent directory".to_string())?;
    let verify_parent = if private_parent.file_name().and_then(|n| n.to_str()) == Some("private") {
        private_parent.parent().unwrap_or(private_parent)
    } else {
        private_parent
    };
    let verify_path = verify_parent.join(CAPABILITY_VERIFY_FILE);
    write_replace_file(&verify_path, &verify_key.to_bytes(), 0o644)?;
    set_root_owner(&verify_path)?;
    validate_verify_key_custody(&verify_path)?;
    Ok((signing_key, verify_key))
}

fn write_new_private_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    file.sync_all()
        .map_err(|e| format!("sync {}: {e}", path.display()))?;
    set_mode(path, mode)
}

fn write_replace_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("replacement file {} needs a parent", path.display()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("broker-key"),
        uuid::Uuid::new_v4().simple()
    ));
    write_new_private_file(&temp, bytes, mode)?;
    // Rust 1.92 uses replacement rename semantics on Windows as well as Unix;
    // never delete the old key before the atomic replacement commit.
    std::fs::rename(&temp, path)
        .map_err(|e| format!("replace {} from {}: {e}", path.display(), temp.display()))?;
    set_mode(path, mode)
}

fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
        Ok(())
    }
}

fn set_root_owner(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        rustix::fs::chown(
            path.as_os_str().as_bytes(),
            Some(rustix::process::Uid::from_raw(0)),
            Some(rustix::process::Gid::from_raw(0)),
        )
        .map_err(|e| format!("chown root:root {}: {e}", path.display()))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

fn prepare_signing_parent(signing_path: &Path) -> Result<(), String> {
    let parent = signing_path
        .parent()
        .ok_or_else(|| "signing key requires a broker-private parent directory".to_string())?;
    #[cfg(unix)]
    {
        if rustix::process::geteuid().as_raw() != 0 {
            return Err("unsupported: Unix signing-key custody requires effective UID 0".into());
        }
    }
    if parent.exists() {
        let metadata = std::fs::symlink_metadata(parent).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err("signing-key parent must be a real directory, not a symlink".into());
        }
    }
    std::fs::create_dir_all(parent).map_err(|e| format!("create {}: {e}", parent.display()))?;
    set_root_owner(parent)?;
    set_mode(parent, 0o711)?;
    validate_signing_parent_custody(parent)
}

fn validate_signing_parent_custody(parent: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mut current = Some(parent);
        while let Some(path) = current {
            let md = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
            if !md.file_type().is_dir()
                || md.file_type().is_symlink()
                || md.uid() != 0
                || md.mode() & 0o022 != 0
            {
                return Err(format!(
                    "signing-key ancestor {} must be a root-owned directory not writable by group/other",
                    path.display()
                ));
            }
            current = path.parent();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = parent;
    }
    Ok(())
}

pub fn validate_signing_key_custody(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let parent_path = path
            .parent()
            .ok_or_else(|| "missing signing-key parent".to_string())?;
        validate_signing_parent_custody(parent_path)?;
        let p = std::fs::symlink_metadata(parent_path).map_err(|e| e.to_string())?;
        let k = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        return validate_signing_custody_metadata(
            CustodyMetadata {
                owner_uid: p.uid(),
                mode: p.mode(),
                is_expected_type: p.file_type().is_dir() && !p.file_type().is_symlink(),
            },
            CustodyMetadata {
                owner_uid: k.uid(),
                mode: k.mode(),
                is_expected_type: k.file_type().is_file() && !k.file_type().is_symlink(),
            },
        );
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

pub fn validate_verify_key_custody(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        return validate_verify_key_custody_metadata(CustodyMetadata {
            owner_uid: md.uid(),
            mode: md.mode(),
            is_expected_type: md.file_type().is_file() && !md.file_type().is_symlink(),
        });
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Load/create the request-MAC secret with physical DAC custody by one daemon UID.
/// Existing files are never repaired in place: unexpected type/owner/mode is rejected.
pub fn load_or_create_request_secret(path: &Path, daemon_uid: u32) -> Result<BrokerSecret, String> {
    #[cfg(unix)]
    {
        use std::io::ErrorKind;
        use std::os::unix::fs::MetadataExt;

        let parent = path
            .parent()
            .ok_or_else(|| "request-MAC secret requires a root-controlled parent".to_string())?;
        validate_signing_parent_custody(parent)?;
        validate_daemon_traversable_ancestry(parent, daemon_uid)?;
        match std::fs::symlink_metadata(path) {
            Ok(md) => {
                validate_request_secret_custody_metadata(
                    CustodyMetadata {
                        owner_uid: md.uid(),
                        mode: md.mode(),
                        is_expected_type: md.file_type().is_file() && !md.file_type().is_symlink(),
                    },
                    daemon_uid,
                )?;
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                let secret = BrokerSecret::generate();
                write_new_private_file(path, secret.as_bytes(), 0o600)?;
                set_owner(path, daemon_uid, 0)?;
                set_mode(path, 0o600)?;
            }
            Err(err) => {
                return Err(format!(
                    "inspect request-MAC secret {}: {err}",
                    path.display()
                ));
            }
        }
        let md = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        validate_request_secret_custody_metadata(
            CustodyMetadata {
                owner_uid: md.uid(),
                mode: md.mode(),
                is_expected_type: md.file_type().is_file() && !md.file_type().is_symlink(),
            },
            daemon_uid,
        )?;
        let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
        if bytes.len() < 32 {
            return Err("secret file too short".into());
        }
        return Ok(BrokerSecret::from_bytes(bytes));
    }
    #[cfg(not(unix))]
    {
        let _ = (path, daemon_uid);
        Err("request-MAC secret DAC custody is unsupported on this OS".into())
    }
}

#[cfg(unix)]
fn validate_daemon_traversable_ancestry(start: &Path, daemon_uid: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let mut current = Some(start);
    while let Some(path) = current {
        let md = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
        validate_daemon_directory_custody_metadata(
            CustodyMetadata {
                owner_uid: md.uid(),
                mode: md.mode(),
                is_expected_type: md.file_type().is_dir() && !md.file_type().is_symlink(),
            },
            daemon_uid,
        )
        .map_err(|e| format!("{e}: {} (fail-closed)", path.display()))?;
        current = path.parent();
    }
    Ok(())
}

#[cfg(unix)]
fn set_owner(path: &Path, owner_uid: u32, group_gid: u32) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    rustix::fs::chown(
        path.as_os_str().as_bytes(),
        Some(rustix::process::Uid::from_raw(owner_uid)),
        Some(rustix::process::Gid::from_raw(group_gid)),
    )
    .map_err(|e| format!("chown {owner_uid}:{group_gid} {}: {e}", path.display()))
}

/// Ensure request-MAC and signing material are distinct files, not aliases or hard links.
pub fn ensure_broker_key_separation(secret_path: &Path, signing_path: &Path) -> Result<(), String> {
    if secret_path == signing_path {
        return Err("capability signing key must not share the request-MAC secret path".into());
    }
    if secret_path.exists() && signing_path.exists() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let secret = std::fs::metadata(secret_path).map_err(|e| e.to_string())?;
            let signing = std::fs::metadata(signing_path).map_err(|e| e.to_string())?;
            if secret.dev() == signing.dev() && secret.ino() == signing.ino() {
                return Err(
                    "capability signing key and request-MAC secret are the same file identity"
                        .into(),
                );
            }
        }
        #[cfg(not(unix))]
        {
            let secret = std::fs::canonicalize(secret_path).map_err(|e| e.to_string())?;
            let signing = std::fs::canonicalize(signing_path).map_err(|e| e.to_string())?;
            if secret == signing {
                return Err(
                    "capability signing key and request-MAC secret alias the same file".into(),
                );
            }
        }
    }
    Ok(())
}

/// Load a previously written capability verify key file.
pub fn load_verify_key(path: &Path) -> Result<CapabilityVerifyKey, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    CapabilityVerifyKey::from_bytes(&bytes).map_err(|e| e.to_string())
}

/// Verify + authorize a request that already carries a capability.
///
/// This platform-independent helper deliberately never mints for `None`.
pub fn execute_verified(
    secret: &BrokerSecret,
    _signing_key: &CapabilitySigningKey,
    verify_key: &CapabilityVerifyKey,
    replay: &mut ReplayCache,
    req: &BrokerRequest,
    peer: &PeerBind,
    now: i64,
) -> Result<BrokerResponse, String> {
    execute_verified_inner(secret, None, verify_key, replay, req, peer, now)
}

/// Production mint path. The unforgeable-in-API [`AuthorizedPeer`] can only be
/// produced after exact trusted executable, live PID and explicit UID policy checks.
pub(crate) fn execute_verified_for_authorized_peer(
    secret: &BrokerSecret,
    signing_key: &CapabilitySigningKey,
    verify_key: &CapabilityVerifyKey,
    replay: &mut ReplayCache,
    req: &BrokerRequest,
    peer: &AuthorizedPeer,
    now: i64,
) -> Result<BrokerResponse, String> {
    execute_verified_inner(
        secret,
        Some(signing_key),
        verify_key,
        replay,
        req,
        peer.peer_bind(),
        now,
    )
}

/// Synthetic one-shot mint path. Process identity is freshly OS-resolved inside
/// this call; callers cannot reuse a past authorization token.
pub fn execute_verified_for_process(
    secret: &BrokerSecret,
    signing_key: &CapabilitySigningKey,
    verify_key: &CapabilityVerifyKey,
    replay: &mut ReplayCache,
    req: &BrokerRequest,
    policy: &crate::peer::TrustedPeerPolicy,
    pid: i32,
    now: i64,
) -> Result<BrokerResponse, String> {
    let authorized = policy.authorize_process(pid)?;
    execute_verified_for_authorized_peer(
        secret,
        signing_key,
        verify_key,
        replay,
        req,
        &authorized,
        now,
    )
}

fn execute_verified_inner(
    secret: &BrokerSecret,
    mint_key: Option<&CapabilitySigningKey>,
    verify_key: &CapabilityVerifyKey,
    replay: &mut ReplayCache,
    req: &BrokerRequest,
    peer: &PeerBind,
    now: i64,
) -> Result<BrokerResponse, String> {
    if peer.pid <= 0 || peer.exe_path.trim().is_empty() {
        return Err("complete peer PID/UID/executable identity required (fail-closed)".into());
    }

    verify_request_mac(secret, req, now).map_err(|e| e.to_string())?;

    let effective = match &req.capability {
        Some(capability) => {
            verify_request(secret, verify_key, req, peer, now).map_err(|e| e.to_string())?;
            capability.clone()
        }
        None => {
            let signing_key = mint_key.ok_or_else(|| {
                "missing capability: mint denied without OS-authorized trusted ownmeshd peer"
                    .to_string()
            })?;
            CapabilityToken::issue_for_operation(
                signing_key,
                peer,
                req.caller_principal.clone(),
                ELEVATED_CAPABILITY_SCOPE,
                req.operation_id.clone(),
                now,
                DEFAULT_CAPABILITY_TTL_SECS,
            )
        }
    };
    replay.check_and_insert(req).map_err(|e| e.to_string())?;

    // Defense in depth: re-check bindings on the effective token.
    effective
        .verify_for_peer(verify_key, peer, now)
        .map_err(|e| e.to_string())?;
    if effective.scope != ELEVATED_CAPABILITY_SCOPE {
        return Ok(BrokerResponse {
            request_id: req.request_id.clone(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some("unauthorized capability scope".into()),
        });
    }
    if effective.operation_id != req.operation_id {
        return Ok(BrokerResponse {
            request_id: req.request_id.clone(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some("unauthorized capability operation".into()),
        });
    }

    Ok(run_elevated_command(req))
}

fn run_elevated_command(req: &BrokerRequest) -> BrokerResponse {
    run_elevated(&req.request_id, &req.command)
}

fn run_elevated(request_id: &str, command: &ElevatedCommand) -> BrokerResponse {
    let mut cmd = Command::new(&command.program);
    cmd.args(&command.args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(cwd) = &command.cwd {
        cmd.current_dir(cwd);
    }
    for (k, v) in &command.env {
        cmd.env(k, v);
    }
    // On Windows, Job Object management is best-effort via process group later;
    // kill_on_drop is handled by the OS when broker exits.
    match cmd.spawn() {
        Ok(mut child) => {
            let stdout = child.stdout.take();
            let stderr = child.stderr.take();
            let stdout_reader = stdout.map(|pipe| std::thread::spawn(move || drain_bounded(pipe)));
            let stderr_reader = stderr.map(|pipe| std::thread::spawn(move || drain_bounded(pipe)));
            let status = child.wait();
            let stdout = join_bounded_output(stdout_reader);
            let stderr = join_bounded_output(stderr_reader);
            match status {
                Ok(status) => BrokerResponse {
                    request_id: request_id.to_string(),
                    ok: status.success(),
                    exit_code: status.code(),
                    stdout,
                    stderr,
                    error: None,
                },
                Err(error) => BrokerResponse {
                    request_id: request_id.to_string(),
                    ok: false,
                    exit_code: None,
                    stdout,
                    stderr,
                    error: Some(error.to_string()),
                },
            }
        }
        Err(e) => BrokerResponse {
            request_id: request_id.to_string(),
            ok: false,
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: Some(e.to_string()),
        },
    }
}

fn drain_bounded<R: std::io::Read>(mut reader: R) -> String {
    let mut retained = Vec::with_capacity(MAX_ELEVATED_OUTPUT_BYTES);
    let mut chunk = [0_u8; 8192];
    let mut truncated = false;
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(read) => {
                let room = MAX_ELEVATED_OUTPUT_BYTES.saturating_sub(retained.len());
                let keep = room.min(read);
                retained.extend_from_slice(&chunk[..keep]);
                truncated |= keep != read;
            }
            Err(_) => {
                truncated = true;
                break;
            }
        }
    }
    let mut result = String::from_utf8_lossy(&retained).into_owned();
    if truncated {
        result.push_str("\n[ownmesh broker output truncated]\n");
    }
    result
}

fn join_bounded_output(handle: Option<std::thread::JoinHandle<String>>) -> String {
    handle
        .and_then(|reader| reader.join().ok())
        .unwrap_or_else(|| "[ownmesh broker output reader unavailable]".into())
}

/// Production elevated broker serve is fixed as **unsupported** until a secure
/// mint authority exists. Never binds an endpoint or executes processes.
///
/// In-process helpers (`execute_verified*`) remain available for unit tests only
/// and are unreachable from this production entry point.
pub async fn run_broker(cfg: BrokerServeConfig) -> Result<(), String> {
    let _ = cfg;
    Err(production_elevated_broker_unsupported())
}

/// Stable operator-facing reason for production elevated broker disablement.
#[must_use]
pub fn production_elevated_broker_unsupported() -> String {
    "unsupported: elevated broker production serve is disabled until a secure mint authority is established; refusing to bind or execute (fail-closed)".into()
}

/// Handle a TCP connection (public for tests of strict MAC/capability path only).
///
/// Production `run_broker` is fixed as unsupported and never binds. This helper remains
/// for in-process unit tests that exercise request auth with a **synthetic** peer bind.
pub async fn handle_tcp_conn(
    sock: tokio::net::TcpStream,
    state: Arc<AsyncMutex<BrokerState>>,
    peer: PeerBind,
) -> Result<(), String> {
    handle_stream(sock, state, peer).await
}

async fn handle_stream<S>(
    mut sock: S,
    state: Arc<AsyncMutex<BrokerState>>,
    peer: PeerBind,
) -> Result<(), String>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (reader, mut writer) = tokio::io::split(&mut sock);
    let mut lines = BufReader::new(reader).lines();
    let Some(line) = lines.next_line().await.map_err(|e| e.to_string())? else {
        return Ok(());
    };
    let req: BrokerRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            let resp = BrokerResponse {
                request_id: "unknown".into(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(format!("malformed request: {e}")),
            };
            write_resp(&mut writer, &resp).await?;
            return Ok(());
        }
    };
    let resp = {
        let mut st = state.lock().await;
        let secret_bytes = st.secret.as_bytes().to_vec();
        let secret = BrokerSecret::from_bytes(secret_bytes);
        // Clone signing material for the call (SigningKey is Clone).
        let signing = CapabilitySigningKey::from_bytes(&st.signing_key.to_bytes())
            .map_err(|e| e.to_string())?;
        let verify = st.verify_key.clone();
        match execute_verified(
            &secret,
            &signing,
            &verify,
            &mut st.replay,
            &req,
            &peer,
            now_unix(),
        ) {
            Ok(r) => r,
            Err(e) => BrokerResponse {
                request_id: req.request_id.clone(),
                ok: false,
                exit_code: None,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(e),
            },
        }
    };
    write_resp(&mut writer, &resp).await
}

async fn write_resp<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    resp: &BrokerResponse,
) -> Result<(), String> {
    let mut out = serde_json::to_string(resp).map_err(|e| e.to_string())?;
    out.push('\n');
    writer
        .write_all(out.as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    Ok(())
}

#[cfg(test)]
mod policy_tests {
    use super::*;

    #[test]
    fn elevated_output_is_drained_but_retained_with_a_hard_cap() {
        let output = drain_bounded(std::io::Cursor::new(vec![
            b'x';
            MAX_ELEVATED_OUTPUT_BYTES + 1
        ]));
        assert!(output.contains("output truncated"));
        assert!(
            output.len() <= MAX_ELEVATED_OUTPUT_BYTES + 64,
            "retained output must remain bounded"
        );
    }

    #[test]
    fn custody_metadata_requires_root_0600_key_and_safe_parent() {
        let safe_parent = CustodyMetadata {
            owner_uid: 0,
            mode: 0o40700,
            is_expected_type: true,
        };
        let safe_key = CustodyMetadata {
            owner_uid: 0,
            mode: 0o100_600,
            is_expected_type: true,
        };
        validate_signing_custody_metadata(safe_parent, safe_key).unwrap();

        for bad_parent in [
            CustodyMetadata {
                owner_uid: 1000,
                ..safe_parent
            },
            CustodyMetadata {
                mode: 0o40720,
                ..safe_parent
            },
            CustodyMetadata {
                is_expected_type: false,
                ..safe_parent
            },
        ] {
            assert!(validate_signing_custody_metadata(bad_parent, safe_key).is_err());
        }
        for bad_key in [
            CustodyMetadata {
                owner_uid: 1000,
                ..safe_key
            },
            CustodyMetadata {
                mode: 0o100_640,
                ..safe_key
            },
            CustodyMetadata {
                is_expected_type: false,
                ..safe_key
            },
        ] {
            assert!(validate_signing_custody_metadata(safe_parent, bad_key).is_err());
        }
    }

    #[test]
    fn daemon_dac_policy_is_single_owner_only_on_every_platform() {
        let security = UnixSocketSecurity {
            owner_uid: 1001,
            group_gid: 77,
            mode: 0o600,
        };
        assert_eq!(validate_daemon_dac_policy(security, &[1001]).unwrap(), 1001);
        for denied in [&[][..], &[1000][..], &[1001, 1001][..], &[1001, 1002][..]] {
            assert!(validate_daemon_dac_policy(security, denied).is_err());
        }
        for mode in [0o000, 0o060, 0o640, 0o660, 0o666, 0o700] {
            assert!(UnixSocketSecurity { mode, ..security }.validate().is_err());
        }
    }

    #[test]
    fn secret_verify_and_socket_metadata_are_exact_on_every_platform() {
        let secret = CustodyMetadata {
            owner_uid: 1001,
            mode: 0o100_600,
            is_expected_type: true,
        };
        validate_request_secret_custody_metadata(secret, 1001).unwrap();
        validate_daemon_directory_custody_metadata(
            CustodyMetadata {
                owner_uid: 0,
                mode: 0o40711,
                is_expected_type: true,
            },
            1001,
        )
        .unwrap();
        assert!(validate_daemon_directory_custody_metadata(
            CustodyMetadata {
                owner_uid: 0,
                mode: 0o40700,
                is_expected_type: true,
            },
            1001,
        )
        .is_err());
        assert!(validate_request_secret_custody_metadata(
            CustodyMetadata {
                owner_uid: 0,
                ..secret
            },
            1001
        )
        .is_err());
        assert!(validate_request_secret_custody_metadata(
            CustodyMetadata {
                mode: 0o100_640,
                ..secret
            },
            1001
        )
        .is_err());
        assert!(validate_request_secret_custody_metadata(
            CustodyMetadata {
                is_expected_type: false,
                ..secret
            },
            1001
        )
        .is_err());

        let verify = CustodyMetadata {
            owner_uid: 0,
            mode: 0o100_644,
            is_expected_type: true,
        };
        validate_verify_key_custody_metadata(verify).unwrap();
        assert!(validate_verify_key_custody_metadata(CustodyMetadata {
            owner_uid: 1001,
            ..verify
        })
        .is_err());

        let expected = UnixSocketSecurity {
            owner_uid: 1001,
            group_gid: 77,
            mode: 0o600,
        };
        let socket = SocketCustodyMetadata {
            owner_uid: 1001,
            group_gid: 77,
            mode: 0o140_600,
            is_socket: true,
            is_symlink: false,
        };
        validate_socket_custody_metadata(socket, expected).unwrap();
        for bad in [
            SocketCustodyMetadata {
                is_socket: false,
                ..socket
            },
            SocketCustodyMetadata {
                is_symlink: true,
                ..socket
            },
            SocketCustodyMetadata {
                owner_uid: 0,
                ..socket
            },
            SocketCustodyMetadata {
                group_gid: 78,
                ..socket
            },
            SocketCustodyMetadata {
                mode: 0o140_660,
                ..socket
            },
        ] {
            assert!(validate_socket_custody_metadata(bad, expected).is_err());
        }
    }

    #[test]
    fn verify_key_replacement_overwrites_existing_target() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("broker.cap.verify");
        std::fs::write(&path, b"old-verify-key").unwrap();

        write_replace_file(&path, b"new-verify-key", 0o644).unwrap();

        assert_eq!(std::fs::read(path).unwrap(), b"new-verify-key");
    }

    #[test]
    fn signing_and_mac_paths_must_be_distinct() {
        let path = Path::new("broker-material");
        assert!(ensure_broker_key_separation(path, path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn non_root_signing_custody_is_explicitly_unsupported() {
        if rustix::process::geteuid().as_raw() == 0 {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let err = load_or_create_capability_keys(
            &dir.path().join("private").join(CAPABILITY_SIGNING_FILE),
        )
        .expect_err("non-root Unix must not gain signing custody");
        assert!(
            err.contains("unsupported") && err.contains("UID 0"),
            "{err}"
        );
    }
}
