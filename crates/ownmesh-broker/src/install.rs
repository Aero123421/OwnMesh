//! Broker install / uninstall / status state (OS service unit templates + local marker).
//!
//! **Platform gate:** install never records `installed=true` until service activation
//! and a live endpoint have been independently verified. This implementation only
//! stages service templates, so it returns an explicit unsupported error and persists
//! `installed=false`; status may trust a separately activated legacy/operator record
//! only while its live socket and all custody metadata validate exactly.

use ownmesh_broker_client::{
    broker_endpoint_display, default_broker_endpoint, resolve_broker_endpoint, BrokerEndpoint,
    TransportKind,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::peer::{endpoint_supports_peer_cred_enforcement, peer_enforcement_unsupported_reason};
use crate::serve::{
    ensure_broker_key_separation, load_or_create_capability_keys, load_or_create_request_secret,
    load_verify_key, validate_daemon_dac_policy, validate_signing_key_custody,
    validate_verify_key_custody, UnixSocketSecurity, CAPABILITY_SIGNING_FILE,
    CAPABILITY_VERIFY_FILE,
};

pub const INSTALL_FILE: &str = "broker-install.json";

/// Explicit install-time trust boundary. No field is inferred from environment.
#[derive(Debug, Clone)]
pub struct BrokerInstallConfig {
    pub endpoint: Option<BrokerEndpoint>,
    pub trusted_executable: PathBuf,
    pub socket_security: UnixSocketSecurity,
    pub allowed_uids: Vec<u32>,
}

/// Persisted install record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRecord {
    pub installed: bool,
    pub installed_at_unix: i64,
    pub endpoint: String,
    pub endpoint_kind: String,
    pub unit_path: Option<String>,
    pub secret_file: String,
    /// Broker-only capability signing key path (never shared as broker.secret).
    #[serde(default)]
    pub signing_key_file: String,
    /// Distributable capability verify key path.
    #[serde(default)]
    pub verify_key_file: String,
    /// Canonical root-controlled ownmeshd executable trust anchor.
    #[serde(default)]
    pub trusted_executable: String,
    #[serde(default)]
    pub socket_owner_uid: u32,
    #[serde(default)]
    pub socket_group_gid: u32,
    #[serde(default)]
    pub socket_mode: u32,
    #[serde(default)]
    pub allowed_uids: Vec<u32>,
    pub notes: Vec<String>,
    /// Explicit platform support flag (`supported` | `unsupported`).
    #[serde(default = "default_support")]
    pub support: String,
}

fn default_support() -> String {
    "unknown".into()
}

/// Status snapshot for CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallStatus {
    pub installed: bool,
    pub network: &'static str,
    pub endpoint: Option<String>,
    pub endpoint_kind: String,
    pub secret_present: bool,
    pub signing_key_present: bool,
    pub verify_key_present: bool,
    pub unit_path: Option<String>,
    pub notes: Vec<String>,
    /// `supported` when peer-cred enforcement is available for this platform/endpoint.
    pub support: String,
}

fn broker_dir(base: &Path) -> PathBuf {
    base.join("broker")
}

fn install_path(base: &Path) -> PathBuf {
    broker_dir(base).join(INSTALL_FILE)
}

fn kind_name(k: TransportKind) -> &'static str {
    match k {
        TransportKind::NamedPipe => "named_pipe",
        TransportKind::UnixSocket => "unix_socket",
        TransportKind::LoopbackTcp => "loopback_tcp",
    }
}

/// Whether a persisted endpoint kind can enforce peer credentials on this host.
#[must_use]
pub fn endpoint_kind_peer_enforceable(kind: &str) -> bool {
    matches!(kind, "unix_socket") && cfg!(target_os = "linux")
}

/// Install broker metadata + OS unit/service template under `base` (state dir).
///
/// On platforms/endpoints without safe peer-cred enforcement this still writes
/// diagnostic templates and key material when possible, but **never** returns
/// `installed: true`. Callers (CLI) must treat `installed == false` as failed/unsupported.
pub fn install_broker(
    _base: &Path,
    _endpoint_override: Option<BrokerEndpoint>,
) -> Result<InstallRecord, String> {
    Err("explicit trusted executable, socket owner/group/mode, and allowed UID configuration is required; install unsupported without it".into())
}

/// Stage an explicit privileged boundary.
///
/// Key material and an operator template are written, but activation is not
/// implemented here, so the function persists `installed=false` and returns `Err`.
#[allow(clippy::needless_pass_by_value)]
pub fn install_broker_with_config(
    base: &Path,
    config: BrokerInstallConfig,
) -> Result<InstallRecord, String> {
    validate_install_base(base)?;
    let dir = broker_dir(base);
    if dir.exists() {
        let metadata = std::fs::symlink_metadata(&dir).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "broker install directory {} must not be a symlink",
                dir.display()
            ));
        }
    }
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    prepare_root_directory(&dir, 0o755)?;
    // Broker socket custody is isolated from ownmesh-ipc's daemon socket.
    let runtime = dir.join("runtime");
    std::fs::create_dir_all(&runtime).map_err(|e| e.to_string())?;
    prepare_root_directory(&runtime, 0o755)?;
    let endpoint = config
        .endpoint
        .clone()
        .unwrap_or_else(|| default_broker_endpoint(&runtime));
    let socket_security = config.socket_security.validate()?;
    let daemon_uid = validate_daemon_dac_policy(socket_security, &config.allowed_uids)?;

    // Fail-closed platform gate: never claim a successful privileged install when
    // OS peer identity cannot be enforced for the chosen endpoint.
    if !endpoint_supports_peer_cred_enforcement(&endpoint) {
        let reason = peer_enforcement_unsupported_reason(&endpoint);
        let mut notes = vec![
            "unsupported".into(),
            reason.clone(),
            "refusing installed=true (no safe Named Pipe / TCP peer credential enforcement)".into(),
            "privileged broker install is failed/unsupported on this platform/endpoint".into(),
        ];
        let secret_file = dir.join("broker.secret");
        let signing_key_file = dir.join("private").join(CAPABILITY_SIGNING_FILE);
        let verify_key_file = dir.join(CAPABILITY_VERIFY_FILE);
        // Best-effort templates for operators; does not imply a working install.
        let unit_path = write_unit_template(
            &dir,
            &endpoint,
            &secret_file,
            &signing_key_file,
            &config.trusted_executable,
            socket_security,
            &config.allowed_uids,
            &mut notes,
        )
        .ok()
        .flatten();
        let rec = InstallRecord {
            installed: false,
            installed_at_unix: crate::now_unix(),
            endpoint: broker_endpoint_display(&endpoint),
            endpoint_kind: kind_name(endpoint.kind()).into(),
            unit_path: unit_path.map(|p| p.display().to_string()),
            secret_file: secret_file.display().to_string(),
            signing_key_file: signing_key_file.display().to_string(),
            verify_key_file: verify_key_file.display().to_string(),
            trusted_executable: config.trusted_executable.display().to_string(),
            socket_owner_uid: socket_security.owner_uid,
            socket_group_gid: socket_security.group_gid,
            socket_mode: socket_security.mode,
            allowed_uids: config.allowed_uids.clone(),
            notes,
            support: "unsupported".into(),
        };
        let raw = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?;
        write_install_record(base, raw.as_bytes())?;
        // Surface as Err so CLI exits non-zero, while the marker remains for status.
        return Err(format!(
            "unsupported: privileged broker install failed — {reason}"
        ));
    }

    validate_installed_endpoint_ancestry(&endpoint, daemon_uid)?;

    // Validate executable custody before producing any staged configuration.
    let policy = crate::peer::load_trusted_peer_policy(
        &config.trusted_executable,
        config.allowed_uids.clone(),
    )?;

    let secret_file = dir.join("broker.secret");
    // Exact 0600 ownership makes the configured daemon UID the only non-root
    // principal that can physically read the request MAC secret.
    let _secret = load_or_create_request_secret(&secret_file, daemon_uid)?;
    // Signing authority lives under a distinct root-only parent.
    let signing_key_file = dir.join("private").join(CAPABILITY_SIGNING_FILE);
    ensure_broker_key_separation(&secret_file, &signing_key_file)?;
    let _keys = load_or_create_capability_keys(&signing_key_file)?;
    ensure_broker_key_separation(&secret_file, &signing_key_file)?;
    let verify_key_file = dir.join(CAPABILITY_VERIFY_FILE);

    // Hard guard: signing material must not be the MAC secret file.
    if signing_key_file == secret_file {
        return Err("capability signing key must not share path with broker.secret".into());
    }

    let mut notes = vec![
        "broker is networkless (no non-loopback listen)".into(),
        "elevated requests require MAC + nonce + expiry + OS peer-bound capability".into(),
        "capability tokens are Ed25519-signed by broker-only key (not broker.secret)".into(),
        format!(
            "request MAC secret: {} (ownmeshd-readable); signing key: {} (broker-only)",
            secret_file.display(),
            signing_key_file.display()
        ),
    ];
    let unit_path = write_unit_template(
        &dir,
        &endpoint,
        &secret_file,
        &signing_key_file,
        policy.trusted_executable(),
        socket_security,
        policy.allowed_uids(),
        &mut notes,
    )?;

    notes.push(
        "staged/configured only: service activation and a live socket were not installed or verified"
            .into(),
    );
    notes.push("refusing installed=true after writing a state-local service template".into());
    let rec = InstallRecord {
        installed: false,
        installed_at_unix: crate::now_unix(),
        endpoint: broker_endpoint_display(&endpoint),
        endpoint_kind: kind_name(endpoint.kind()).into(),
        unit_path: unit_path.map(|p| p.display().to_string()),
        secret_file: secret_file.display().to_string(),
        signing_key_file: signing_key_file.display().to_string(),
        verify_key_file: verify_key_file.display().to_string(),
        trusted_executable: policy.trusted_executable().display().to_string(),
        socket_owner_uid: socket_security.owner_uid,
        socket_group_gid: socket_security.group_gid,
        socket_mode: socket_security.mode,
        allowed_uids: policy.allowed_uids().to_vec(),
        notes,
        support: "unsupported".into(),
    };
    let raw = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?;
    write_install_record(base, raw.as_bytes())?;
    Err("unsupported: broker configuration was staged, but service activation/live socket verification is not implemented; installed=false".into())
}

#[cfg(unix)]
fn validate_install_base(base: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("unsupported: Unix broker install requires effective UID 0".into());
    }
    let mut current = Some(base);
    while let Some(path) = current {
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|e| format!("inspect install ancestor {}: {e}", path.display()))?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "install ancestor {} must be root-owned and non-group/other-writable (fail-closed)",
                path.display()
            ));
        }
        current = path.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_install_base(_base: &Path) -> Result<(), String> {
    Err("unsupported: broker install custody is unavailable on this OS".into())
}

#[cfg(target_os = "linux")]
fn root_owned_directory_ancestry(start: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut current = Some(start);
    while let Some(path) = current {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return false;
        }
        current = path.parent();
    }
    true
}

#[cfg(target_os = "linux")]
fn daemon_traversable_root_ancestry(start: &Path, daemon_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let mut current = Some(start);
    while let Some(path) = current {
        let Ok(metadata) = std::fs::symlink_metadata(path) else {
            return false;
        };
        if crate::serve::validate_daemon_directory_custody_metadata(
            crate::serve::CustodyMetadata {
                owner_uid: metadata.uid(),
                mode: metadata.mode(),
                is_expected_type: metadata.file_type().is_dir()
                    && !metadata.file_type().is_symlink(),
            },
            daemon_uid,
        )
        .is_err()
        {
            return false;
        }
        current = path.parent();
    }
    true
}

#[cfg(target_os = "linux")]
fn install_record_custody_valid(path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(parent) = path.parent() else {
        return false;
    };
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.uid() == 0
        && metadata.mode() & 0o022 == 0
        && root_owned_directory_ancestry(parent)
}

#[cfg(not(target_os = "linux"))]
fn install_record_custody_valid(_path: &Path) -> bool {
    false
}

fn validate_installed_endpoint_ancestry(
    endpoint: &BrokerEndpoint,
    daemon_uid: u32,
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        let BrokerEndpoint::UnixSocket(path) = endpoint else {
            return Err("only a Linux Unix socket can satisfy endpoint custody".into());
        };
        if !path.is_absolute()
            || !path
                .parent()
                .is_some_and(|parent| daemon_traversable_root_ancestry(parent, daemon_uid))
        {
            return Err(format!(
                "broker endpoint {} requires root-owned non-writable directory ancestry (fail-closed)",
                path.display()
            ));
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (endpoint, daemon_uid);
        Err("broker endpoint custody unsupported on this OS (fail-closed)".into())
    }
}

fn write_template_file(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let parent = path
        .parent()
        .ok_or_else(|| format!("template {} requires a parent", path.display()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("broker-template"),
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options.open(&temp).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    prepare_root_file(&temp, 0o644)?;
    // Rust 1.92 replaces an existing Windows target in the rename operation;
    // never expose a delete/create gap for service templates.
    std::fs::rename(&temp, path).map_err(|e| e.to_string())
}

#[cfg(all(unix, not(target_os = "macos")))]
fn systemd_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
}

fn write_install_record(base: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let path = install_path(base);
    let parent = path
        .parent()
        .ok_or_else(|| "install record requires a parent".to_string())?;
    let temp = parent.join(format!(
        ".{INSTALL_FILE}.{}.tmp",
        uuid::Uuid::new_v4().simple()
    ));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o644);
    }
    let mut file = options
        .open(&temp)
        .map_err(|e| format!("create install record {}: {e}", temp.display()))?;
    file.write_all(bytes)
        .map_err(|e| format!("write install record {}: {e}", temp.display()))?;
    file.sync_all()
        .map_err(|e| format!("sync install record {}: {e}", temp.display()))?;
    #[cfg(unix)]
    {
        prepare_root_file(&temp, 0o644)?;
    }
    // Keep the old record present until Rust 1.92 atomically replaces it.
    std::fs::rename(&temp, &path)
        .map_err(|e| format!("replace install record {}: {e}", path.display()))
}

#[cfg(unix)]
fn prepare_root_file(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    rustix::fs::chown(
        path.as_os_str().as_bytes(),
        Some(rustix::process::Uid::from_raw(0)),
        Some(rustix::process::Gid::from_raw(0)),
    )
    .map_err(|e| format!("chown root:root {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))
}

#[cfg(unix)]
fn prepare_root_directory(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if rustix::process::geteuid().as_raw() != 0 {
        return Err("unsupported: Unix broker custody requires effective UID 0".into());
    }
    let before = std::fs::symlink_metadata(path)
        .map_err(|e| format!("inspect broker directory {}: {e}", path.display()))?;
    if !before.file_type().is_dir() || before.file_type().is_symlink() {
        return Err(format!(
            "broker custody path {} must be a real directory, not a symlink",
            path.display()
        ));
    }
    rustix::fs::chown(
        path.as_os_str().as_bytes(),
        Some(rustix::process::Uid::from_raw(0)),
        Some(rustix::process::Gid::from_raw(0)),
    )
    .map_err(|e| format!("chown root:root {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {:o} {}: {e}", mode, path.display()))?;
    let mut current = Some(path);
    while let Some(candidate) = current {
        let metadata = std::fs::symlink_metadata(candidate).map_err(|e| e.to_string())?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            return Err(format!(
                "broker custody ancestor {} must be root-owned and non-group/other-writable",
                candidate.display()
            ));
        }
        current = candidate.parent();
    }
    Ok(())
}

#[cfg(not(unix))]
fn prepare_root_directory(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("broker directory custody unsupported on this OS (fail-closed)".into())
}

/// Remove install marker and unit templates (does not kill a running broker).
pub fn uninstall_broker(base: &Path) -> Result<(), String> {
    validate_install_base(base)?;
    let dir = broker_dir(base);
    let marker = install_path(base);
    if marker.exists() {
        std::fs::remove_file(&marker).map_err(|e| e.to_string())?;
    }
    for name in [
        "ownmesh-broker.service",
        "com.ownmesh.broker.plist",
        "ownmesh-broker-service.xml",
        "README-INSTALL.txt",
    ] {
        let path = dir.join(name);
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| e.to_string())?;
        }
    }
    // Keep secret + signing keys unless explicitly purged — write uninstalled marker.
    let rec = InstallRecord {
        installed: false,
        installed_at_unix: crate::now_unix(),
        endpoint: String::new(),
        endpoint_kind: String::new(),
        unit_path: None,
        secret_file: dir.join("broker.secret").display().to_string(),
        signing_key_file: dir
            .join("private")
            .join(CAPABILITY_SIGNING_FILE)
            .display()
            .to_string(),
        verify_key_file: dir.join(CAPABILITY_VERIFY_FILE).display().to_string(),
        trusted_executable: String::new(),
        socket_owner_uid: 0,
        socket_group_gid: 0,
        socket_mode: 0,
        allowed_uids: vec![],
        notes: vec!["uninstalled".into()],
        support: "unsupported".into(),
    };
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let raw = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?;
    write_install_record(base, raw.as_bytes())?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn regular_file_custody_valid(path: &Path, owner_uid: u32, mode: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    md.file_type().is_file()
        && !md.file_type().is_symlink()
        && md.uid() == owner_uid
        && md.mode() & 0o777 == mode
}

#[cfg(not(target_os = "linux"))]
fn regular_file_custody_valid(_path: &Path, _owner_uid: u32, _mode: u32) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn endpoint_socket_custody_valid(path: &Path, expected: UnixSocketSecurity) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    let Ok(md) = std::fs::symlink_metadata(path) else {
        return false;
    };
    crate::serve::validate_socket_custody_metadata(
        crate::serve::SocketCustodyMetadata {
            owner_uid: md.uid(),
            group_gid: md.gid(),
            mode: md.mode(),
            is_socket: md.file_type().is_socket(),
            is_symlink: md.file_type().is_symlink(),
        },
        expected,
    )
    .is_ok()
        && std::os::unix::net::UnixStream::connect(path).is_ok()
}

#[cfg(not(target_os = "linux"))]
fn endpoint_socket_custody_valid(_path: &Path, _expected: UnixSocketSecurity) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn file_identities_differ(first: &Path, second: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(a), Ok(b)) = (std::fs::metadata(first), std::fs::metadata(second)) else {
        return false;
    };
    (a.dev(), a.ino()) != (b.dev(), b.ino())
}

#[cfg(not(target_os = "linux"))]
fn file_identities_differ(_first: &Path, _second: &Path) -> bool {
    false
}

/// Read install status. A record is installed only while every configured file
/// and the live Unix socket still have exact trusted metadata.
pub fn broker_status(base: &Path) -> Result<InstallStatus, String> {
    let path = install_path(base);
    let secret_path = broker_dir(base).join("broker.secret");
    let signing_path = broker_dir(base)
        .join("private")
        .join(CAPABILITY_SIGNING_FILE);
    let verify_path = broker_dir(base).join(CAPABILITY_VERIFY_FILE);
    let physical_presence = || {
        (
            std::fs::symlink_metadata(&secret_path).is_ok(),
            std::fs::symlink_metadata(&signing_path).is_ok(),
            std::fs::symlink_metadata(&verify_path).is_ok(),
        )
    };
    if std::fs::symlink_metadata(&path).is_err() || !install_record_custody_valid(&path) {
        let (secret_present, signing_key_present, verify_key_present) = physical_presence();
        return Ok(InstallStatus {
            installed: false,
            network: "disabled",
            endpoint: None,
            endpoint_kind: String::new(),
            secret_present,
            signing_key_present,
            verify_key_present,
            unit_path: None,
            notes: vec!["unsupported: missing or untrusted install record (fail-closed)".into()],
            support: "unsupported".into(),
        });
    }

    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let rec: InstallRecord = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let (secret_present, signing_key_present, verify_key_present) = physical_presence();
    let socket_security = UnixSocketSecurity {
        owner_uid: rec.socket_owner_uid,
        group_gid: rec.socket_group_gid,
        mode: rec.socket_mode,
    };
    let exact_dac = validate_daemon_dac_policy(socket_security, &rec.allowed_uids).is_ok();
    let expected_paths = Path::new(&rec.secret_file) == secret_path
        && Path::new(&rec.signing_key_file) == signing_path
        && Path::new(&rec.verify_key_file) == verify_path;
    let trusted_custody = crate::peer::load_trusted_peer_policy(
        Path::new(&rec.trusted_executable),
        rec.allowed_uids.clone(),
    )
    .map(|policy| policy.trusted_executable() == Path::new(&rec.trusted_executable))
    .unwrap_or(false);
    let secret_valid = regular_file_custody_valid(&secret_path, rec.socket_owner_uid, 0o600)
        && std::fs::read(&secret_path).is_ok_and(|bytes| bytes.len() >= 32);
    let verify_valid = regular_file_custody_valid(&verify_path, 0, 0o644)
        && validate_verify_key_custody(&verify_path).is_ok()
        && load_verify_key(&verify_path).is_ok();
    let signing_valid = validate_signing_key_custody(&signing_path).is_ok();
    let keys_separate = file_identities_differ(&secret_path, &signing_path)
        && ensure_broker_key_separation(&secret_path, &signing_path).is_ok();

    let resolved_endpoint = resolve_broker_endpoint(base, Some(&rec.endpoint)).ok();
    let endpoint_live = resolved_endpoint.as_ref().is_some_and(|endpoint| {
        kind_name(endpoint.kind()) == rec.endpoint_kind
            && endpoint_kind_peer_enforceable(&rec.endpoint_kind)
            && validate_installed_endpoint_ancestry(endpoint, rec.socket_owner_uid).is_ok()
            && matches!(endpoint, BrokerEndpoint::UnixSocket(socket_path)
                if endpoint_socket_custody_valid(socket_path, socket_security))
    });
    let boundary_valid = rec.support == "supported"
        && expected_paths
        && exact_dac
        && trusted_custody
        && secret_valid
        && signing_valid
        && verify_valid
        && keys_separate
        && endpoint_live;
    let installed = rec.installed && boundary_valid;
    let mut notes = rec.notes;
    if rec.installed && !installed {
        notes.push(
            "installed=true cleared: live socket or exact file/socket custody validation failed"
                .into(),
        );
    }
    if !boundary_valid {
        notes.push(
            "unsupported: broker is not active with the exact configured trust boundary".into(),
        );
    }

    Ok(InstallStatus {
        installed,
        network: "disabled",
        endpoint: (!rec.endpoint.is_empty()).then_some(rec.endpoint),
        endpoint_kind: rec.endpoint_kind,
        secret_present,
        signing_key_present,
        verify_key_present,
        unit_path: rec.unit_path,
        notes,
        support: if boundary_valid {
            "supported"
        } else {
            "unsupported"
        }
        .into(),
    })
}

fn write_unit_template(
    dir: &Path,
    endpoint: &BrokerEndpoint,
    secret_file: &Path,
    signing_key_file: &Path,
    trusted_executable: &Path,
    socket_security: UnixSocketSecurity,
    allowed_uids: &[u32],
    notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
    #[cfg(windows)]
    let readme = dir.join("README-INSTALL.txt");
    let allowed_args = allowed_uids.iter().fold(String::new(), |mut args, uid| {
        write!(args, " --allowed-uid {uid}").expect("writing to String cannot fail");
        args
    });
    #[cfg(windows)]
    {
        let xml = dir.join("ownmesh-broker-service.xml");
        let pipe = match endpoint {
            BrokerEndpoint::NamedPipe(n) => n.clone(),
            other => broker_endpoint_display(other),
        };
        let body = format!(
            r#"<!-- OwnMesh privileged broker Windows Service template
  Named Pipe peer PID/token/ACL cannot be safely enforced under forbid(unsafe_code).
  Install is explicit UNSUPPORTED until a safe peer-cred path exists.
  Docs: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
-->
<service>
  <id>ownmesh-broker</id>
  <name>OwnMesh Privileged Broker</name>
  <description>Networkless elevated command broker (UNSUPPORTED without peer creds)</description>
  <executable>ownmesh-broker.exe</executable>
  <arguments>run --endpoint pipe:{pipe} --secret-file "{secret}" --signing-key-file "{signing}" --trusted-executable "{trusted}" --socket-owner-uid {owner} --socket-group-gid {group} --socket-mode {mode:o}{allowed}</arguments>
</service>
"#,
            secret = secret_file.display(),
            signing = signing_key_file.display(),
            trusted = trusted_executable.display(),
            owner = socket_security.owner_uid,
            group = socket_security.group_gid,
            mode = socket_security.mode,
            allowed = allowed_args,
        );
        write_template_file(&xml, body.as_bytes())?;
        write_template_file(
            &readme,
            b"UNSUPPORTED on Windows:\n  Safe Named Pipe client PID/token/ACL enforcement is not available.\n  ownmesh-broker install/status/run refuse installed=true / production serve.\n",
        )?;
        notes.push(
            "Windows Service template written for reference only (install remains unsupported)"
                .into(),
        );
        return Ok(Some(xml));
    }
    #[cfg(target_os = "macos")]
    {
        let plist = dir.join("com.ownmesh.broker.plist");
        let sock = match endpoint {
            BrokerEndpoint::UnixSocket(p) => p.display().to_string(),
            other => broker_endpoint_display(other),
        };
        let body = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- LaunchDaemon template: root-owned unix socket + code signature verification at install -->
<plist version="1.0">
<dict>
  <key>Label</key><string>com.ownmesh.broker</string>
  <key>ProgramArguments</key>
  <array>
    <string>/usr/local/bin/ownmesh-broker</string>
    <string>run</string>
    <string>--endpoint</string><string>unix:{sock}</string>
    <string>--secret-file</string><string>{secret}</string>
    <string>--signing-key-file</string><string>{signing}</string>
    <string>--trusted-executable</string><string>{trusted}</string>
    <string>--socket-owner-uid</string><string>{owner}</string>
    <string>--socket-group-gid</string><string>{group}</string>
    <string>--socket-mode</string><string>{mode:o}</string>
    {allowed_xml}
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
            secret = secret_file.display(),
            signing = signing_key_file.display(),
            trusted = trusted_executable.display(),
            owner = socket_security.owner_uid,
            group = socket_security.group_gid,
            mode = socket_security.mode,
            allowed_xml = allowed_uids
                .iter()
                .map(|uid| format!("<string>--allowed-uid</string><string>{uid}</string>"))
                .collect::<Vec<_>>()
                .join("\n    "),
        );
        write_template_file(&plist, body.as_bytes())?;
        notes.push("macOS LaunchDaemon plist written".into());
        return Ok(Some(plist));
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let unit = dir.join("ownmesh-broker.service");
        let sock = match endpoint {
            BrokerEndpoint::UnixSocket(p) => systemd_escape(&p.display().to_string()),
            other => systemd_escape(&broker_endpoint_display(other)),
        };
        let secret_arg = systemd_escape(&secret_file.display().to_string());
        let signing_arg = systemd_escape(&signing_key_file.display().to_string());
        let trusted_arg = systemd_escape(&trusted_executable.display().to_string());
        let writable_dir = systemd_escape(&dir.display().to_string());
        let body = format!(
            r#"[Unit]
Description=OwnMesh networkless privileged broker
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ownmesh-broker run --endpoint "unix:{sock}" --secret-file "{secret}" --signing-key-file "{signing}" --trusted-executable "{trusted}" --socket-owner-uid {owner} --socket-group-gid {group} --socket-mode {mode:o}{allowed}
Restart=on-failure
# Hardening (systemd)
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
ReadWritePaths="{writable_dir}"
PrivateTmp=true
# Socket custody is explicit; peer PID/UID/exe checked via SO_PEERCRED + /proc.
# Capability mint key is broker-only (separate from request MAC secret)

[Install]
WantedBy=multi-user.target
"#,
            secret = secret_arg,
            signing = signing_arg,
            trusted = trusted_arg,
            owner = socket_security.owner_uid,
            group = socket_security.group_gid,
            mode = socket_security.mode,
            allowed = allowed_args,
            writable_dir = writable_dir,
        );
        write_template_file(&unit, body.as_bytes()).map_err(|e| e.to_string())?;
        notes.push("Linux systemd unit written (SO_PEERCRED on accept)".into());
        return Ok(Some(unit));
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = (
            dir,
            endpoint,
            secret_file,
            signing_key_file,
            trusted_executable,
            socket_security,
            allowed_uids,
            allowed_args,
            notes,
        );
        Ok(None)
    }
}

#[cfg(all(test, windows))]
mod windows_replacement_tests {
    use super::*;

    #[test]
    fn templates_and_install_records_replace_existing_targets() {
        let base = tempfile::tempdir().unwrap();
        let broker = broker_dir(base.path());
        std::fs::create_dir(&broker).unwrap();

        let template = broker.join("ownmesh-broker-service.xml");
        std::fs::write(&template, b"old-template").unwrap();
        write_template_file(&template, b"new-template").unwrap();
        assert_eq!(std::fs::read(&template).unwrap(), b"new-template");

        let record = install_path(base.path());
        std::fs::write(&record, b"old-record").unwrap();
        write_install_record(base.path(), b"new-record").unwrap();
        assert_eq!(std::fs::read(record).unwrap(), b"new-record");
    }
}
