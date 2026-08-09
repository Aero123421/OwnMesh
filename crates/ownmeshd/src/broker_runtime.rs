//! Fail-closed loading of native privileged-broker installations.
//!
//! `ownmeshd` is deliberately an unprivileged client. It may read the
//! request-MAC secret, but never the broker signing key. This module refuses
//! every caller-configurable endpoint and only accepts the exact root-owned
//! installation written by the native installer. Windows delegates unsafe
//! ACL/SCM/token work to the broker crate's narrow, safe facade.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use ownmesh_broker_client::{BrokerEndpoint, BrokerSecret, CapabilityVerifyKey};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

const LINUX_BROKER: &str = "/usr/lib/ownmesh/ownmesh-broker";
const LINUX_DAEMON: &str = "/usr/lib/ownmesh/ownmeshd";
const LINUX_STATE: &str = "/var/lib/ownmesh/broker";
const LINUX_RECORD: &str = "/var/lib/ownmesh/broker/broker-install.json";
const LINUX_SECRET: &str = "/var/lib/ownmesh/broker/broker.secret";
const LINUX_VERIFY: &str = "/var/lib/ownmesh/broker/broker.cap.verify";
const LINUX_CONFIG: &str = "/etc/ownmesh/ownmesh-broker.json";
const LINUX_UNIT: &str = "/etc/systemd/system/ownmesh-broker.service";
const LINUX_SOCKET: &str = "/run/ownmesh/broker.sock";

/// The only local broker inputs the unprivileged daemon may use.
#[derive(Clone)]
pub(crate) struct LinuxBrokerClient {
    pub(crate) endpoint: BrokerEndpoint,
    pub(crate) secret: BrokerSecret,
    /// Loaded and custody-checked even though v2 responses contain no
    /// capability. This proves the daemon is looking at the same installed
    /// broker key family, and prevents accepting a partially replaced install.
    #[allow(dead_code)]
    pub(crate) verify_key: CapabilityVerifyKey,
    pub(crate) trusted_executable: PathBuf,
}

/// Safe projection of the broker crate's Windows custody facade. The signing
/// key never crosses this API boundary.
#[cfg(windows)]
#[derive(Clone)]
pub(crate) struct WindowsBrokerClient {
    pub(crate) endpoint: BrokerEndpoint,
    pub(crate) secret: BrokerSecret,
    pub(crate) trust: ownmesh_broker_client::WindowsBrokerTrust,
    pub(crate) trusted_executable: PathBuf,
}

#[cfg(windows)]
pub(crate) fn load_windows_broker_client(
    current_exe: &Path,
) -> Result<WindowsBrokerClient, String> {
    let client = ownmesh_broker::load_windows_daemon_broker_client(current_exe)?;
    Ok(WindowsBrokerClient {
        endpoint: client.endpoint().clone(),
        secret: client.request_secret().clone(),
        trust: client.server_trust().clone(),
        trusted_executable: client.trusted_daemon_executable().to_path_buf(),
    })
}

#[derive(Debug, Clone)]
pub(crate) struct LinuxBrokerInstallPaths {
    record: PathBuf,
    broker: PathBuf,
    daemon: PathBuf,
    config: PathBuf,
    unit: PathBuf,
    secret: PathBuf,
    verify: PathBuf,
    socket: PathBuf,
}

impl LinuxBrokerInstallPaths {
    pub(crate) fn production() -> Self {
        Self {
            record: PathBuf::from(LINUX_RECORD),
            broker: PathBuf::from(LINUX_BROKER),
            daemon: PathBuf::from(LINUX_DAEMON),
            config: PathBuf::from(LINUX_CONFIG),
            unit: PathBuf::from(LINUX_UNIT),
            secret: PathBuf::from(LINUX_SECRET),
            verify: PathBuf::from(LINUX_VERIFY),
            socket: PathBuf::from(LINUX_SOCKET),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallRecord {
    installed: bool,
    endpoint: String,
    endpoint_kind: String,
    unit_path: Option<String>,
    secret_file: String,
    signing_key_file: String,
    verify_key_file: String,
    trusted_executable: String,
    socket_owner_uid: u32,
    socket_group_gid: u32,
    socket_mode: u32,
    allowed_uids: Vec<u32>,
    daemon_uid: u32,
    daemon_gid: u32,
    broker_binary: String,
    config_path: String,
    broker_sha256: String,
    trusted_executable_sha256: String,
    config_sha256: String,
    unit_sha256: String,
    #[serde(default)]
    support: String,
    // Keep deserialization closed over the authority-bearing schema. These
    // audit-only values are intentionally retained only for schema parity.
    installed_at_unix: i64,
    #[serde(default)]
    notes: Vec<String>,
}

/// Load the fixed Linux installation. Any custody, identity, endpoint, or
/// daemon-image mismatch is an error; callers must leave elevation unavailable.
pub(crate) fn load_linux_broker_client(current_exe: &Path) -> Result<LinuxBrokerClient, String> {
    load_linux_broker_client_at(current_exe, &LinuxBrokerInstallPaths::production())
}

fn load_linux_broker_client_at(
    current_exe: &Path,
    paths: &LinuxBrokerInstallPaths,
) -> Result<LinuxBrokerClient, String> {
    #[cfg(target_os = "linux")]
    {
        let record_bytes = read_regular_owned_mode(&paths.record, 0, 0o600)?;
        let record: InstallRecord = serde_json::from_slice(&record_bytes)
            .map_err(|error| format!("parse broker install record: {error}"))?;
        let daemon_uid = rustix::process::geteuid().as_raw();
        let daemon_gid = rustix::process::getegid().as_raw();
        validate_record(&record, paths, daemon_uid, daemon_gid)?;

        // The executable that holds the socket peer credential must be the
        // root-installed image that the broker independently pins. Do not
        // canonicalize a user-supplied path and then compare strings: both
        // current and installed files are opened only after identity checks.
        verify_root_hash(&paths.daemon, 0o755, &record.trusted_executable_sha256)?;
        let current = std::fs::canonicalize(current_exe)
            .map_err(|error| format!("canonicalize running ownmeshd image: {error}"))?;
        if current != paths.daemon {
            return Err(
                "running ownmeshd image is not the installed broker-trusted executable".into(),
            );
        }
        if sha256_file(&current)? != record.trusted_executable_sha256 {
            return Err("running ownmeshd image hash differs from broker install record".into());
        }

        verify_socket(&paths.socket, record.daemon_uid, record.daemon_gid, 0o600)?;
        let secret = BrokerSecret::from_bytes(read_regular_owned_mode(
            &paths.secret,
            record.daemon_uid,
            0o600,
        )?);
        if secret.as_bytes().len() < 32 {
            return Err("broker request-MAC secret is too short".into());
        }
        let verify_bytes = read_regular_owned_mode(&paths.verify, 0, 0o644)?;
        let verify_key = CapabilityVerifyKey::from_bytes(&verify_bytes)
            .map_err(|error| format!("load broker capability verify key: {error}"))?;
        Ok(LinuxBrokerClient {
            endpoint: BrokerEndpoint::UnixSocket(paths.socket.clone()),
            secret,
            verify_key,
            trusted_executable: paths.daemon.clone(),
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (current_exe, paths);
        Err(
            "unsupported: native privileged broker lifecycle is currently supported on Linux only"
                .into(),
        )
    }
}

#[cfg(target_os = "linux")]
fn validate_record(
    record: &InstallRecord,
    paths: &LinuxBrokerInstallPaths,
    uid: u32,
    gid: u32,
) -> Result<(), String> {
    if !record.installed
        || record.support != "supported"
        || record.endpoint != LINUX_SOCKET
        || record.endpoint_kind != "unix_socket"
        || record.unit_path.as_deref() != Some(LINUX_UNIT)
        || record.secret_file != LINUX_SECRET
        || record.verify_key_file != LINUX_VERIFY
        || record.signing_key_file != format!("{LINUX_STATE}/private/broker.cap.signing")
        || record.trusted_executable != LINUX_DAEMON
        || record.broker_binary != LINUX_BROKER
        || record.config_path != LINUX_CONFIG
        || record.daemon_uid == 0
        || record.daemon_uid != uid
        || record.daemon_gid == 0
        || record.daemon_gid != gid
        || record.allowed_uids != [uid]
        || record.socket_owner_uid != uid
        || record.socket_group_gid != gid
        || record.socket_mode != 0o600
    {
        return Err("broker install record is not an exact installed Linux custody record".into());
    }
    verify_root_hash(&paths.broker, 0o755, &record.broker_sha256)?;
    verify_root_hash(&paths.daemon, 0o755, &record.trusted_executable_sha256)?;
    verify_root_hash(&paths.config, 0o600, &record.config_sha256)?;
    verify_root_hash(&paths.unit, 0o644, &record.unit_sha256)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_regular_owned_mode(path: &Path, uid: u32, mode: u32) -> Result<Vec<u8>, String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect {}: {error}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.mode() & 0o777 != mode
    {
        return Err(format!("{} has unexpected file custody", path.display()));
    }
    std::fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))
}

#[cfg(target_os = "linux")]
fn verify_root_hash(path: &Path, mode: u32, expected_hash: &str) -> Result<(), String> {
    if expected_hash.len() != 64 || !expected_hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!("{} has invalid recorded SHA-256", path.display()));
    }
    if hex::encode(Sha256::digest(read_regular_owned_mode(path, 0, mode)?)) != expected_hash {
        return Err(format!(
            "{} hash differs from install record",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn sha256_file(path: &Path) -> Result<String, String> {
    Ok(hex::encode(Sha256::digest(std::fs::read(path).map_err(
        |error| format!("hash {}: {error}", path.display()),
    )?)))
}

#[cfg(target_os = "linux")]
fn verify_socket(path: &Path, uid: u32, gid: u32, mode: u32) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("inspect broker socket {}: {error}", path.display()))?;
    if !metadata.file_type().is_socket()
        || metadata.file_type().is_symlink()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.mode() & 0o777 != mode
    {
        return Err("broker Unix socket custody validation failed".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_or_authority_substituted_record_is_refused_before_connect() {
        #[cfg(target_os = "linux")]
        {
            let paths = LinuxBrokerInstallPaths::production();
            let record = InstallRecord {
                installed: true,
                endpoint: "/tmp/attacker.sock".into(),
                endpoint_kind: "unix_socket".into(),
                unit_path: Some(LINUX_UNIT.into()),
                secret_file: LINUX_SECRET.into(),
                signing_key_file: format!("{LINUX_STATE}/private/broker.cap.signing"),
                verify_key_file: LINUX_VERIFY.into(),
                trusted_executable: LINUX_DAEMON.into(),
                socket_owner_uid: 1000,
                socket_group_gid: 1000,
                socket_mode: 0o600,
                allowed_uids: vec![1000],
                daemon_uid: 1000,
                daemon_gid: 1000,
                broker_binary: LINUX_BROKER.into(),
                config_path: LINUX_CONFIG.into(),
                broker_sha256: "0".repeat(64),
                trusted_executable_sha256: "0".repeat(64),
                config_sha256: "0".repeat(64),
                unit_sha256: "0".repeat(64),
                support: "supported".into(),
                installed_at_unix: 1,
                notes: Vec::new(),
            };
            assert!(validate_record(&record, &paths, 1000, 1000).is_err());
        }
    }

    #[test]
    fn non_linux_loader_is_explicitly_unsupported() {
        #[cfg(not(target_os = "linux"))]
        assert!(load_linux_broker_client(Path::new("ignored")).is_err());
    }
}
