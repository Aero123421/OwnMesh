//! Linux native installation of the networkless privileged broker.
//!
//! The service is intentionally boring: all production paths are fixed, root
//! owned, and recorded.  In particular, an installer never follows a link or
//! replaces an object it did not create.

use ownmesh_broker_client::BrokerEndpoint;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::serve::UnixSocketSecurity;
#[cfg(target_os = "linux")]
use crate::serve::{CAPABILITY_SIGNING_FILE, CAPABILITY_VERIFY_FILE};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};

pub const INSTALL_FILE: &str = "broker-install.json";
#[cfg(target_os = "linux")]
const LINUX_LIB_DIR: &str = "/usr/lib/ownmesh";
#[cfg(target_os = "linux")]
const LINUX_BROKER: &str = "/usr/lib/ownmesh/ownmesh-broker";
#[cfg(target_os = "linux")]
const LINUX_DAEMON: &str = "/usr/lib/ownmesh/ownmeshd";
#[cfg(target_os = "linux")]
const LINUX_STATE: &str = "/var/lib/ownmesh/broker";
#[cfg(target_os = "linux")]
const LINUX_RUNTIME: &str = "/run/ownmesh";
#[cfg(target_os = "linux")]
const LINUX_SOCKET: &str = "/run/ownmesh/broker.sock";
#[cfg(target_os = "linux")]
const LINUX_CONFIG: &str = "/etc/ownmesh/ownmesh-broker.json";
#[cfg(target_os = "linux")]
const LINUX_UNIT: &str = "/etc/systemd/system/ownmesh-broker.service";

/// Explicit install-time trust boundary. No value is inferred from a request.
#[derive(Debug, Clone)]
pub struct BrokerInstallConfig {
    pub endpoint: Option<BrokerEndpoint>,
    /// Source ownmeshd image.  It is copied into the same root-controlled
    /// directory as the broker so the peer policy can pin an executable inode.
    pub trusted_executable: PathBuf,
    /// Exact non-root identity of the unprivileged ownmeshd peer.
    pub daemon_uid: u32,
    pub daemon_gid: u32,
    pub socket_security: UnixSocketSecurity,
    pub allowed_uids: Vec<u32>,
}

/// Persisted identity of every static artifact this installer owns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRecord {
    pub installed: bool,
    pub installed_at_unix: i64,
    pub endpoint: String,
    pub endpoint_kind: String,
    pub unit_path: Option<String>,
    pub secret_file: String,
    #[serde(default)]
    pub signing_key_file: String,
    #[serde(default)]
    pub verify_key_file: String,
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
    #[serde(default)]
    pub daemon_uid: u32,
    #[serde(default)]
    pub daemon_gid: u32,
    #[serde(default)]
    pub broker_binary: String,
    #[serde(default)]
    pub config_path: String,
    #[serde(default)]
    pub broker_sha256: String,
    #[serde(default)]
    pub trusted_executable_sha256: String,
    #[serde(default)]
    pub config_sha256: String,
    #[serde(default)]
    pub unit_sha256: String,
    #[serde(default)]
    pub notes: Vec<String>,
    #[serde(default)]
    pub support: String,
}

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
    pub support: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg(target_os = "linux")]
struct LinuxRunConfig {
    endpoint: String,
    secret_file: String,
    signing_key_file: String,
    trusted_executable: String,
    socket_owner_uid: u32,
    socket_group_gid: u32,
    socket_mode: u32,
    allowed_uids: Vec<u32>,
    daemon_uid: u32,
    daemon_gid: u32,
}

#[cfg(target_os = "linux")]
fn install_path(_base: &Path) -> PathBuf {
    PathBuf::from(LINUX_STATE).join(INSTALL_FILE)
}

#[must_use]
pub fn endpoint_kind_peer_enforceable(kind: &str) -> bool {
    matches!(kind, "unix_socket") && cfg!(any(target_os = "linux", target_os = "macos"))
}

/// Install using this executable and a sibling `ownmeshd` image.  Distribution
/// archives intentionally place those two files together.
#[cfg_attr(not(target_os = "linux"), allow(clippy::needless_pass_by_value))]
pub fn install_broker(
    base: &Path,
    endpoint_override: Option<BrokerEndpoint>,
) -> Result<InstallRecord, String> {
    #[cfg(target_os = "linux")]
    {
        let broker =
            std::env::current_exe().map_err(|e| format!("resolve broker executable: {e}"))?;
        let daemon = broker.with_file_name("ownmeshd");
        return install_linux(
            base,
            &broker,
            &BrokerInstallConfig {
                endpoint: endpoint_override,
                trusted_executable: daemon,
                daemon_uid: 0,
                daemon_gid: 0,
                socket_security: UnixSocketSecurity {
                    owner_uid: 0,
                    group_gid: 0,
                    mode: 0o600,
                },
                allowed_uids: vec![0],
            },
        );
    }
    #[cfg(windows)]
    {
        if endpoint_override.is_some() {
            return Err(
                "Windows broker endpoint is fixed; refusing caller-controlled endpoint".into(),
            );
        }
        return crate::windows_lifecycle::install_windows_broker(base);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = base;
        let invoking_user = std::env::var("SUDO_UID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|uid| *uid != 0)
            .ok_or_else(|| {
                "macOS install requires an explicit non-root daemon identity; invoke through `sudo ownmesh privileged install`"
                    .to_string()
            })?;
        let invoking_group = std::env::var("SUDO_GID")
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|gid| *gid != 0)
            .ok_or_else(|| "macOS install requires SUDO_GID for the invoking user".to_string())?;
        let broker = std::env::current_exe()
            .map_err(|error| format!("resolve broker executable: {error}"))?;
        let daemon = broker.with_file_name("ownmeshd");
        let config = BrokerInstallConfig {
            endpoint: endpoint_override,
            trusted_executable: daemon,
            daemon_uid: invoking_user,
            daemon_gid: invoking_group,
            socket_security: UnixSocketSecurity {
                owner_uid: invoking_user,
                group_gid: invoking_group,
                mode: 0o600,
            },
            allowed_uids: vec![invoking_user],
        };
        return crate::macos_lifecycle::install_macos_broker(&broker, &config);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (base, endpoint_override);
        Err(
            "unsupported: native privileged broker lifecycle is unavailable on this platform"
                .into(),
        )
    }
}

#[allow(clippy::needless_pass_by_value)]
pub fn install_broker_with_config(
    base: &Path,
    config: BrokerInstallConfig,
) -> Result<InstallRecord, String> {
    #[cfg(target_os = "linux")]
    {
        let broker =
            std::env::current_exe().map_err(|e| format!("resolve broker executable: {e}"))?;
        return install_linux(base, &broker, &config);
    }
    #[cfg(windows)]
    {
        if config.endpoint.is_some() {
            return Err(
                "Windows broker endpoint is fixed; refusing caller-controlled endpoint".into(),
            );
        }
        return crate::windows_lifecycle::install_windows_broker(base);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = base;
        let broker = std::env::current_exe()
            .map_err(|error| format!("resolve broker executable: {error}"))?;
        return crate::macos_lifecycle::install_macos_broker(&broker, &config);
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (base, config);
        Err(
            "unsupported: native privileged broker lifecycle is unavailable on this platform"
                .into(),
        )
    }
}

#[cfg(target_os = "linux")]
fn install_linux(
    base: &Path,
    broker_source: &Path,
    config: &BrokerInstallConfig,
) -> Result<InstallRecord, String> {
    require_root()?;
    if !base.as_os_str().is_empty() && base != Path::new(".") {
        // State no longer follows a caller-controlled directory.  Keeping the
        // argument accepts old clients without letting them redirect root data.
    }
    let endpoint = match config.endpoint.as_ref() {
        None => PathBuf::from(LINUX_SOCKET),
        Some(BrokerEndpoint::UnixSocket(path)) if path == Path::new(LINUX_SOCKET) => path.clone(),
        Some(_) => {
            return Err(format!(
                "broker endpoint is fixed at {LINUX_SOCKET}; refusing caller-controlled endpoint"
            ))
        }
    };
    if config.daemon_uid == 0
        || config.daemon_gid == 0
        || config.socket_security
            != (UnixSocketSecurity {
                owner_uid: config.daemon_uid,
                group_gid: config.daemon_gid,
                mode: 0o600,
            })
        || config.allowed_uids != [config.daemon_uid]
    {
        return Err("Linux native service requires one explicit non-root ownmeshd UID/GID; socket owner and allowed UID must exactly match it".into());
    }
    verify_source(broker_source)?;
    verify_source(&config.trusted_executable)?;
    ensure_dir(Path::new("/etc/ownmesh"), 0o700)?;
    ensure_dir(Path::new(LINUX_LIB_DIR), 0o755)?;
    // These root-owned lookup-only parents let precisely the daemon UID reach
    // its 0600 socket and secret; broker keys/ledger/staging stay in private/.
    ensure_dir(Path::new("/var/lib/ownmesh"), 0o711)?;
    ensure_dir(Path::new(LINUX_STATE), 0o711)?;
    ensure_dir(Path::new(LINUX_RUNTIME), 0o711)?;

    let record_path = install_path(base);
    if record_path.exists() {
        let record = read_record(&record_path)?;
        validate_record(&record)?;
        validate_requested_matches_record(&record, broker_source, config)?;
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "ownmesh-broker.service"])?;
        wait_active(&record)?;
        return Ok(record);
    }
    for path in [
        Path::new(LINUX_BROKER),
        Path::new(LINUX_DAEMON),
        Path::new(LINUX_CONFIG),
        Path::new(LINUX_UNIT),
    ] {
        if path.exists() || std::fs::symlink_metadata(path).is_ok() {
            return Err(format!(
                "refusing foreign or unrecorded installation artifact {}",
                path.display()
            ));
        }
    }

    let mut created = Vec::new();
    let outcome = (|| {
        copy_new_root_file(broker_source, Path::new(LINUX_BROKER), 0o755)?;
        created.push(PathBuf::from(LINUX_BROKER));
        copy_new_root_file(&config.trusted_executable, Path::new(LINUX_DAEMON), 0o755)?;
        created.push(PathBuf::from(LINUX_DAEMON));
        let run = LinuxRunConfig {
            endpoint: format!("unix:{}", endpoint.display()),
            secret_file: format!("{LINUX_STATE}/broker.secret"),
            signing_key_file: format!("{LINUX_STATE}/private/{CAPABILITY_SIGNING_FILE}"),
            trusted_executable: LINUX_DAEMON.into(),
            socket_owner_uid: config.daemon_uid,
            socket_group_gid: config.daemon_gid,
            socket_mode: 0o600,
            allowed_uids: vec![config.daemon_uid],
            daemon_uid: config.daemon_uid,
            daemon_gid: config.daemon_gid,
        };
        let config_bytes = serde_json::to_vec_pretty(&run)
            .map_err(|e| format!("serialize service config: {e}"))?;
        write_new_root_file(Path::new(LINUX_CONFIG), &config_bytes, 0o600)?;
        created.push(PathBuf::from(LINUX_CONFIG));
        let unit_bytes = systemd_unit();
        write_new_root_file(Path::new(LINUX_UNIT), &unit_bytes, 0o644)?;
        created.push(PathBuf::from(LINUX_UNIT));
        let rec = InstallRecord {
            installed: true,
            installed_at_unix: crate::now_unix(),
            endpoint: endpoint.display().to_string(),
            endpoint_kind: "unix_socket".into(),
            unit_path: Some(LINUX_UNIT.into()),
            secret_file: run.secret_file,
            signing_key_file: run.signing_key_file,
            verify_key_file: format!("{LINUX_STATE}/{CAPABILITY_VERIFY_FILE}"),
            trusted_executable: LINUX_DAEMON.into(),
            socket_owner_uid: config.daemon_uid,
            socket_group_gid: config.daemon_gid,
            socket_mode: 0o600,
            allowed_uids: vec![config.daemon_uid],
            daemon_uid: config.daemon_uid,
            daemon_gid: config.daemon_gid,
            broker_binary: LINUX_BROKER.into(),
            config_path: LINUX_CONFIG.into(),
            broker_sha256: sha256_file(Path::new(LINUX_BROKER))?,
            trusted_executable_sha256: sha256_file(Path::new(LINUX_DAEMON))?,
            config_sha256: sha256_file(Path::new(LINUX_CONFIG))?,
            unit_sha256: sha256_file(Path::new(LINUX_UNIT))?,
            notes: vec![
                "Linux systemd native service; PrivateNetwork=yes; RestrictAddressFamilies=AF_UNIX"
                    .into(),
            ],
            support: "supported".into(),
        };
        let bytes = serde_json::to_vec_pretty(&rec)
            .map_err(|e| format!("serialize install record: {e}"))?;
        write_new_root_file(&record_path, &bytes, 0o600)?;
        created.push(record_path.clone());
        systemctl(&["daemon-reload"])?;
        systemctl(&["enable", "--now", "ownmesh-broker.service"])?;
        wait_active(&rec)?;
        Ok(rec)
    })();
    if outcome.is_err() {
        rollback_created(&created);
        let _ = systemctl(&["daemon-reload"]);
    }
    outcome
}

#[cfg(target_os = "linux")]
fn validate_requested_matches_record(
    record: &InstallRecord,
    broker_source: &Path,
    requested: &BrokerInstallConfig,
) -> Result<(), String> {
    if requested.daemon_uid != record.daemon_uid
        || requested.daemon_gid != record.daemon_gid
        || requested.socket_security.owner_uid != record.socket_owner_uid
        || requested.socket_security.group_gid != record.socket_group_gid
        || requested.socket_security.mode != record.socket_mode
        || requested.allowed_uids != record.allowed_uids
        || sha256_file(broker_source)? != record.broker_sha256
        || sha256_file(&requested.trusted_executable)? != record.trusted_executable_sha256
    {
        return Err(
            "idempotent reinstall identity/configuration mismatch; refusing overwrite".into(),
        );
    }
    Ok(())
}

pub fn uninstall_broker(base: &Path) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        require_root()?;
        let path = install_path(base);
        if !path.exists() {
            return Ok(());
        }
        let rec = read_record(&path)?;
        validate_record(&rec)?;
        systemctl(&["stop", "ownmesh-broker.service"])?;
        systemctl(&["disable", "ownmesh-broker.service"])?;
        if systemctl_status("is-active", "ownmesh-broker.service")? {
            return Err("ownmesh-broker service remains active after stop".into());
        }
        // Deletion is individually revalidated. Dynamic broker data is never
        // recursively removed: a changed/unrecorded item is preserved safely.
        for (artifact, hash) in [
            (
                rec.unit_path.as_deref().unwrap_or(""),
                rec.unit_sha256.as_str(),
            ),
            (rec.config_path.as_str(), rec.config_sha256.as_str()),
            (rec.broker_binary.as_str(), rec.broker_sha256.as_str()),
            (
                rec.trusted_executable.as_str(),
                rec.trusted_executable_sha256.as_str(),
            ),
        ] {
            let p = Path::new(artifact);
            verify_regular_root_hash(p, hash)?;
            std::fs::remove_file(p).map_err(|e| format!("remove {}: {e}", p.display()))?;
        }
        verify_regular_root_hash(&path, &sha256_file(&path)?)?; // custody before remove; record naturally has no self hash.
        std::fs::remove_file(&path).map_err(|e| format!("remove install record: {e}"))?;
        systemctl(&["daemon-reload"])?;
        if systemctl_status("is-enabled", "ownmesh-broker.service")?
            || systemctl_status("is-active", "ownmesh-broker.service")?
        {
            return Err("broker systemd unit still present after uninstall".into());
        }
        Ok(())
    }
    #[cfg(windows)]
    {
        return crate::windows_lifecycle::uninstall_windows_broker(base);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = base;
        return crate::macos_lifecycle::uninstall_macos_broker();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = base;
        Err(
            "unsupported: native privileged broker lifecycle is unavailable on this platform"
                .into(),
        )
    }
}

pub fn broker_status(base: &Path) -> Result<InstallStatus, String> {
    #[cfg(target_os = "linux")]
    {
        let record_path = install_path(base);
        if !record_path.exists() {
            return Ok(absent_status("no native Linux broker install record"));
        }
        let rec = match read_record(&record_path).and_then(|r| {
            validate_record(&r)?;
            Ok(r)
        }) {
            Ok(v) => v,
            Err(e) => {
                return Ok(InstallStatus {
                    notes: vec![format!("invalid native install: {e}")],
                    ..absent_status("custody validation failed")
                })
            }
        };
        let active = systemctl_status("is-active", "ownmesh-broker.service").unwrap_or(false)
            && active_pid_matches(Path::new(&rec.broker_binary)).unwrap_or(false);
        let socket_ok = endpoint_socket_valid(
            Path::new(&rec.endpoint),
            UnixSocketSecurity {
                owner_uid: rec.daemon_uid,
                group_gid: rec.daemon_gid,
                mode: 0o600,
            },
        );
        let installed = active && socket_ok;
        Ok(InstallStatus {
            installed,
            network: "disabled",
            endpoint: Some(rec.endpoint),
            endpoint_kind: rec.endpoint_kind,
            secret_present: regular_file_owned_mode(
                Path::new(&rec.secret_file),
                rec.daemon_uid,
                0o600,
            ),
            signing_key_present: Path::new(&rec.signing_key_file).is_file(),
            verify_key_present: Path::new(&rec.verify_key_file).is_file(),
            unit_path: rec.unit_path,
            notes: if installed {
                rec.notes
            } else {
                vec!["service inactive or socket custody/ready validation failed".into()]
            },
            support: if installed {
                "supported".into()
            } else {
                "unsupported".into()
            },
        })
    }
    #[cfg(windows)]
    {
        return crate::windows_lifecycle::broker_status_windows(base);
    }
    #[cfg(target_os = "macos")]
    {
        let _ = base;
        return crate::macos_lifecycle::broker_status_macos();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = base;
        Ok(absent_status(
            "native privileged broker lifecycle is unsupported on this OS",
        ))
    }
}

#[cfg(not(any(target_os = "macos", windows)))]
fn absent_status(note: &str) -> InstallStatus {
    InstallStatus {
        installed: false,
        network: "disabled",
        endpoint: None,
        endpoint_kind: String::new(),
        secret_present: false,
        signing_key_present: false,
        verify_key_present: false,
        unit_path: None,
        notes: vec![note.into()],
        support: "unsupported".into(),
    }
}

#[cfg(target_os = "linux")]
pub fn load_linux_run_config(path: &Path) -> Result<crate::serve::BrokerServeConfig, String> {
    require_root()?;
    verify_regular_root(path, 0o600)?;
    let raw =
        std::fs::read(path).map_err(|e| format!("read broker config {}: {e}", path.display()))?;
    let cfg: LinuxRunConfig =
        serde_json::from_slice(&raw).map_err(|e| format!("parse broker config: {e}"))?;
    let endpoint = cfg
        .endpoint
        .strip_prefix("unix:")
        .ok_or_else(|| "broker config endpoint must be unix:".to_string())?;
    if endpoint != LINUX_SOCKET
        || cfg.secret_file != format!("{LINUX_STATE}/broker.secret")
        || cfg.signing_key_file != format!("{LINUX_STATE}/private/{CAPABILITY_SIGNING_FILE}")
        || cfg.trusted_executable != LINUX_DAEMON
        || cfg.daemon_uid == 0
        || cfg.daemon_gid == 0
        || cfg.socket_owner_uid != cfg.daemon_uid
        || cfg.socket_group_gid != cfg.daemon_gid
        || cfg.socket_mode != 0o600
        || cfg.allowed_uids != [cfg.daemon_uid]
    {
        return Err("broker config differs from strict native Linux policy".into());
    }
    Ok(crate::serve::BrokerServeConfig {
        endpoint: BrokerEndpoint::UnixSocket(PathBuf::from(endpoint)),
        secret_file: PathBuf::from(cfg.secret_file),
        signing_key_file: PathBuf::from(cfg.signing_key_file),
        trusted_executable: PathBuf::from(cfg.trusted_executable),
        allowed_uids: cfg.allowed_uids,
        socket_security: UnixSocketSecurity {
            owner_uid: cfg.daemon_uid,
            group_gid: cfg.daemon_gid,
            mode: 0o600,
        },
        addr_file: None,
    })
}

#[cfg(not(target_os = "linux"))]
pub fn load_linux_run_config(_path: &Path) -> Result<crate::serve::BrokerServeConfig, String> {
    Err("unsupported: native privileged broker lifecycle is unavailable on this platform".into())
}

#[cfg(target_os = "linux")]
fn systemd_unit() -> Vec<u8> {
    format!("[Unit]\nDescription=OwnMesh networkless privileged broker\nAfter=local-fs.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\nExecStart={LINUX_BROKER} run --config {LINUX_CONFIG}\nRestart=on-failure\nRestartSec=1\nUMask=0077\nNoNewPrivileges=yes\nPrivateNetwork=yes\nRestrictAddressFamilies=AF_UNIX\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\nLockPersonality=yes\nReadWritePaths={LINUX_STATE} {LINUX_RUNTIME}\n\n[Install]\nWantedBy=multi-user.target\n").into_bytes()
}

#[cfg(target_os = "linux")]
fn require_root() -> Result<(), String> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err("native Linux broker lifecycle requires effective UID 0; re-run with elevation".into())
    }
}
#[cfg(target_os = "linux")]
fn systemctl(args: &[&str]) -> Result<(), String> {
    let out = std::process::Command::new("systemctl")
        .args(args)
        .output()
        .map_err(|e| format!("execute systemctl: {e}"))?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "systemctl {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ))
    }
}
#[cfg(target_os = "linux")]
fn systemctl_status(command: &str, unit: &str) -> Result<bool, String> {
    let status = std::process::Command::new("systemctl")
        .args([command, "--quiet", unit])
        .status()
        .map_err(|e| format!("execute systemctl {command}: {e}"))?;
    Ok(status.success())
}
#[cfg(target_os = "linux")]
fn wait_active(record: &InstallRecord) -> Result<(), String> {
    for _ in 0..30 {
        if systemctl_status("is-active", "ownmesh-broker.service")?
            && active_pid_matches(Path::new(&record.broker_binary))?
            && endpoint_socket_valid(
                Path::new(&record.endpoint),
                UnixSocketSecurity {
                    owner_uid: record.daemon_uid,
                    group_gid: record.daemon_gid,
                    mode: 0o600,
                },
            )
        {
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    Err("ownmesh-broker did not become active with a custody-valid Unix socket".into())
}

/// `systemctl is-active` alone is not enough: prove that systemd's main PID
/// is still executing the immutable image recorded by this installation.
#[cfg(target_os = "linux")]
fn active_pid_matches(expected: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let output = std::process::Command::new("systemctl")
        .args([
            "show",
            "--property=MainPID",
            "--value",
            "ownmesh-broker.service",
        ])
        .output()
        .map_err(|e| format!("read broker MainPID: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "read broker MainPID: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let pid = String::from_utf8_lossy(&output.stdout)
        .trim()
        .parse::<u32>()
        .map_err(|_| "broker systemd MainPID is missing".to_string())?;
    if pid == 0 {
        return Ok(false);
    }
    let process = std::fs::metadata(format!("/proc/{pid}/exe"))
        .map_err(|e| format!("inspect broker process executable: {e}"))?;
    let installed = std::fs::metadata(expected)
        .map_err(|e| format!("inspect installed broker executable: {e}"))?;
    Ok(process.dev() == installed.dev() && process.ino() == installed.ino())
}
#[cfg(target_os = "linux")]
fn ensure_dir(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !path.exists() {
        std::fs::create_dir(path).map_err(|e| format!("create {}: {e}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .map_err(|e| format!("chmod {}: {e}", path.display()))?;
    }
    let md =
        std::fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if !md.file_type().is_dir()
        || md.file_type().is_symlink()
        || md.uid() != 0
        || md.mode() & 0o777 != mode
    {
        return Err(format!(
            "directory {} is not root-owned mode {:04o} without symlink",
            path.display(),
            mode
        ));
    }
    ensure_no_extended_acl(path)?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn verify_source(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::symlink_metadata(path)
        .map_err(|e| format!("inspect source {}: {e}", path.display()))?;
    if !md.file_type().is_file() || md.file_type().is_symlink() || md.mode() & 0o022 != 0 {
        return Err(format!(
            "source {} must be a non-symlink regular executable not writable by group/other",
            path.display()
        ));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn write_new_root_file(path: &Path, bytes: &[u8], mode: u32) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .map_err(|e| format!("create {}: {e}", path.display()))?;
    f.write_all(bytes)
        .map_err(|e| format!("write {}: {e}", path.display()))?;
    f.sync_all()
        .map_err(|e| format!("fsync {}: {e}", path.display()))?;
    root_mode(path, mode)
}
#[cfg(target_os = "linux")]
fn copy_new_root_file(source: &Path, destination: &Path, mode: u32) -> Result<(), String> {
    let bytes =
        std::fs::read(source).map_err(|e| format!("read source {}: {e}", source.display()))?;
    write_new_root_file(destination, &bytes, mode)?;
    if sha256_bytes(&bytes) != sha256_file(destination)? {
        return Err(format!(
            "hash verification failed for {}",
            destination.display()
        ));
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn root_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    rustix::fs::chown(
        path.as_os_str().as_bytes(),
        Some(rustix::process::Uid::from_raw(0)),
        Some(rustix::process::Gid::from_raw(0)),
    )
    .map_err(|e| format!("chown {}: {e}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("chmod {}: {e}", path.display()))
}
#[cfg(target_os = "linux")]
fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
#[cfg(target_os = "linux")]
fn sha256_file(path: &Path) -> Result<String, String> {
    Ok(sha256_bytes(
        &std::fs::read(path).map_err(|e| format!("hash {}: {e}", path.display()))?,
    ))
}
#[cfg(target_os = "linux")]
fn verify_regular_root(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let md =
        std::fs::symlink_metadata(path).map_err(|e| format!("inspect {}: {e}", path.display()))?;
    if md.file_type().is_file()
        && !md.file_type().is_symlink()
        && md.uid() == 0
        && md.mode() & 0o777 == mode
    {
        ensure_no_extended_acl(path)
    } else {
        Err(format!(
            "{} is not an expected root-owned mode {:04o} regular file",
            path.display(),
            mode
        ))
    }
}

#[cfg(target_os = "linux")]
fn regular_file_owned_mode(path: &Path, uid: u32, mode: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    std::fs::symlink_metadata(path).ok().is_some_and(|md| {
        md.file_type().is_file()
            && !md.file_type().is_symlink()
            && md.uid() == uid
            && md.mode() & 0o777 == mode
            && ensure_no_extended_acl(path).is_ok()
    })
}

/// POSIX ACLs can grant access that the mode bits do not show.  `getfacl` is
/// the portable operator-facing reader available on supported Linux hosts; if
/// it is installed, any named/default ACL is a custody violation.  Minimal
/// WSL images without ACL tooling expose no POSIX ACL administration surface,
/// so normal mode/owner validation remains available there.
#[cfg(target_os = "linux")]
fn ensure_no_extended_acl(path: &Path) -> Result<(), String> {
    let rendered = path.display().to_string();
    let output = match std::process::Command::new("getfacl")
        .args(["-cp", "--", rendered.as_str()])
        .output()
    {
        Ok(output) => output,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("inspect ACL {}: {error}", path.display())),
    };
    if !output.status.success() {
        return Err(format!(
            "inspect ACL {}: {}",
            path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    for line in String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        if !(line.starts_with("user::")
            || line.starts_with("group::")
            || line.starts_with("other::")
            || line.starts_with("mask::"))
        {
            return Err(format!(
                "extended/default ACL on {} is forbidden for privileged broker custody",
                path.display()
            ));
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn verify_regular_root_hash(path: &Path, hash: &str) -> Result<(), String> {
    verify_regular_root(
        path,
        if path == Path::new(LINUX_CONFIG) || path == Path::new(LINUX_STATE).join(INSTALL_FILE) {
            0o600
        } else if path == Path::new(LINUX_UNIT) {
            0o644
        } else {
            0o755
        },
    )?;
    if hash.is_empty() || sha256_file(path)? != hash {
        Err(format!(
            "identity/hash mismatch for {}; refusing deletion",
            path.display()
        ))
    } else {
        Ok(())
    }
}
#[cfg(target_os = "linux")]
fn read_record(path: &Path) -> Result<InstallRecord, String> {
    verify_regular_root(path, 0o600)?;
    serde_json::from_slice(&std::fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("parse install record: {e}"))
}
#[cfg(target_os = "linux")]
fn validate_record(rec: &InstallRecord) -> Result<(), String> {
    if !rec.installed
        || rec.support != "supported"
        || rec.endpoint != LINUX_SOCKET
        || rec.endpoint_kind != "unix_socket"
        || rec.unit_path.as_deref() != Some(LINUX_UNIT)
        || rec.broker_binary != LINUX_BROKER
        || rec.config_path != LINUX_CONFIG
        || rec.trusted_executable != LINUX_DAEMON
        || rec.daemon_uid == 0
        || rec.daemon_gid == 0
        || rec.allowed_uids != [rec.daemon_uid]
        || rec.socket_owner_uid != rec.daemon_uid
        || rec.socket_group_gid != rec.daemon_gid
        || rec.socket_mode != 0o600
    {
        return Err("install record is not an exact Linux native service record".into());
    }
    verify_regular_root_hash(Path::new(LINUX_BROKER), &rec.broker_sha256)?;
    verify_regular_root_hash(Path::new(LINUX_DAEMON), &rec.trusted_executable_sha256)?;
    verify_regular_root_hash(Path::new(LINUX_CONFIG), &rec.config_sha256)?;
    verify_regular_root_hash(Path::new(LINUX_UNIT), &rec.unit_sha256)?;
    let _ = load_linux_run_config(Path::new(LINUX_CONFIG))?;
    Ok(())
}
#[cfg(target_os = "linux")]
fn endpoint_socket_valid(path: &Path, expected: UnixSocketSecurity) -> bool {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};
    std::fs::symlink_metadata(path).ok().is_some_and(|md| {
        md.file_type().is_socket()
            && !md.file_type().is_symlink()
            && md.uid() == expected.owner_uid
            && md.gid() == expected.group_gid
            && md.mode() & 0o777 == expected.mode
            && std::os::unix::net::UnixStream::connect(path).is_ok()
    })
}
#[cfg(target_os = "linux")]
fn rollback_created(paths: &[PathBuf]) {
    for path in paths.iter().rev() {
        if let Ok(md) = std::fs::symlink_metadata(path) {
            use std::os::unix::fs::MetadataExt;
            if md.file_type().is_file() && !md.file_type().is_symlink() && md.uid() == 0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn linux_unit_has_no_shell_or_network() {
        #[cfg(target_os = "linux")]
        {
            let unit = String::from_utf8(systemd_unit()).unwrap();
            assert!(unit.contains("PrivateNetwork=yes"));
            assert!(unit.contains("RestrictAddressFamilies=AF_UNIX"));
            assert!(unit.contains("ExecStart=/usr/lib/ownmesh/ownmesh-broker run --config /etc/ownmesh/ownmesh-broker.json"));
            assert!(!unit.contains("sh -c"));
        }
    }
    #[test]
    fn non_linux_never_claims_native_support() {
        #[cfg(not(target_os = "linux"))]
        assert!(!broker_status(Path::new(".")).unwrap().installed);
    }
}
