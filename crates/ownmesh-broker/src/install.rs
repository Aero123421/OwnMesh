//! Broker install / uninstall / status state (OS service unit templates + local marker).
//!
//! **Production elevated broker is unsupported** until a secure mint authority exists.
//! Install/status always return `installed=false` / `support=unsupported` and never
//! provision a live root execution surface.

use ownmesh_broker_client::{broker_endpoint_display, BrokerEndpoint};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use crate::serve::{UnixSocketSecurity, CAPABILITY_SIGNING_FILE, CAPABILITY_VERIFY_FILE};

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

/// Whether a persisted endpoint kind can enforce peer credentials on this host.
#[must_use]
pub fn endpoint_kind_peer_enforceable(kind: &str) -> bool {
    matches!(kind, "unix_socket") && cfg!(target_os = "linux")
}

/// Refuse production installation without creating directories, templates,
/// markers, secrets, or any other privileged filesystem state.
pub fn install_broker(
    _base: &Path,
    _endpoint_override: Option<BrokerEndpoint>,
) -> Result<InstallRecord, String> {
    Err(
        "unsupported: elevated broker production install is disabled until a secure mint authority is established; no native service was activated or verified; no filesystem changes were made (fail-closed)"
            .into(),
    )
}

/// Refuse configured production installation with the same side-effect-free
/// behavior as [`install_broker`]. Configuration is intentionally ignored.
#[allow(clippy::needless_pass_by_value)]
pub fn install_broker_with_config(
    _base: &Path,
    _config: BrokerInstallConfig,
) -> Result<InstallRecord, String> {
    Err(
        "unsupported: elevated broker production install is disabled until a secure mint authority is established; no native service was activated or verified; no filesystem changes were made (fail-closed)"
            .into(),
    )
}

// Retained custody helpers for a future secure mint path; unused while production
// elevated broker remains unsupported.
#[allow(dead_code)]
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

#[allow(dead_code)]
#[cfg(not(unix))]
fn validate_install_base(_base: &Path) -> Result<(), String> {
    Err("unsupported: broker install custody is unavailable on this OS".into())
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[cfg(not(target_os = "linux"))]
fn install_record_custody_valid(_path: &Path) -> bool {
    false
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

/// Format `--allowed-uid` CLI flags for Windows service XML and Linux systemd units.
/// macOS LaunchDaemon templates emit separate plist entries instead.
#[cfg_attr(target_os = "macos", allow(dead_code))]
fn format_allowed_uid_cli_args(allowed_uids: &[u32]) -> String {
    allowed_uids.iter().fold(String::new(), |mut args, uid| {
        write!(args, " --allowed-uid {uid}").expect("writing to String cannot fail");
        args
    })
}

/// Escape values embedded in systemd unit `ExecStart=` command lines (Linux only).
#[cfg(all(unix, not(target_os = "macos")))]
fn systemd_escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('%', "%%")
}

#[allow(dead_code)]
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

#[allow(dead_code)]
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

#[allow(dead_code)]
#[cfg(not(unix))]
fn prepare_root_directory(_path: &Path, _mode: u32) -> Result<(), String> {
    Err("broker directory custody unsupported on this OS (fail-closed)".into())
}

/// Refuse production uninstallation without deleting or rewriting any privileged
/// filesystem state. Manual cleanup remains an explicit operator action.
pub fn uninstall_broker(_base: &Path) -> Result<(), String> {
    Err(
        "unsupported: elevated broker production uninstall is disabled; native service absence cannot be verified; no filesystem changes were made (fail-closed)"
            .into(),
    )
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[cfg(not(target_os = "linux"))]
fn regular_file_custody_valid(_path: &Path, _owner_uid: u32, _mode: u32) -> bool {
    false
}

#[allow(dead_code)]
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

#[allow(dead_code)]
#[cfg(not(target_os = "linux"))]
fn endpoint_socket_custody_valid(_path: &Path, _expected: UnixSocketSecurity) -> bool {
    false
}

#[allow(dead_code)]
#[cfg(target_os = "linux")]
fn file_identities_differ(first: &Path, second: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let (Ok(a), Ok(b)) = (std::fs::metadata(first), std::fs::metadata(second)) else {
        return false;
    };
    (a.dev(), a.ino()) != (b.dev(), b.ino())
}

#[allow(dead_code)]
#[cfg(not(target_os = "linux"))]
fn file_identities_differ(_first: &Path, _second: &Path) -> bool {
    false
}

/// Read install status. Production elevated broker is always `support=unsupported`
/// and `installed=false` until a secure mint authority exists — never trust a
/// hand-written success record or live socket as production-ready.
pub fn broker_status(base: &Path) -> Result<InstallStatus, String> {
    let path = install_path(base);
    let secret_path = broker_dir(base).join("broker.secret");
    let signing_path = broker_dir(base)
        .join("private")
        .join(CAPABILITY_SIGNING_FILE);
    let verify_path = broker_dir(base).join(CAPABILITY_VERIFY_FILE);
    let secret_present = std::fs::symlink_metadata(&secret_path).is_ok();
    let signing_key_present = std::fs::symlink_metadata(&signing_path).is_ok();
    let verify_key_present = std::fs::symlink_metadata(&verify_path).is_ok();

    let mut notes = vec![crate::serve::production_elevated_broker_unsupported()];
    let mut endpoint = None;
    let mut endpoint_kind = String::new();
    let mut unit_path = None;

    if std::fs::symlink_metadata(&path).is_ok() {
        if let Ok(raw) = std::fs::read_to_string(&path) {
            if let Ok(rec) = serde_json::from_str::<InstallRecord>(&raw) {
                endpoint = (!rec.endpoint.is_empty()).then_some(rec.endpoint);
                endpoint_kind = rec.endpoint_kind;
                unit_path = rec.unit_path;
                for n in rec.notes {
                    if !notes.iter().any(|existing| existing == &n) {
                        notes.push(n);
                    }
                }
                if rec.installed {
                    notes.push(
                        "installed=true cleared: production elevated broker is unsupported".into(),
                    );
                }
            } else {
                notes.push("unsupported: unreadable install record (fail-closed)".into());
            }
        }
    } else {
        notes.push("unsupported: missing install record (fail-closed)".into());
    }

    if secret_present || signing_key_present {
        notes.push(
            "warning: residual broker secret/signing material detected; production serve remains unsupported"
                .into(),
        );
    }

    Ok(InstallStatus {
        installed: false,
        network: "disabled",
        endpoint,
        endpoint_kind,
        secret_present,
        signing_key_present,
        verify_key_present,
        unit_path,
        notes,
        support: "unsupported".into(),
    })
}

#[allow(dead_code)]
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
            allowed = format_allowed_uid_cli_args(allowed_uids),
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
            allowed = format_allowed_uid_cli_args(allowed_uids),
            writable_dir = writable_dir,
        );
        write_template_file(&unit, body.as_bytes())?;
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
            notes,
        );
        Ok(None)
    }
}

#[cfg(test)]
mod allowed_uid_cli_args_tests {
    use super::format_allowed_uid_cli_args;

    #[test]
    fn formats_explicit_uid_flags_without_implicit_current_uid() {
        assert_eq!(format_allowed_uid_cli_args(&[]), "");
        assert_eq!(format_allowed_uid_cli_args(&[1000]), " --allowed-uid 1000");
        assert_eq!(
            format_allowed_uid_cli_args(&[1000, 1001]),
            " --allowed-uid 1000 --allowed-uid 1001"
        );
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
