//! Broker install / uninstall / status state (OS service unit templates + local marker).

use ownmesh_broker_client::{
    broker_endpoint_display, default_broker_endpoint, BrokerEndpoint, TransportKind,
};
use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

const INSTALL_FILE: &str = "broker-install.json";

/// Persisted install record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallRecord {
    pub installed: bool,
    pub installed_at_unix: i64,
    pub endpoint: String,
    pub endpoint_kind: String,
    pub unit_path: Option<String>,
    pub secret_file: String,
    pub notes: Vec<String>,
}

/// Status snapshot for CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallStatus {
    pub installed: bool,
    pub network: &'static str,
    pub endpoint: Option<String>,
    pub endpoint_kind: String,
    pub secret_present: bool,
    pub unit_path: Option<String>,
    pub notes: Vec<String>,
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

/// Restrict secret file mode to owner read/write only (Unix). Failure must fail install.
#[cfg(unix)]
fn apply_secret_permissions(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| {
        format!(
            "failed to set broker secret permissions (0o600) on {}: {e}",
            path.display()
        )
    })
}

/// Write a newly generated secret and apply restrictive permissions. Permission
/// failures propagate and abort install (never discarded).
fn write_new_secret_file(secret_file: &Path) -> Result<(), String> {
    write_new_secret_file_with(secret_file, |path| {
        // POSIX mode bits only exist on Unix; non-Unix relies on OS ACLs.
        #[cfg(unix)]
        apply_secret_permissions(path)?;
        #[cfg(not(unix))]
        let _ = path;
        Ok(())
    })
}

fn write_new_secret_file_with(
    secret_file: &Path,
    apply_permissions: impl FnOnce(&Path) -> Result<(), String>,
) -> Result<(), String> {
    let secret = ownmesh_broker_client::BrokerSecret::generate();
    std::fs::write(secret_file, secret.as_bytes()).map_err(|e| e.to_string())?;
    if let Err(permission_error) = apply_permissions(secret_file) {
        // Do not leave a newly generated secret behind with unverified permissions.
        return match std::fs::remove_file(secret_file) {
            Ok(()) => Err(permission_error),
            Err(cleanup_error) => Err(format!(
                "{permission_error}; additionally failed to remove insecure secret {}: {cleanup_error}",
                secret_file.display()
            )),
        };
    }
    Ok(())
}

/// Remove a path for template cleanup. Missing files are success; other IO errors are reported.
fn remove_template_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("remove {}: {e}", path.display())),
    }
}

fn push_cleanup_error(errors: &mut Vec<String>, result: Result<(), String>) {
    if let Err(e) = result {
        errors.push(e);
    }
}

fn format_uninstall_error(cleanup_errors: &[String]) -> String {
    let mut msg = String::from(
        "broker service uninstall is unsupported: template cleanup completed, but native service absence cannot be verified",
    );
    if !cleanup_errors.is_empty() {
        msg.push_str("; cleanup errors: ");
        msg.push_str(&cleanup_errors.join("; "));
    }
    msg
}

/// Install broker metadata + OS unit/service template under `base` (state dir).
pub fn install_broker(
    base: &Path,
    endpoint_override: Option<BrokerEndpoint>,
) -> Result<InstallRecord, String> {
    let dir = broker_dir(base);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let runtime = base.join("runtime");
    std::fs::create_dir_all(&runtime).map_err(|e| e.to_string())?;
    let endpoint = endpoint_override.unwrap_or_else(|| default_broker_endpoint(&runtime));
    let secret_file = dir.join("broker.secret");
    if !secret_file.exists() {
        write_new_secret_file(&secret_file)?;
    }

    let mut notes = vec![
        "broker is networkless (no non-loopback listen)".into(),
        "elevated requests require MAC + nonce + expiry + caller allow-list".into(),
    ];
    let unit_path = write_unit_template(&dir, &endpoint, &secret_file, &mut notes)?;

    notes.push(
        "service template prepared, but native service activation and verification are unsupported"
            .into(),
    );
    let rec = InstallRecord {
        installed: false,
        installed_at_unix: crate::now_unix(),
        endpoint: broker_endpoint_display(&endpoint),
        endpoint_kind: kind_name(endpoint.kind()).into(),
        unit_path: unit_path.map(|p| p.display().to_string()),
        secret_file: secret_file.display().to_string(),
        notes,
    };
    let raw = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?;
    std::fs::write(install_path(base), raw).map_err(|e| e.to_string())?;
    Err("broker service installation is unsupported: a template was prepared, but no native service was activated or verified".into())
}

/// Remove install marker and unit templates (does not kill a running broker).
///
/// Missing template files are tolerated. Other cleanup IO errors are aggregated into the
/// returned error message (never silently discarded).
pub fn uninstall_broker(base: &Path) -> Result<(), String> {
    let dir = broker_dir(base);
    let mut cleanup_errors: Vec<String> = Vec::new();

    push_cleanup_error(
        &mut cleanup_errors,
        remove_template_file(&install_path(base)),
    );
    for name in [
        "ownmesh-broker.service",
        "com.ownmesh.broker.plist",
        "ownmesh-broker-service.xml",
        "README-INSTALL.txt",
    ] {
        push_cleanup_error(&mut cleanup_errors, remove_template_file(&dir.join(name)));
    }

    // Keep secret unless explicitly purged; write an uninstalled marker.
    let rec = InstallRecord {
        installed: false,
        installed_at_unix: crate::now_unix(),
        endpoint: String::new(),
        endpoint_kind: String::new(),
        unit_path: None,
        secret_file: dir.join("broker.secret").display().to_string(),
        notes: vec!["uninstalled".into()],
    };

    match std::fs::create_dir_all(&dir) {
        Ok(()) => {
            let raw = serde_json::to_string_pretty(&rec).map_err(|e| e.to_string())?;
            let marker = install_path(base);
            if let Err(e) = std::fs::write(&marker, raw) {
                cleanup_errors.push(format!("write install marker {}: {e}", marker.display()));
            }
        }
        Err(e) => {
            cleanup_errors.push(format!("create_dir_all {}: {e}", dir.display()));
        }
    }

    Err(format_uninstall_error(&cleanup_errors))
}

/// Read install status.
pub fn broker_status(base: &Path) -> Result<InstallStatus, String> {
    let path = install_path(base);
    if !path.exists() {
        return Ok(InstallStatus {
            installed: false,
            network: "disabled",
            endpoint: None,
            endpoint_kind: String::new(),
            secret_present: broker_dir(base).join("broker.secret").exists(),
            unit_path: None,
            notes: vec!["not installed".into()],
        });
    }
    let raw = std::fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let rec: InstallRecord = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let mut notes = rec.notes;
    if rec.installed {
        notes.push(
            "legacy marker claimed installation, but native service state is unverified; reporting not installed"
                .into(),
        );
    }
    Ok(InstallStatus {
        // A metadata marker or unit template is not proof of an active OS service.
        installed: false,
        network: "disabled",
        endpoint: if rec.endpoint.is_empty() {
            None
        } else {
            Some(rec.endpoint)
        },
        endpoint_kind: rec.endpoint_kind,
        secret_present: PathBuf::from(&rec.secret_file).exists()
            || broker_dir(base).join("broker.secret").exists(),
        unit_path: rec.unit_path,
        notes,
    })
}

fn write_unit_template(
    dir: &Path,
    endpoint: &BrokerEndpoint,
    secret_file: &Path,
    notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
    write_platform_unit_template(dir, endpoint, secret_file, notes)
}

#[cfg(windows)]
fn write_platform_unit_template(
    dir: &Path,
    endpoint: &BrokerEndpoint,
    secret_file: &Path,
    notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
    let xml = dir.join("ownmesh-broker-service.xml");
    let pipe = match endpoint {
        BrokerEndpoint::NamedPipe(n) => n.clone(),
        other => broker_endpoint_display(other),
    };
    let body = format!(
        r#"<!-- OwnMesh privileged broker Windows Service template
  Named Pipe ACL: CreateNamedPipe security descriptor controls access.
  Docs: https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
  Default SD: LocalSystem, Administrators, creator owner (full); tighten to registered user + ownmeshd.
-->
<service>
  <id>ownmesh-broker</id>
  <name>OwnMesh Privileged Broker</name>
  <description>Networkless elevated command broker</description>
  <executable>ownmesh-broker.exe</executable>
  <arguments>run --endpoint pipe:{pipe} --secret-file "{secret}" --allow-callers ownmeshd</arguments>
</service>
"#,
        secret = secret_file.display()
    );
    std::fs::write(&xml, body).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("README-INSTALL.txt"),
        "Install (elevated):\n  sc.exe create ownmesh-broker binPath= \"...\\ownmesh-broker.exe run ...\"\n  Or use the generated ownmesh-broker-service.xml with your service wrapper.\n",
    )
    .map_err(|e| e.to_string())?;
    notes.push("Windows Service template written (Named Pipe ACL)".into());
    Ok(Some(xml))
}

#[cfg(target_os = "macos")]
fn write_platform_unit_template(
    dir: &Path,
    endpoint: &BrokerEndpoint,
    secret_file: &Path,
    notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
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
    <string>--allow-callers</string><string>ownmeshd</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
"#,
        secret = secret_file.display()
    );
    std::fs::write(&plist, body).map_err(|e| e.to_string())?;
    notes.push("macOS LaunchDaemon plist written".into());
    Ok(Some(plist))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn write_platform_unit_template(
    dir: &Path,
    endpoint: &BrokerEndpoint,
    secret_file: &Path,
    notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
    let unit = dir.join("ownmesh-broker.service");
    let sock = match endpoint {
        BrokerEndpoint::UnixSocket(p) => p.display().to_string(),
        other => broker_endpoint_display(other),
    };
    let body = format!(
        r#"[Unit]
Description=OwnMesh networkless privileged broker
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ownmesh-broker run --endpoint unix:{sock} --secret-file {secret} --allow-callers ownmeshd
Restart=on-failure
# Hardening (systemd)
NoNewPrivileges=false
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
# Socket is root-owned mode 0600; peer checked via SO_PEERCRED (Linux socket(7))

[Install]
WantedBy=multi-user.target
"#,
        secret = secret_file.display()
    );
    std::fs::write(&unit, body).map_err(|e| e.to_string())?;
    notes.push("Linux systemd unit written (SO_PEERCRED on accept)".into());
    Ok(Some(unit))
}

#[cfg(not(any(windows, unix)))]
fn write_platform_unit_template(
    _dir: &Path,
    _endpoint: &BrokerEndpoint,
    _secret_file: &Path,
    _notes: &mut Vec<String>,
) -> Result<Option<PathBuf>, String> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn uninstall_tolerates_missing_templates_without_cleanup_errors() {
        let dir = tempdir().unwrap();
        let err = uninstall_broker(dir.path()).unwrap_err();
        assert!(
            err.contains("native service absence cannot be verified"),
            "{err}"
        );
        assert!(
            !err.contains("cleanup errors:"),
            "missing files must not be reported as cleanup errors: {err}"
        );
        // Marker written as uninstalled.
        assert!(install_path(dir.path()).exists());
    }

    #[test]
    fn uninstall_aggregates_cleanup_io_errors() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let broker = broker_dir(base);
        fs::create_dir_all(&broker).unwrap();

        // remove_file fails with an IO error (not NotFound) when the path is a directory.
        let blocking = broker.join("ownmesh-broker.service");
        fs::create_dir_all(&blocking).unwrap();
        fs::write(blocking.join("keep"), b"x").unwrap();

        let blocking_plist = broker.join("com.ownmesh.broker.plist");
        fs::create_dir_all(&blocking_plist).unwrap();
        fs::write(blocking_plist.join("keep"), b"y").unwrap();

        let err = uninstall_broker(base).unwrap_err();
        assert!(
            err.contains("native service absence cannot be verified"),
            "{err}"
        );
        assert!(err.contains("cleanup errors:"), "{err}");
        assert!(err.contains("ownmesh-broker.service"), "{err}");
        assert!(err.contains("com.ownmesh.broker.plist"), "{err}");
    }

    #[test]
    fn write_new_secret_propagates_permission_errors() {
        let dir = tempdir().unwrap();
        // A missing parent makes the write fail, and that failure must surface.
        let missing_parent = dir.path().join("nope").join("broker.secret");
        let err = write_new_secret_file(&missing_parent).unwrap_err();
        assert!(!err.is_empty(), "{err}");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            // chmod helper must surface failures (install uses `?` via write_new_secret_file).
            let missing = Path::new("/no/such/ownmesh/broker.secret");
            let err = apply_secret_permissions(missing).unwrap_err();
            assert!(err.contains("0o600"), "{err}");
            assert!(err.contains("broker secret permissions"), "{err}");

            // Happy-path: secret is 0o600, install still fail-closes on native verification.
            let base = tempdir().unwrap();
            let install_err = install_broker(base.path(), None).unwrap_err();
            assert!(
                install_err.contains("no native service was activated or verified"),
                "{install_err}"
            );
            let secret = broker_dir(base.path()).join("broker.secret");
            assert!(secret.is_file());
            let mode = fs::metadata(&secret).unwrap().permissions().mode();
            assert_eq!(
                mode & 0o777,
                0o600,
                "secret mode must be 0o600, got {mode:#o}"
            );
        }
    }

    #[test]
    fn write_new_secret_propagates_chmod_failure_and_removes_secret() {
        let dir = tempdir().unwrap();
        let secret = dir.path().join("broker.secret");
        let err = write_new_secret_file_with(&secret, |_| Err("chmod denied".into())).unwrap_err();
        assert!(err.contains("chmod denied"), "{err}");
        assert!(
            !secret.exists(),
            "a secret with unverified permissions must be removed"
        );
    }

    #[test]
    fn format_uninstall_error_includes_aggregated_cleanup() {
        let msg = format_uninstall_error(&[
            "remove a: access denied".into(),
            "remove b: is a directory".into(),
        ]);
        assert!(
            msg.contains("native service absence cannot be verified"),
            "{msg}"
        );
        assert!(msg.contains("cleanup errors:"), "{msg}");
        assert!(msg.contains("remove a: access denied"), "{msg}");
        assert!(msg.contains("remove b: is a directory"), "{msg}");
    }
}
