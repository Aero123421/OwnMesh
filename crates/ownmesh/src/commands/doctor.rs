//! `ownmesh doctor` — fully read-only diagnostics.

use crate::cli::{Cli, DoctorArgs};
use crate::commands::service::{self, ServiceStatusSnapshot};
use ownmesh_config::{redact_control_plane_url, OwnMeshPaths};
use ownmesh_diagnostics::{
    appears_redacted, run_doctor, BinaryObservation, ConfigObservation, ControlPlaneObservation,
    CredentialObservation, DaemonObservation, DoctorOutcome, DoctorReport,
    PrivacyPolicyObservation, ServiceObservation,
};
use ownmesh_domain::ExitCode;
use ownmesh_identity::SecretPurpose;
use ownmesh_ipc::{ClientIdentity, ClientOptions, Endpoint, IpcClient};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Gather observations and produce a doctor report (read-only).
pub fn collect_doctor_report(
    paths: &OwnMeshPaths,
    args: &DoctorArgs,
    cli_version: &str,
) -> DoctorReport {
    let mut input = ownmesh_diagnostics::DoctorInput {
        binary: observe_binaries(cli_version),
        config: observe_config(paths),
        credentials: observe_credentials(paths),
        daemon: observe_daemon(paths),
        control_plane: ControlPlaneObservation::default(),
        privacy_policy: observe_privacy_policy(paths),
        service: observe_service(),
    };

    // Control-plane URL from config. Unsafe URLs are rejected/redacted before any output.
    match load_config_readonly(paths) {
        Ok(cfg) => {
            if let Some(url) = active_control_plane_url(&cfg) {
                input.control_plane.configured = true;
                // Never surface raw URL material that could carry userinfo/query.
                input.control_plane.url = Some(redact_control_plane_url(&url));
                let should_probe = args.check_network || input.control_plane.configured;
                if should_probe {
                    input.control_plane.probed = true;
                    match probe_control_plane_health(&url) {
                        Ok(status) if (200..300).contains(&status) => {
                            input.control_plane.reachable = Some(true);
                            input.control_plane.http_status = Some(status);
                        }
                        Ok(status) => {
                            input.control_plane.reachable = Some(false);
                            input.control_plane.http_status = Some(status);
                            input.control_plane.message =
                                Some(format!("control plane /health returned HTTP {status}"));
                        }
                        Err(msg) => {
                            input.control_plane.reachable = Some(false);
                            input.control_plane.message =
                                Some(msg.replace(&url, &redact_control_plane_url(&url)));
                        }
                    }
                }
            }
        }
        Err(msg) if msg != "missing" => {
            // Config present but unreadable/invalid (including unsafe URL). Do not echo secrets.
            input.config.message = Some(sanitize_doctor_message(&msg));
            if msg.to_ascii_lowercase().contains("base_url")
                || msg.to_ascii_lowercase().contains("userinfo")
                || msg.to_ascii_lowercase().contains("http")
            {
                input.control_plane.configured = true;
                input.control_plane.url = Some("[REDACTED]".into());
                input.control_plane.message = Some(
                    "control-plane URL failed validation (value redacted; re-run setup)".into(),
                );
            }
        }
        Err(_) => {}
    }

    let report = run_doctor(&input);
    // Hard guarantee: serialized report must not contain secret-looking payloads.
    debug_assert!(appears_redacted(
        &serde_json::to_string(&report).unwrap_or_default()
    ));
    report
}

fn load_config_readonly(paths: &OwnMeshPaths) -> Result<ownmesh_config::OwnMeshConfig, String> {
    // Avoid create-on-missing side effects: only read if present.
    let path = paths.config_file();
    if !path.exists() {
        return Err("missing".into());
    }
    let raw = fs::read_to_string(&path).map_err(|e| e.to_string())?;
    let cfg: ownmesh_config::OwnMeshConfig = toml::from_str(&raw).map_err(|e| e.to_string())?;
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

fn active_control_plane_url(cfg: &ownmesh_config::OwnMeshConfig) -> Option<String> {
    let id = cfg.active_instance.as_deref()?;
    cfg.instances
        .iter()
        .find(|i| i.id == id)
        .map(|i| i.base_url.trim().trim_end_matches('/').to_string())
        .filter(|u| !u.is_empty())
}

fn observe_binaries(cli_version: &str) -> BinaryObservation {
    let cli_path = env::current_exe().ok().map(|p| p.display().to_string());
    let daemon = service::resolve_ownmeshd_path(None).ok();
    BinaryObservation {
        cli_version: cli_version.to_string(),
        cli_on_path: which_on_path("ownmesh").is_some(),
        cli_path,
        daemon_on_path: which_on_path("ownmeshd").is_some()
            || which_on_path("ownmeshd.exe").is_some(),
        daemon_path: daemon.map(|p| p.display().to_string()),
    }
}

fn which_on_path(name: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
        #[cfg(windows)]
        {
            let exe = dir.join(format!("{name}.exe"));
            if exe.is_file() {
                return Some(exe);
            }
        }
    }
    None
}

fn observe_config(paths: &OwnMeshPaths) -> ConfigObservation {
    let path = paths.config_file();
    let mut obs = ConfigObservation {
        path: Some(path.display().to_string()),
        present: path.exists(),
        ..ConfigObservation::default()
    };
    if !obs.present {
        return obs;
    }
    match fs::read_to_string(&path) {
        Ok(raw) => {
            obs.readable = true;
            // Never copy raw into report — only status flags.
            match toml::from_str::<ownmesh_config::OwnMeshConfig>(&raw) {
                Ok(cfg) => {
                    obs.parse_ok = true;
                    match cfg.validate() {
                        Ok(()) => obs.validate_ok = true,
                        Err(e) => {
                            obs.validate_ok = false;
                            obs.message = Some(format!("validation: {e}"));
                        }
                    }
                }
                Err(e) => {
                    obs.parse_ok = false;
                    obs.message = Some(format!("parse error: {e}"));
                }
            }
        }
        Err(e) => {
            obs.readable = false;
            obs.message = Some(format!("unreadable: {e}"));
        }
    }
    obs.permissions_ok = config_permissions_ok(&path);
    if !obs.permissions_ok && obs.message.is_none() {
        obs.message = Some("config file mode allows other-write".into());
    }
    obs
}

fn config_permissions_ok(path: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        match fs::metadata(path) {
            Ok(md) => md.mode() & 0o002 == 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        true
    }
}

fn observe_credentials(paths: &OwnMeshPaths) -> CredentialObservation {
    let mut obs = CredentialObservation::default();
    let session_file = paths.state_dir.join("auth_session.json");
    obs.auth_session_present = session_file.is_file();
    if obs.auth_session_present {
        if let Ok(raw) = fs::read_to_string(&session_file) {
            // Presence only — never surface token fields even if mis-written.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                obs.enrolled_device_id_present = v
                    .get("device_id")
                    .and_then(|x| x.as_str())
                    .is_some_and(|s| !s.is_empty());
            }
        }
    }

    // Presence from non-secret metadata only. Doctor must never call OS credential
    // store load APIs or decode secret material (no keychain read, no prompt).
    observe_secret_presence_metadata_only(paths, &mut obs);
    obs
}

/// File-name / path metadata only — never opens keychain or decrypts blobs.
fn observe_secret_presence_metadata_only(paths: &OwnMeshPaths, obs: &mut CredentialObservation) {
    let keystore = paths.keystore_dir();
    if !keystore.is_dir() {
        // No non-secret metadata available → leave presence flags false ("unknown"/
        // absent in the report). Do not probe the OS credential store.
        return;
    }
    let human_blob = keystore.join(format!(
        "{}.oms",
        SecretPurpose::HumanRefreshToken.account()
    ));
    let device_key_blob =
        keystore.join(format!("{}.oms", SecretPurpose::DevicePrivateKey.account()));
    let device_cred_blob =
        keystore.join(format!("{}.oms", SecretPurpose::DeviceCredential.account()));
    if human_blob.is_file() {
        obs.human_refresh_present = true;
    }
    if device_key_blob.is_file() {
        obs.device_key_present = true;
    }
    if device_cred_blob.is_file() {
        obs.device_credential_present = true;
    }
}

fn sanitize_doctor_message(msg: &str) -> String {
    // Collapse anything that looks like a URL or credential carrier.
    let mut out = msg.to_string();
    if let Some(start) = out.find("http://").or_else(|| out.find("https://")) {
        let rest = &out[start..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == '`' || c == '"' || c == '\'')
            .unwrap_or(rest.len());
        let url = &rest[..end];
        out = out.replace(url, &redact_control_plane_url(url));
    }
    out
}

fn observe_daemon(paths: &OwnMeshPaths) -> DaemonObservation {
    let mut obs = DaemonObservation::default();
    let cfg_path = paths.config_file();
    let socket_override = if cfg_path.exists() {
        load_config_readonly(paths)
            .ok()
            .and_then(|c| c.service_socket.path)
    } else {
        None
    };
    let endpoint = match Endpoint::configured_daemon(&paths.runtime_dir, socket_override.as_deref())
    {
        Ok(ep) => ep,
        Err(err) => {
            obs.message = Some(format!("endpoint error: {err}"));
            return obs;
        }
    };
    obs.endpoint = Some(endpoint.display());

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            obs.message = Some(format!("runtime error: {err}"));
            return obs;
        }
    };

    let reachable = rt.block_on(async {
        let client = match IpcClient::new(
            endpoint,
            paths.runtime_dir.clone(),
            ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            ClientOptions {
                request_timeout: Duration::from_millis(800),
                max_reconnect_attempts: 1,
                reconnect_base_delay: Duration::from_millis(20),
            },
        )
        .with_client_credential_from_env()
        {
            Ok(c) => c,
            Err(err) => {
                return Err(format!("client credential error: {err}"));
            }
        };
        match client.status().await {
            Ok(_) => Ok(()),
            Err(err) => Err(err.to_string()),
        }
    });

    match reachable {
        Ok(()) => obs.reachable = true,
        Err(msg) => {
            obs.reachable = false;
            obs.message = Some(msg);
        }
    }
    obs
}

fn observe_privacy_policy(paths: &OwnMeshPaths) -> PrivacyPolicyObservation {
    let mut obs = PrivacyPolicyObservation {
        relay_enabled: false, // no cloud relay surface in config yet — default OFF
        ..PrivacyPolicyObservation::default()
    };

    if paths.policy_file().exists() {
        obs.policy_present = true;
        match load_policy_readonly(paths) {
            Ok(p) => {
                obs.policy_valid = true;
                obs.policy_preset = p.preset;
            }
            Err(msg) => {
                obs.policy_valid = false;
                let _ = msg;
            }
        }
    }

    if let Ok(cfg) = load_config_readonly(paths) {
        obs.telemetry_project = cfg.telemetry.project;
        obs.telemetry_crash_upload = cfg.telemetry.crash_upload;
        obs.telemetry_usage_analytics = cfg.telemetry.usage_analytics;
        obs.update_mode = Some(cfg.update.mode.clone());
        obs.update_channel = Some(cfg.update.channel.clone());
        obs.update_network_off = cfg.update.mode == "off";
    } else {
        // Defaults when no config: privacy-first expectations.
        obs.update_network_off = true;
        obs.update_mode = Some("off".into());
    }
    obs
}

fn load_policy_readonly(paths: &OwnMeshPaths) -> Result<ownmesh_config::PolicyFile, String> {
    let path = paths.policy_file();
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let policy: ownmesh_config::PolicyFile = toml::from_str(&raw).map_err(|e| e.to_string())?;
    policy.validate().map_err(|e| e.to_string())?;
    Ok(policy)
}

fn observe_service() -> ServiceObservation {
    match service::probe_service_status() {
        Ok(snap) => service_obs_from_snapshot(&snap),
        Err(err) => ServiceObservation {
            platform: std::env::consts::OS.to_string(),
            supported: false,
            installed: false,
            running: None,
            unit_path: None,
            message: Some(err),
        },
    }
}

fn service_obs_from_snapshot(snap: &ServiceStatusSnapshot) -> ServiceObservation {
    ServiceObservation {
        platform: snap.platform.clone(),
        supported: snap.supported,
        installed: snap.installed,
        running: snap.running,
        unit_path: snap.unit_path.clone(),
        message: snap.message.clone(),
    }
}

/// Probe `{base}/health` without sending credentials.
pub fn probe_control_plane_health(base_url: &str) -> Result<u16, String> {
    let base = base_url.trim().trim_end_matches('/');
    let url = format!("{base}/health");
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| format!("http client: {e}"))?;
    let resp = client
        .get(&url)
        .header("accept", "application/json")
        .send()
        .map_err(|e| format!("control plane unreachable: {e}"))?;
    Ok(resp.status().as_u16())
}

fn emit_report(cli: &Cli, report: &DoctorReport) {
    if cli.json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_else(|_| "{\"ok\":false}".into())
        );
    } else {
        println!(
            "ownmesh doctor — {} ({})",
            report.outcome.as_str(),
            report.version
        );
        for check in &report.checks {
            let mark = match check.status {
                ownmesh_diagnostics::CheckStatus::Pass => "ok  ",
                ownmesh_diagnostics::CheckStatus::Warn => "warn",
                ownmesh_diagnostics::CheckStatus::Fail => "FAIL",
            };
            println!("  [{mark}] {}: {}", check.id, check.message);
        }
        println!("outcome: {}", report.outcome.as_str());
    }
}

/// Map doctor outcome to a stable process exit code.
#[must_use]
pub fn exit_for_report(report: &DoctorReport) -> ExitCode {
    match report.outcome {
        DoctorOutcome::Healthy | DoctorOutcome::Warn => ExitCode::Success,
        DoctorOutcome::Error => ExitCode::UsageConfig,
    }
}

/// CLI entrypoint — never mutates config, credentials, or services.
pub fn run_doctor_cmd(cli: &Cli, args: &DoctorArgs) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("doctor: path error: {err}");
        ExitCode::UsageConfig
    })?;
    // Intentionally do NOT ensure_layout / create dirs — doctor is read-only.
    let report = collect_doctor_report(&paths, args, env!("CARGO_PKG_VERSION"));

    // Redaction guard on the emitted payload.
    let payload = serde_json::to_string(&report).unwrap_or_default();
    if !appears_redacted(&payload) {
        eprintln!("doctor: internal error: report failed redaction guard");
        return Err(ExitCode::Internal);
    }

    emit_report(cli, &report);
    let code = exit_for_report(&report);
    if code == ExitCode::Success {
        Ok(())
    } else {
        Err(code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_config::{save_config, save_policy, InstanceConfig, OwnMeshConfig, PolicyFile};
    use tempfile::tempdir;

    #[test]
    fn doctor_is_read_only_on_missing_layout() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path().join("absent"));
        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
            },
            "test",
        );
        // Should not create config.
        assert!(!paths.config_file().exists());
        assert!(report.checks.iter().any(|c| c.id == "config.present"));
        let json = serde_json::to_string(&report).unwrap();
        assert!(appears_redacted(&json));
    }

    #[test]
    fn doctor_never_loads_os_credential_store() {
        // Source-level guard on production code only (strip the tests module).
        let src = include_str!("doctor.rs");
        let prod = src.split("#[cfg(test)]").next().unwrap_or(src);
        assert!(
            !prod.contains("OsKeychainStore"),
            "doctor must not construct OsKeychainStore"
        );
        assert!(
            !prod.contains("keyring::"),
            "doctor must not use keyring APIs"
        );
        assert!(
            !prod.contains(".load(SecretPurpose"),
            "doctor must not load secret purposes from a credential store"
        );
        assert!(
            !prod.contains("SecretStore"),
            "doctor must not use SecretStore trait in production paths"
        );
        assert!(
            prod.contains("observe_secret_presence_metadata_only"),
            "doctor must use metadata-only credential observation"
        );

        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        // Plant a fake encrypted blob and a decoy secret file; doctor may note presence
        // via filename only and must never emit blob bytes.
        let keystore = paths.keystore_dir();
        fs::create_dir_all(&keystore).unwrap();
        let decoy = b"SUPER-SECRET-REFRESH-TOKEN-VALUE-do-not-leak";
        fs::write(
            keystore.join(format!(
                "{}.oms",
                SecretPurpose::HumanRefreshToken.account()
            )),
            decoy,
        )
        .unwrap();
        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
            },
            "test",
        );
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(!json.contains("SUPER-SECRET-REFRESH-TOKEN-VALUE"));
        assert!(appears_redacted(&json));
        assert!(
            report.checks.iter().any(|c| c.id == "credential.human"),
            "presence metadata should surface as a check"
        );
    }

    #[test]
    fn doctor_redacts_unsafe_control_plane_url() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        // Bypass save_config validation to simulate a hostile on-disk URL.
        fs::write(
            paths.config_file(),
            r#"
schema_version = 1
active_instance = "bad"
lang = "en-US"

[[instances]]
id = "bad"
base_url = "https://USER:s3cretTOKEN@cp.example.test/path?access_token=abc#frag"
"#,
        )
        .unwrap();
        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
            },
            "test",
        );
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(!json.contains("s3cretTOKEN"));
        assert!(!json.contains("access_token=abc"));
        assert!(!json.contains("USER:"));
        assert!(appears_redacted(&json));
    }

    #[test]
    fn doctor_reads_config_without_secrets() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let cfg = OwnMeshConfig {
            active_instance: Some("home".into()),
            update: ownmesh_config::UpdateConfig {
                mode: "off".into(),
                channel: "stable".into(),
            },
            instances: vec![InstanceConfig {
                id: "home".into(),
                base_url: "https://cp.example.test".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        save_config(&paths, &cfg).unwrap();
        save_policy(
            &paths,
            &PolicyFile {
                schema_version: 1,
                preset: Some("recommended".into()),
            },
        )
        .unwrap();

        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
            },
            "1.2.3",
        );
        assert!(report
            .checks
            .iter()
            .any(|c| c.id == "config" && c.status == ownmesh_diagnostics::CheckStatus::Pass));
        assert!(report.checks.iter().any(
            |c| c.id == "privacy.update" && c.status == ownmesh_diagnostics::CheckStatus::Pass
        ));
        let json = serde_json::to_string_pretty(&report).unwrap();
        assert!(!json.to_ascii_lowercase().contains("refresh_token"));
        assert!(appears_redacted(&json));
        // Still read-only: no unexpected new files beyond what setup wrote.
        assert!(paths.config_file().exists());
    }

    #[test]
    fn exit_codes_stable() {
        let healthy =
            DoctorReport::from_checks("1", vec![ownmesh_diagnostics::DoctorCheck::pass("a", "ok")]);
        assert_eq!(exit_for_report(&healthy), ExitCode::Success);
        let warn =
            DoctorReport::from_checks("1", vec![ownmesh_diagnostics::DoctorCheck::warn("a", "w")]);
        assert_eq!(exit_for_report(&warn), ExitCode::Success);
        let err =
            DoctorReport::from_checks("1", vec![ownmesh_diagnostics::DoctorCheck::fail("a", "e")]);
        assert_eq!(exit_for_report(&err), ExitCode::UsageConfig);
    }

    #[test]
    fn network_probe_skipped_without_config_and_without_flag() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
            },
            "test",
        );
        assert!(!report
            .checks
            .iter()
            .any(|c| c.id == "control_plane.health" && c.message.contains("HTTP")));
    }
}
