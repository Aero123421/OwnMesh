//! `ownmesh doctor` — diagnostics. Inspection is read-only; `--repair-journal`
//! is an explicit local mutation that requires `--i-understand-replay-risk`.

use crate::cli::{Cli, DoctorArgs};
use crate::commands::service::{self, ServiceStatusSnapshot};
use ownmesh_config::{redact_control_plane_url, OwnMeshPaths};
use ownmesh_diagnostics::{
    appears_redacted, run_doctor, BinaryObservation, ConfigObservation, ControlPlaneObservation,
    CredentialObservation, CredentialState, CredentialStoreObservation, DaemonObservation,
    DoctorOutcome, DoctorReport, PrivacyPolicyObservation, ServiceObservation,
};
use ownmesh_domain::ExitCode;
use ownmesh_identity::{
    CredentialStoreDiagnosticSnapshot, SecretPurpose, CREDENTIAL_STORE_DIAGNOSTIC_FILE,
};
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
    let daemon = observe_daemon(paths);
    let mut service = observe_service();
    merge_daemon_service_status(&daemon, &mut service);
    let mut input = ownmesh_diagnostics::DoctorInput {
        binary: observe_binaries(cli_version),
        config: observe_config(paths),
        credentials: observe_credentials(paths),
        credential_store: observe_credential_store(paths),
        daemon,
        control_plane: ControlPlaneObservation::default(),
        privacy_policy: observe_privacy_policy(paths),
        service,
        journals: observe_journals(paths),
        profile_discovery: observe_profile_discovery(),
    };

    // Control-plane URL from config. Unsafe URLs are rejected/redacted before any output.
    match load_config_readonly(paths) {
        Ok(cfg) => {
            if let Some(url) = active_control_plane_url(&cfg) {
                input.control_plane.configured = true;
                // Never surface raw URL material that could carry userinfo/query.
                input.control_plane.url = Some(redact_control_plane_url(&url));
                // Opt-in only. This used to read `args.check_network ||
                // input.control_plane.configured`, and `configured` had just
                // been set to `true` on the line above — so the condition was
                // a tautology, `--check-network` changed nothing, and any
                // machine with a configured control plane made a network call
                // on every `doctor` run.
                if args.check_network && !args.offline {
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
    // Recover interrupted setup transactions before observing the live pair.
    // Fail closed if recovery cannot complete (journal preserved).
    ownmesh_config::ensure_config_policy_consistent(paths).map_err(|e| e.to_string())?;
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
        obs.device_key_state = CredentialState::NotRequiredForCurrentMode;
        obs.device_credential_state = CredentialState::NotRequiredForCurrentMode;
        if let Ok(raw) = fs::read_to_string(&session_file) {
            // Presence only — never surface token fields even if mis-written.
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&raw) {
                obs.human_refresh_state = match v
                    .get("has_refresh_token")
                    .and_then(serde_json::Value::as_bool)
                {
                    // `auth_session.json` is deliberately non-secret metadata;
                    // this marker is written only after a successful secret-store
                    // save. It establishes presence without loading the value.
                    Some(true) => CredentialState::Present,
                    Some(false) => CredentialState::Missing,
                    // Older metadata did not carry the marker. Do not turn its
                    // absence into a false claim about an OS-keychain secret.
                    None => CredentialState::Unknown,
                };
                obs.enrolled_device_id_present = v
                    .get("device_id")
                    .and_then(|x| x.as_str())
                    .is_some_and(|s| !s.is_empty());
                if obs.enrolled_device_id_present {
                    // An enrolled device can store material in the OS keychain.
                    // File metadata alone cannot prove that it is missing.
                    obs.device_key_state = CredentialState::Unknown;
                    obs.device_credential_state = CredentialState::Unknown;
                }
            } else {
                obs.human_refresh_state = CredentialState::Unknown;
                obs.device_key_state = CredentialState::Unknown;
                obs.device_credential_state = CredentialState::Unknown;
            }
        } else {
            obs.human_refresh_state = CredentialState::Unknown;
            obs.device_key_state = CredentialState::Unknown;
            obs.device_credential_state = CredentialState::Unknown;
        }
    } else {
        obs.human_refresh_state = CredentialState::NotRequiredForCurrentMode;
        obs.device_key_state = CredentialState::NotRequiredForCurrentMode;
        obs.device_credential_state = CredentialState::NotRequiredForCurrentMode;
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
        obs.human_refresh_state = CredentialState::Present;
    }
    if device_key_blob.is_file() {
        obs.device_key_present = true;
        obs.device_key_state = CredentialState::Present;
    }
    if device_cred_blob.is_file() {
        obs.device_credential_present = true;
        obs.device_credential_state = CredentialState::Present;
    }
}

fn observe_credential_store(paths: &OwnMeshPaths) -> CredentialStoreObservation {
    let path = paths.keystore_dir().join(CREDENTIAL_STORE_DIAGNOSTIC_FILE);
    if !path.is_file() {
        return CredentialStoreObservation::default();
    }
    let metadata = match fs::metadata(&path) {
        Ok(metadata) if metadata.len() <= 16 * 1024 => metadata,
        Ok(_) => {
            return CredentialStoreObservation {
                metadata_present: true,
                read_error: Some("credential-store provenance metadata exceeds size limit".into()),
                ..CredentialStoreObservation::default()
            };
        }
        Err(_) => {
            return CredentialStoreObservation {
                metadata_present: true,
                read_error: Some(
                    "credential-store provenance metadata could not be inspected".into(),
                ),
                ..CredentialStoreObservation::default()
            };
        }
    };
    let _ = metadata;
    match fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<CredentialStoreDiagnosticSnapshot>(&bytes).ok())
    {
        Some(snapshot) if snapshot.schema_version == 1 => CredentialStoreObservation {
            metadata_present: true,
            backend_name: Some(snapshot.backend_name),
            fallback_policy: Some(snapshot.fallback_policy),
            degraded: snapshot.degraded || snapshot.cleanup_degraded,
            residual_fallback_entries: snapshot.residual_fallback_entries,
            read_error: None,
        },
        _ => CredentialStoreObservation {
            metadata_present: true,
            read_error: Some("credential-store provenance metadata is invalid".into()),
            ..CredentialStoreObservation::default()
        },
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

fn repair_op_journal_files(paths: &OwnMeshPaths) -> Result<String, String> {
    let primary = paths.state_dir.join("op-journal.json");
    let bak = paths.state_dir.join("op-journal.json.bak");
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let archive = |src: &Path, kind: &str| -> Result<PathBuf, String> {
        for n in 0..32 {
            let dest = paths.state_dir.join(if n == 0 {
                format!("op-journal.json.{kind}-{stamp}")
            } else {
                format!("op-journal.json.{kind}-{stamp}-{n}")
            });
            if dest.exists() {
                continue;
            }
            fs::rename(src, &dest)
                .map_err(|e| format!("failed to archive {}: {e}", src.display()))?;
            return Ok(dest);
        }
        Err(format!(
            "failed to archive {}: no unique name",
            src.display()
        ))
    };

    let mut archived = Vec::new();
    if primary.exists() {
        archived.push(archive(&primary, "corrupt")?);
    }
    if bak.exists() {
        match fs::read(&bak) {
            Ok(raw)
                if raw.len() <= 4 * 1024 * 1024
                    && serde_json::from_slice::<serde_json::Value>(&raw).is_ok() =>
            {
                fs::copy(&bak, &primary)
                    .map_err(|e| format!("failed to restore op-journal from backup: {e}"))?;
                let _ = fs::remove_file(&bak);
                return Ok(format!(
                    "restored op-journal.json from backup; archived unreadable primary as {}. Restart ownmeshd.",
                    archived
                        .first()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "(none)".into())
                ));
            }
            _ => {
                archived.push(archive(&bak, "corrupt-bak")?);
            }
        }
    }
    fs::write(&primary, b"{}").map_err(|e| format!("failed to write empty op-journal: {e}"))?;
    Ok(format!(
        "wrote an empty op-journal.json after archiving unreadable files ({}). In-flight keys may replay. Restart ownmeshd.",
        archived
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ))
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
        .with_client_credential_from_env_or_management_file(&paths.state_dir)
        {
            Ok(c) => c,
            Err(err) => {
                return Err(format!("client credential error: {err}"));
            }
        };
        match client.status().await {
            Ok(status) => Ok(status),
            Err(err) => Err(err.to_string()),
        }
    });

    match reachable {
        Ok(status) => {
            obs.reachable = true;
            obs.pid = (status.pid != 0).then_some(status.pid);
        }
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
    // Mandatory recovery before policy is observed or reported.
    ownmesh_config::ensure_config_policy_consistent(paths).map_err(|e| e.to_string())?;
    let path = paths.policy_file();
    if !path.exists() {
        return Err("missing".into());
    }
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let policy: ownmesh_config::PolicyFile = toml::from_str(&raw).map_err(|e| e.to_string())?;
    policy.validate().map_err(|e| e.to_string())?;
    Ok(policy)
}

/// Read-only observation of the daemon's durable journals (P0-A/P0-B): only
/// counts/sizes are surfaced, bounded reads, never entry content.
fn observe_journals(paths: &OwnMeshPaths) -> ownmesh_diagnostics::JournalsObservation {
    let mut obs = ownmesh_diagnostics::JournalsObservation::default();
    // Transition journal: bounded (256 KiB) read of the durable file.
    let transition_path = paths
        .state_dir
        .join("session-transitions")
        .join("session-transition-journal.json");
    if transition_path.exists() {
        match fs::read(&transition_path) {
            Ok(raw) if raw.len() <= 256 * 1024 => {
                // P1-F: run the *same* typed validation as the daemon's loader
                // (`ownmesh_transition_journal::parse_and_validate`): version,
                // entry cap, map-key/record-id agreement, unknown-field
                // rejection, invalid enum values, identifier shape, epoch/
                // expiry bounds, host-expiry coverage, binding invariants and
                // phase consistency. A journal the daemon would refuse to open
                // is never reported healthy by doctor.
                match ownmesh_transition_journal::parse_and_validate(&raw) {
                    Ok(parsed) => {
                        let entries = parsed.pending();
                        obs.transition_pending = entries.len();
                        let now = unix_now();
                        obs.transition_expired = entries
                            .iter()
                            .filter(|entry| entry.expires_unix <= now)
                            .count();
                    }
                    Err(message) => {
                        obs.transition_read_error = Some(format!(
                            "transition journal failed full validation: {message}"
                        ));
                    }
                }
            }
            Ok(_) => {
                obs.transition_read_error =
                    Some("transition journal exceeds 256 KiB budget".into());
            }
            Err(e) => obs.transition_read_error = Some(format!("read failed: {e}")),
        }
    }
    // Op journal: bounded (4 MiB) read of the durable file (compacted post-fix).
    let op_path = paths.state_dir.join("op-journal.json");
    if op_path.exists() {
        let meta = fs::metadata(&op_path);
        obs.op_journal_durable_bytes = meta.map(|m| m.len() as usize).unwrap_or(0);
        match fs::read(&op_path) {
            Ok(raw) if raw.len() <= 4 * 1024 * 1024 => {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&raw) {
                    if let Some(entries) = value.as_object() {
                        obs.op_journal_entries = entries.len();
                        // Mirror the runtime's fail-closed classifier
                        // (`op_journal_entry_state`): only an entry with an
                        // explicit positive completed marker (`durable_receipt:
                        // true` or `__ownmesh_operation_state == "completed"`,
                        // each carrying the exact-once `operation_id` (ADR
                        // 0010 §1b), or a legacy completed body with positive
                        // completion proof) counts as completed; the exact
                        // `in_progress` marker counts as in-progress; anything
                        // else (unknown/forward-version state, malformed state
                        // values such as null/number/boolean, a completed
                        // marker without an `operation_id`, an unmarked object
                        // like a truncated `{}`, or non-object entries) is
                        // uncertain and must never be reported healthy (P1-F).
                        for entry in entries.values() {
                            let object = entry.as_object();
                            let exact_once_id = object
                                .and_then(|o| o.get("operation_id"))
                                .and_then(serde_json::Value::as_str)
                                .is_some_and(|id| !id.is_empty());
                            match object.and_then(|o| o.get("__ownmesh_operation_state")) {
                                None => {
                                    let completed_receipt = object.is_some_and(|o| {
                                        o.get("durable_receipt")
                                            .and_then(serde_json::Value::as_bool)
                                            == Some(true)
                                            && exact_once_id
                                    }) || entry
                                        .get("operation_id")
                                        .and_then(serde_json::Value::as_str)
                                        .is_some_and(|id| !id.is_empty())
                                        && (entry
                                            .get("decision")
                                            .and_then(serde_json::Value::as_str)
                                            .is_some_and(|d| !d.is_empty())
                                            || entry
                                                .get("approval_required")
                                                .is_some_and(serde_json::Value::is_boolean)
                                            || entry
                                                .get("review_id")
                                                .and_then(serde_json::Value::as_str)
                                                .is_some_and(|id| !id.is_empty()));
                                    if !completed_receipt {
                                        obs.op_journal_uncertain += 1;
                                    }
                                }
                                Some(field) => {
                                    if field.as_str() == Some("in_progress") {
                                        obs.op_journal_in_progress += 1;
                                    } else if field.as_str() == Some("completed") && exact_once_id {
                                        // Explicit completed marker with the
                                        // exact-once operation_id: completed.
                                    } else {
                                        obs.op_journal_uncertain += 1;
                                    }
                                }
                            }
                        }
                    } else {
                        // Parseable but wrong-shaped JSON: the daemon's typed
                        // loader would reject this, so doctor must not report
                        // the journal as healthy (P1-F).
                        obs.op_journal_read_error = Some(
                            "op journal has unexpected structure (expected a JSON object)".into(),
                        );
                    }
                } else {
                    obs.op_journal_read_error = Some("op journal parse failed (corrupt)".into());
                }
            }
            Ok(_) => obs.op_journal_read_error = Some("op journal exceeds 4 MiB budget".into()),
            Err(e) => obs.op_journal_read_error = Some(format!("read failed: {e}")),
        }
    }
    // Stale `op-journal.json.bak` (P0-B): the shared atomic writer copies the
    // previous file to `path.bak` *before* replacing it, so a crash or a
    // failed cleanup after the replace can leave the pre-compaction journal
    // (possibly with full result bodies) behind. The daemon removes the
    // backup on the next load/persist; while it exists doctor must surface it
    // so the class is not reported healthy.
    let mut bak_path = op_path.as_os_str().to_os_string();
    bak_path.push(".bak");
    let bak_path = PathBuf::from(bak_path);
    if bak_path.exists() {
        obs.op_journal_backup_bytes = fs::metadata(&bak_path).map(|m| m.len() as usize).ok();
    }
    obs
}

/// Read-only official-profile discovery health (P1-D/P1-F): runs the official
/// registry against the deterministic search (system PATH + user-local dirs)
/// and compares it with the bare system PATH. Never spawns version probes —
/// observation must not run binaries as a side effect.
fn observe_profile_discovery() -> ownmesh_diagnostics::ProfileDiscoveryObservation {
    #[cfg(windows)]
    {
        // Windows user bins are already reachable through the inherited user
        // PATH; no separate user-local discovery step exists there.
        ownmesh_diagnostics::ProfileDiscoveryObservation::default()
    }

    #[cfg(not(windows))]
    {
        let mut obs = ownmesh_diagnostics::ProfileDiscoveryObservation::default();
        let Some(home) = env::var_os("HOME") else {
            // A missing HOME means the deterministic user-local search could not
            // be evaluated at all — that is a discovery-health issue, not a
            // healthy result (P1-F).
            obs.home_unavailable = true;
            return obs;
        };
        let system_dirs: Vec<PathBuf> = env::var_os("PATH")
            .map(|path| env::split_paths(&path).collect())
            .unwrap_or_default();
        let user_dirs = ownmesh_exec::user_cli_search_dirs(Some(home.as_ref()));
        let mut full_dirs = system_dirs.clone();
        for dir in &user_dirs {
            if !full_dirs.contains(dir) {
                full_dirs.push(dir.clone());
            }
        }
        // Existing user-local bin dirs that are absent from PATH.
        for dir in &user_dirs {
            if dir.is_dir() && !system_dirs.contains(dir) {
                obs.existing_dirs_not_searched
                    .push(dir.display().to_string());
            }
        }
        // Official profiles that resolve only through the full search.
        let registry = ownmesh_profiles::ProfileRegistry::with_official();
        for profile in registry.list() {
            let id = &profile.id;
            let via_system = registry
                .resolve_binary_in_dirs(id, &system_dirs)
                .ok()
                .flatten();
            let via_full = registry
                .resolve_binary_in_dirs(id, &full_dirs)
                .ok()
                .flatten();
            if via_full.is_some() && via_system.is_none() {
                obs.user_local_only.push(id.clone());
            }
        }
        obs
    }
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(0))
        .unwrap_or(0)
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
            hardening: None,
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
        hardening: snap.hardening.as_ref().map(|h| {
            ownmesh_diagnostics::ServiceHardeningObservation {
                no_new_privileges: h.no_new_privileges,
                umask_set: h.umask_set,
                restrict_suidsgid: h.restrict_suidsgid,
                restrict_realtime: h.restrict_realtime,
                lock_personality: h.lock_personality,
                system_call_architectures: h.system_call_architectures,
                restrict_namespaces: h.restrict_namespaces,
                capability_bounding_set: h.capability_bounding_set,
                user_namespace_forcing: h.user_namespace_forcing,
                read_only_hierarchy: h.read_only_hierarchy,
                private_users: h.private_users,
                protect_system_full: h.protect_system_full,
                private_tmp: h.private_tmp,
                protect_proc: h.protect_proc,
                protect_kernel_tunables: h.protect_kernel_tunables,
                protect_control_groups: h.protect_control_groups,
                protect_hostname: h.protect_hostname,
                read_write_paths_set: h.read_write_paths_set,
                start_breaking_directives: h.start_breaking_directives,
                masked: h.masked,
                summary: h.summary.clone(),
            }
        }),
    }
}

/// Merge only an authenticated daemon fact into an otherwise indeterminate OS
/// service probe. A reachable daemon does not prove that it belongs to a
/// particular service descriptor, so explicit `false` is never overwritten.
fn merge_daemon_service_status(daemon: &DaemonObservation, service: &mut ServiceObservation) {
    if daemon.reachable && daemon.pid.is_some() && service.installed && service.running.is_none() {
        service.running = Some(true);
        service.message = Some("run-state confirmed by authenticated daemon.status".into());
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
        let mut value = serde_json::to_value(report).unwrap_or_else(|_| {
            serde_json::json!({
                "schema_version": 1,
                "ok": false,
            })
        });
        if report.outcome == DoctorOutcome::Error {
            value["exit_code"] = serde_json::json!(ExitCode::UsageConfig.code());
            value["error"] = serde_json::json!({
                "code": crate::commands::fail::code_for(ExitCode::UsageConfig),
                "message": "one or more doctor checks failed",
            });
        }
        println!("{value}");
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

/// CLI entrypoint. Inspection does not mutate config, credentials, or services.
/// `--repair-journal` is the only mutating path and is local-only.
pub fn run_doctor_cmd(cli: &Cli, args: &DoctorArgs) -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("doctor: path error: {err}");
        ExitCode::UsageConfig
    })?;
    if args.repair_journal {
        if !args.i_understand_replay_risk {
            eprintln!(
                "doctor: --repair-journal requires --i-understand-replay-risk (discarding an unreadable journal accepts bounded replay risk)"
            );
            return Err(ExitCode::UsageConfig);
        }
        if observe_daemon(&paths).reachable {
            eprintln!(
                "doctor: stop ownmeshd before repairing the op-journal (local-only; no remote repair)"
            );
            return Err(ExitCode::Conflict);
        }
        match repair_op_journal_files(&paths) {
            Ok(message) => {
                if cli.json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": 1,
                            "ok": true,
                            "repair": "op_journal",
                            "message": message,
                        })
                    );
                    crate::commands::fail::note_envelope_emitted();
                } else {
                    println!("{message}");
                }
                return Ok(());
            }
            Err(err) => {
                eprintln!("doctor: {err}");
                return Err(ExitCode::Internal);
            }
        }
    }
    // Intentionally do NOT ensure_layout / create dirs — doctor is read-only.
    let report = collect_doctor_report(&paths, args, env!("CARGO_PKG_VERSION"));

    // Redaction guard on the emitted payload.
    let payload = serde_json::to_string(&report).unwrap_or_default();
    if !appears_redacted(&payload) {
        eprintln!("doctor: internal error: report failed redaction guard");
        return Err(ExitCode::Internal);
    }

    emit_report(cli, &report);
    if cli.json {
        crate::commands::fail::note_envelope_emitted();
    }
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
    use clap::Parser;
    use ownmesh_config::{save_config, save_policy, InstanceConfig, OwnMeshConfig, PolicyFile};
    use tempfile::tempdir;

    /// `--check-network` must be the only thing that reaches the network.
    ///
    /// The probe condition was `args.check_network || configured`, evaluated
    /// right after `configured` was set to `true`, so it was a tautology: the
    /// flag changed nothing and every configured machine probed on every run.
    #[test]
    fn network_probe_is_opt_in_and_offline_wins() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let cfg = OwnMeshConfig {
            active_instance: Some("home".into()),
            instances: vec![InstanceConfig {
                id: "home".into(),
                // Unroutable by RFC 6761, so a probe would have to be skipped
                // rather than merely fail fast.
                base_url: "https://cp.invalid".into(),
                display_name: None,
            }],
            ..OwnMeshConfig::default()
        };
        save_config(&paths, &cfg).unwrap();
        save_policy(&paths, &PolicyFile::default()).unwrap();

        let default_run = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        let health = default_run
            .checks
            .iter()
            .find(|c| c.id == "control_plane.health")
            .expect("health check row");
        assert_eq!(
            health.status,
            ownmesh_diagnostics::CheckStatus::Pass,
            "without --check-network the probe must be skipped: {health:?}"
        );
        assert!(health.message.contains("skipped"), "{health:?}");

        // --offline is a hard override for aliases that already pass the flag.
        let offline_run = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: true,
                offline: true,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        let offline_health = offline_run
            .checks
            .iter()
            .find(|c| c.id == "control_plane.health")
            .expect("health check row");
        assert!(
            offline_health.message.contains("skipped"),
            "{offline_health:?}"
        );
    }

    /// An explicitly requested network probe must be useful in automation.
    #[test]
    fn unreachable_control_plane_fails_an_explicit_probe() {
        let mut input = ownmesh_diagnostics::DoctorInput::default();
        input.binary.cli_version = "test".into();
        input.control_plane.configured = true;
        input.control_plane.probed = true;
        input.control_plane.reachable = Some(false);
        input.control_plane.message = Some("control plane unreachable".into());
        let report = ownmesh_diagnostics::run_doctor(&input);
        assert_eq!(report.outcome, DoctorOutcome::Error, "{report:?}");
        assert_eq!(exit_for_report(&report), ExitCode::UsageConfig);
    }

    #[test]
    fn offline_can_override_an_aliased_network_probe() {
        let cli = Cli::try_parse_from(["ownmesh", "doctor", "--check-network", "--offline"])
            .expect("offline override must be accepted by clap");
        let crate::cli::Commands::Doctor(args) = cli.command.expect("doctor command") else {
            panic!("expected doctor command");
        };
        assert!(args.check_network);
        assert!(args.offline);
    }

    #[test]
    fn doctor_is_read_only_on_missing_layout() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path().join("absent"));
        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
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
    fn doctor_uses_non_secret_session_markers_without_keychain_reads() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        fs::write(
            paths.state_dir.join("auth_session.json"),
            r#"{"has_refresh_token":true,"device_id":"dev_123"}"#,
        )
        .unwrap();

        let observed = observe_credentials(&paths);
        assert_eq!(observed.human_refresh_state, CredentialState::Present);
        assert_eq!(observed.device_key_state, CredentialState::Unknown);
        assert_eq!(observed.device_credential_state, CredentialState::Unknown);

        fs::write(
            paths.state_dir.join("auth_session.json"),
            r#"{"device_id":"dev_legacy"}"#,
        )
        .unwrap();
        assert_eq!(
            observe_credentials(&paths).human_refresh_state,
            CredentialState::Unknown
        );
    }

    #[test]
    fn daemon_status_only_resolves_indeterminate_service_state() {
        let daemon = DaemonObservation {
            endpoint: Some("local".into()),
            reachable: true,
            pid: Some(42),
            message: None,
        };
        let mut unknown = ServiceObservation {
            platform: "test".into(),
            supported: true,
            installed: true,
            running: None,
            unit_path: None,
            message: None,
            hardening: None,
        };
        merge_daemon_service_status(&daemon, &mut unknown);
        assert_eq!(unknown.running, Some(true));

        let mut explicit_stopped = unknown.clone();
        explicit_stopped.running = Some(false);
        merge_daemon_service_status(&daemon, &mut explicit_stopped);
        assert_eq!(explicit_stopped.running, Some(false));
    }

    /// P0-A/P0-B: doctor exposes pending/expired transition-journal health and
    /// op-journal pressure instead of an unconditional healthy result.
    #[test]
    fn doctor_surfaces_poisoned_journal_health() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        // A poisoned transition journal: one expired record.
        let transition_dir = paths.state_dir.join("session-transitions");
        fs::create_dir_all(&transition_dir).unwrap();
        let expired_record = serde_json::json!({
            "transition_id": "tr_expired_1",
            "kind": "claim",
            "phase": "intent",
            "session_id": "ses_1",
            "device_id": "dev",
            "workspace_id": "ws_default",
            "authenticated_principal": "owner",
            "old_binding": {
                "device_id": "dev", "workspace_id": "ws_default",
                "owner_principal": "owner", "host_nonce": "n",
                "controller_epoch": 1, "binding_expires_unix": now - 20,
                "host_expires_unix": now - 10, "child_pid": null,
                "child_process_birth": null,
            },
            "target": {
                "principal": "owner", "controller_epoch": 2,
                "binding_expires_unix": now - 20, "controller_attached": true,
                "terminal": false,
            },
            "new_binding": null,
            "created_unix": now - 3600,
            "expires_unix": now - 10,
        });
        let journal = serde_json::json!({
            "version": 1,
            "entries": { "tr_expired_1": expired_record },
        });
        fs::write(
            transition_dir.join("session-transition-journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        // A near-capacity op journal (all completed receipts).
        let mut op = serde_json::Map::new();
        for i in 0..2500 {
            op.insert(
                format!("prin\u{1f}op_{i}"),
                serde_json::json!({
                    "durable_receipt": true,
                    "truncated": true,
                    "status": "completed",
                    "operation_id": format!("op_{i}"),
                }),
            );
        }
        fs::write(
            paths.state_dir.join("op-journal.json"),
            serde_json::to_vec(&serde_json::Value::Object(op)).unwrap(),
        )
        .unwrap();

        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        let transition = report
            .checks
            .iter()
            .find(|c| c.id == "journals.transition")
            .expect("transition journal check");
        assert_eq!(transition.status, ownmesh_diagnostics::CheckStatus::Fail);
        assert!(transition.message.contains("expired"));
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .expect("op journal check");
        assert_eq!(op.status, ownmesh_diagnostics::CheckStatus::Warn);
        assert!(op.message.contains("pressure"));
        // The report must stay redacted (no entry content leaked).
        let json = serde_json::to_string(&report).unwrap();
        assert!(appears_redacted(&json));
        assert!(!json.contains("host_nonce"));
    }

    /// P1-D/P1-F: doctor runs official profile discovery and compares the
    /// bare system PATH with the deterministic user-local search — an
    /// installed CLI that only a login shell finds is surfaced, and dirs that
    /// exist but are not searched are named. The check is pure over the
    /// environment inputs so it does not depend on the CI host's PATH.
    #[cfg(not(windows))]
    #[test]
    fn doctor_profile_discovery_compares_service_and_login_paths() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join(".local/bin");
        fs::create_dir_all(&bin).unwrap();
        let codex = bin.join("codex");
        fs::write(&codex, b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(&codex).unwrap().permissions();
            perms.set_mode(0o755);
            fs::set_permissions(&codex, perms).unwrap();
        }

        // Isolated computation with a system-only PATH.
        let system_dirs: Vec<PathBuf> =
            env::split_paths(&std::ffi::OsString::from("/usr/bin:/bin")).collect();
        let full_dirs = {
            let mut dirs = system_dirs.clone();
            for d in ownmesh_exec::user_cli_search_dirs(Some(dir.path())) {
                if !dirs.contains(&d) {
                    dirs.push(d);
                }
            }
            dirs
        };
        let registry = ownmesh_profiles::ProfileRegistry::with_official();
        let user_local_only: Vec<String> = registry
            .list()
            .iter()
            .filter(|p| {
                registry
                    .resolve_binary_in_dirs(&p.id, &system_dirs)
                    .ok()
                    .flatten()
                    .is_none()
                    && registry
                        .resolve_binary_in_dirs(&p.id, &full_dirs)
                        .ok()
                        .flatten()
                        .is_some()
            })
            .map(|p| p.id.clone())
            .collect();
        assert!(
            user_local_only.contains(&"codex".to_string()),
            "codex installed in ~/.local/bin must resolve through the full search only: \
{user_local_only:?}"
        );

        // Feed the observation into run_doctor and expect a warn row.
        let mut input = ownmesh_diagnostics::DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();
        input.profile_discovery = ownmesh_diagnostics::ProfileDiscoveryObservation {
            user_local_only,
            existing_dirs_not_searched: vec![bin.display().to_string()],
            home_unavailable: false,
        };
        let report = ownmesh_diagnostics::run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "profiles.discovery")
            .expect("profile discovery check row");
        assert_eq!(check.status, ownmesh_diagnostics::CheckStatus::Warn);
        assert!(check.message.contains("codex"), "{check:?}");
        assert!(
            check.message.contains("not-installed"),
            "must explain the daemon-vs-login consequence: {check:?}"
        );

        // All-clear → pass.
        let mut input = ownmesh_diagnostics::DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();
        let report = ownmesh_diagnostics::run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "profiles.discovery")
            .unwrap();
        assert_eq!(check.status, ownmesh_diagnostics::CheckStatus::Pass);
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
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
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
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
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
                delegate_remote_mcp: false,
                rules: Vec::new(),
            },
        )
        .unwrap();

        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
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
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        assert!(!report
            .checks
            .iter()
            .any(|c| c.id == "control_plane.health" && c.message.contains("HTTP")));
    }

    /// P1-F: a parseable but wrong-shaped transition journal (the daemon's
    /// typed loader would reject it) must be disclosed as unreadable, not
    /// silently reported healthy with zero counts.
    #[test]
    fn structurally_invalid_transition_journal_is_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let transition_dir = paths.state_dir.join("session-transitions");
        std::fs::create_dir_all(&transition_dir).unwrap();
        // Wrong shape: `entries` is an array, not an object.
        std::fs::write(
            transition_dir.join("session-transition-journal.json"),
            br#"{"entries": [1, 2, 3]}"#,
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.transition_read_error.is_some(),
            "wrong-shaped transition journal must be disclosed: {obs:?}"
        );
        assert!(
            obs.transition_read_error
                .as_deref()
                .unwrap()
                .contains("full validation"),
            "{obs:?}"
        );
    }

    /// P1-F: a parseable but wrong-shaped op journal (the daemon's typed
    /// loader would reject it) must be disclosed as unreadable, not silently
    /// reported healthy with zero counts.
    #[test]
    fn structurally_invalid_op_journal_is_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        // Wrong shape: top-level is an array, not an object.
        std::fs::write(paths.state_dir.join("op-journal.json"), br"[1, 2, 3]").unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.op_journal_read_error.is_some(),
            "wrong-shaped op journal must be disclosed: {obs:?}"
        );
        assert!(
            obs.op_journal_read_error
                .as_deref()
                .unwrap()
                .contains("unexpected structure"),
            "{obs:?}"
        );
    }

    /// P1-F: entries the runtime refuses to replay/compact/evict (unknown
    /// forward-version state, malformed state values, or non-object entries)
    /// must be counted as uncertain and surfaced — never reported as an okay
    /// journal. Mirrors the runtime's fail-closed classifier.
    #[test]
    fn uncertain_op_journal_entries_are_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let journal = serde_json::json!({
            "prin\u{1f}op_done": {
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": "op_done",
            },
            "prin\u{1f}op_busy": {
                "__ownmesh_operation_state": "in_progress",
                "operation_id": "op_busy",
            },
            "prin\u{1f}op_future": {
                "__ownmesh_operation_state": "phase_two",
                "operation_id": "op_future",
            },
            "prin\u{1f}op_null_state": {
                "__ownmesh_operation_state": null,
                "operation_id": "op_null_state",
            },
            "prin\u{1f}op_bare_empty": {},
            "prin\u{1f}op_not_object": null,
        });
        std::fs::write(
            paths.state_dir.join("op-journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert_eq!(obs.op_journal_entries, 6);
        assert_eq!(
            obs.op_journal_in_progress, 1,
            "only the exact in-progress marker counts: {obs:?}"
        );
        assert_eq!(
            obs.op_journal_uncertain, 4,
            "unknown state, malformed state value, unmarked object, and non-object entry must count as uncertain: {obs:?}"
        );
        assert!(obs.op_journal_read_error.is_none(), "{obs:?}");

        // The doctor check must not report the journal as okay.
        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .expect("op journal check");
        assert_eq!(op.status, ownmesh_diagnostics::CheckStatus::Warn);
        assert!(
            op.message.contains("uncertain"),
            "uncertain entries must be surfaced: {}",
            op.message
        );
    }

    /// P0-B review (Medium): a durable `in_progress` marker is permanently
    /// non-replayable (the runtime refuses to replay/compact/evict it), so an
    /// operation that crashed or failed after reserving its key can never be
    /// retried. Doctor must surface it as a warning instead of a plain pass —
    /// the old check only mentioned in-progress markers inside the pass text.
    #[test]
    fn durable_in_progress_op_journal_marker_is_warned_not_passed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let journal = serde_json::json!({
            "prin\u{1f}op_stuck": {
                "__ownmesh_operation_state": "in_progress",
                "operation_id": "op_stuck",
            },
            "prin\u{1f}op_done": {
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": "op_done",
            },
        });
        std::fs::write(
            paths.state_dir.join("op-journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert_eq!(obs.op_journal_in_progress, 1);
        assert_eq!(obs.op_journal_uncertain, 0);

        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .expect("op journal check");
        assert_eq!(
            op.status,
            ownmesh_diagnostics::CheckStatus::Warn,
            "a durable in-progress marker must not be reported as a pass: {}",
            op.message
        );
        assert!(
            op.message.contains("in-progress") && op.message.contains("non-replayable"),
            "the warning must say the marker is non-replayable: {}",
            op.message
        );
    }

    /// ADR 0010 §1b / review: doctor must mirror the runtime's fail-closed
    /// classifier — a `durable_receipt: true` marker or an explicit
    /// `__ownmesh_operation_state == "completed"` value *without* the
    /// exact-once `operation_id` is malformed and counts as uncertain, never
    /// reported as a healthy completed receipt.
    #[test]
    fn completed_markers_without_operation_id_are_disclosed_as_uncertain() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let journal = serde_json::json!({
            "prin\u{1f}op_receipt_no_id": {
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
            },
            "prin\u{1f}op_state_no_id": {
                "__ownmesh_operation_state": "completed",
            },
            "prin\u{1f}op_good": {
                "durable_receipt": true,
                "truncated": true,
                "status": "completed",
                "operation_id": "op_good",
            },
        });
        std::fs::write(
            paths.state_dir.join("op-journal.json"),
            serde_json::to_vec(&journal).unwrap(),
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert_eq!(obs.op_journal_entries, 3);
        assert_eq!(
            obs.op_journal_uncertain, 2,
            "markers without the exact-once operation_id count as uncertain: {obs:?}"
        );
        assert!(obs.op_journal_read_error.is_none(), "{obs:?}");

        let report = collect_doctor_report(
            &paths,
            &DoctorArgs {
                check_network: false,
                offline: false,
                repair_journal: false,
                i_understand_replay_risk: false,
            },
            "test",
        );
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .expect("op journal check");
        assert_eq!(op.status, ownmesh_diagnostics::CheckStatus::Warn);
        assert!(
            op.message.contains("uncertain"),
            "malformed markers must be surfaced: {}",
            op.message
        );
    }

    #[test]
    fn repair_journal_restores_valid_backup_and_otherwise_writes_empty() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let primary = paths.state_dir.join("op-journal.json");
        let bak = paths.state_dir.join("op-journal.json.bak");
        std::fs::write(&primary, br#"{"broken""#).unwrap();
        std::fs::write(&bak, b"{}").unwrap();
        let restored = repair_op_journal_files(&paths).expect("restore from backup");
        assert!(restored.contains("restored"), "{restored}");
        let body = std::fs::read_to_string(&primary).unwrap();
        assert_eq!(body.trim(), "{}");
        assert!(!bak.exists(), "valid backup is consumed after restore");

        std::fs::write(&primary, br#"{"broken""#).unwrap();
        let emptied = repair_op_journal_files(&paths).expect("empty journal after archive");
        assert!(emptied.contains("empty"), "{emptied}");
        assert_eq!(std::fs::read_to_string(&primary).unwrap(), "{}");
    }

    #[test]
    fn repair_journal_requires_confirmation_flag() {
        let cli = Cli::try_parse_from(["ownmesh", "doctor", "--repair-journal"])
            .expect("repair flag must parse");
        let crate::cli::Commands::Doctor(args) = cli.command.expect("doctor command") else {
            panic!("expected doctor command");
        };
        assert!(args.repair_journal);
        assert!(!args.i_understand_replay_risk);
        let confirmed = Cli::try_parse_from([
            "ownmesh",
            "doctor",
            "--repair-journal",
            "--i-understand-replay-risk",
        ])
        .expect("confirmation flag must parse");
        let crate::cli::Commands::Doctor(confirmed) = confirmed.command.expect("doctor") else {
            panic!("expected doctor command");
        };
        assert!(confirmed.i_understand_replay_risk);
    }

    /// P1-F: a transition journal with an unsupported `version` (the daemon's
    /// typed loader would reject it) must be disclosed, not reported healthy.
    #[test]
    fn unsupported_transition_journal_version_is_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let transition_dir = paths.state_dir.join("session-transitions");
        std::fs::create_dir_all(&transition_dir).unwrap();
        std::fs::write(
            transition_dir.join("session-transition-journal.json"),
            br#"{"version": 99, "entries": {}}"#,
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.transition_read_error.is_some(),
            "unsupported version must be disclosed: {obs:?}"
        );
        assert!(
            obs.transition_read_error
                .as_deref()
                .unwrap()
                .contains("full validation"),
            "{obs:?}"
        );
    }

    /// P1-F: a transition journal whose entries are malformed (missing the
    /// fields the daemon's typed loader requires) must be disclosed, not
    /// reported healthy with zero counts.
    #[test]
    fn malformed_transition_journal_entries_are_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let transition_dir = paths.state_dir.join("session-transitions");
        std::fs::create_dir_all(&transition_dir).unwrap();
        std::fs::write(
            transition_dir.join("session-transition-journal.json"),
            br#"{"version": 1, "entries": {"tr_1": {"kind": "Claim"}}}"#,
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.transition_read_error.is_some(),
            "malformed entries must be disclosed: {obs:?}"
        );
        assert!(
            obs.transition_read_error
                .as_deref()
                .unwrap()
                .contains("full validation"),
            "{obs:?}"
        );
    }

    /// P1-F: a transition journal whose entry map key disagrees with the
    /// record's own `transition_id` (the daemon's typed loader rejects the
    /// whole journal) must be disclosed — a shape-only subset check would
    /// miss it.
    #[test]
    fn transition_journal_key_id_mismatch_is_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let transition_dir = paths.state_dir.join("session-transitions");
        std::fs::create_dir_all(&transition_dir).unwrap();
        let now = unix_now();
        let record = serde_json::json!({
            "transition_id": "tr_actual",
            "kind": "claim",
            "phase": "intent",
            "session_id": "ses_1",
            "device_id": "dev",
            "workspace_id": "ws_default",
            "authenticated_principal": "owner",
            "old_binding": {
                "device_id": "dev", "workspace_id": "ws_default",
                "owner_principal": "owner", "host_nonce": "n",
                "controller_epoch": 1, "binding_expires_unix": now - 20,
                "host_expires_unix": now - 10, "child_pid": null,
                "child_process_birth": null,
            },
            "target": {
                "principal": "owner", "controller_epoch": 2,
                "binding_expires_unix": now - 20, "controller_attached": true,
                "terminal": false,
            },
            "new_binding": null,
            "created_unix": now - 3600,
            "expires_unix": now - 10,
        });
        std::fs::write(
            transition_dir.join("session-transition-journal.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "entries": { "tr_wrong_key": record },
            }))
            .unwrap(),
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.transition_read_error.is_some(),
            "key/id mismatch must be disclosed: {obs:?}"
        );
        assert!(
            obs.transition_read_error
                .as_deref()
                .unwrap()
                .contains("full validation"),
            "{obs:?}"
        );
    }

    /// P1-F: a transition journal entry with an unknown field (which the
    /// daemon's `deny_unknown_fields` typed loader rejects) must be
    /// disclosed — the old shape-subset check would report it healthy.
    #[test]
    fn transition_journal_unknown_field_is_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let transition_dir = paths.state_dir.join("session-transitions");
        std::fs::create_dir_all(&transition_dir).unwrap();
        let now = unix_now();
        let record = serde_json::json!({
            "transition_id": "tr_1",
            "kind": "claim",
            "phase": "intent",
            "session_id": "ses_1",
            "device_id": "dev",
            "workspace_id": "ws_default",
            "authenticated_principal": "owner",
            "old_binding": {
                "device_id": "dev", "workspace_id": "ws_default",
                "owner_principal": "owner", "host_nonce": "n",
                "controller_epoch": 1, "binding_expires_unix": now - 20,
                "host_expires_unix": now - 10, "child_pid": null,
                "child_process_birth": null,
            },
            "target": {
                "principal": "owner", "controller_epoch": 2,
                "binding_expires_unix": now - 20, "controller_attached": true,
                "terminal": false,
            },
            "new_binding": null,
            "created_unix": now - 3600,
            "expires_unix": now - 10,
            "sneaky_extra": "not part of the typed model",
        });
        std::fs::write(
            transition_dir.join("session-transition-journal.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "entries": { "tr_1": record },
            }))
            .unwrap(),
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.transition_read_error.is_some(),
            "unknown-field entry must be disclosed: {obs:?}"
        );
        assert!(
            obs.transition_read_error
                .as_deref()
                .unwrap()
                .contains("full validation"),
            "{obs:?}"
        );
    }

    /// P1-F: a transition journal entry whose binding violates the daemon's
    /// invariants (host-expiry bound not covering the referenced host TTL)
    /// must be disclosed — the old shape-subset check would report it
    /// healthy.
    #[test]
    fn transition_journal_binding_invariant_violation_is_disclosed() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let transition_dir = paths.state_dir.join("session-transitions");
        std::fs::create_dir_all(&transition_dir).unwrap();
        let now = unix_now();
        // expires_unix (now - 10) < old_binding.host_expires_unix (now + 20):
        // clearing this record as expired could strand a still-live host.
        let record = serde_json::json!({
            "transition_id": "tr_1",
            "kind": "claim",
            "phase": "intent",
            "session_id": "ses_1",
            "device_id": "dev",
            "workspace_id": "ws_default",
            "authenticated_principal": "owner",
            "old_binding": {
                "device_id": "dev", "workspace_id": "ws_default",
                "owner_principal": "owner", "host_nonce": "n",
                "controller_epoch": 1, "binding_expires_unix": now - 20,
                "host_expires_unix": now + 20, "child_pid": null,
                "child_process_birth": null,
            },
            "target": {
                "principal": "owner", "controller_epoch": 2,
                "binding_expires_unix": now - 20, "controller_attached": true,
                "terminal": false,
            },
            "new_binding": null,
            "created_unix": now - 3600,
            "expires_unix": now - 10,
        });
        std::fs::write(
            transition_dir.join("session-transition-journal.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 1,
                "entries": { "tr_1": record },
            }))
            .unwrap(),
        )
        .unwrap();
        let obs = observe_journals(&paths);
        assert!(
            obs.transition_read_error.is_some(),
            "binding invariant violation must be disclosed: {obs:?}"
        );
        assert!(
            obs.transition_read_error
                .as_deref()
                .unwrap()
                .contains("full validation"),
            "{obs:?}"
        );
    }

    /// P1-F: a missing `HOME` must surface as a profile-discovery health
    /// issue, not silently produce a healthy observation.
    #[cfg(not(windows))]
    #[test]
    fn missing_home_surfaces_profile_discovery_issue() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let obs = observe_profile_discovery();
        if std::env::var_os("HOME").is_none() {
            assert!(
                obs.home_unavailable,
                "missing HOME must be surfaced: {obs:?}"
            );
        } else {
            assert!(!obs.home_unavailable, "HOME present: {obs:?}");
        }
    }
}
