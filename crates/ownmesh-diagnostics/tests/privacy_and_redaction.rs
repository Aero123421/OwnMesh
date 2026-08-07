//! §14 diagnostics: telemetry/relay doctor defaults + support bundle redaction (harden-07).

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnested_or_patterns
)]

use ownmesh_diagnostics::{
    build_support_bundle, redact_text, run_doctor, BinaryObservation, CheckStatus,
    ConfigObservation, ControlPlaneObservation, CredentialObservation, DaemonObservation,
    DoctorInput, PrivacyPolicyObservation, ServiceObservation,
};
use std::collections::BTreeMap;

fn base_input() -> DoctorInput {
    DoctorInput {
        binary: BinaryObservation {
            cli_version: "test".into(),
            cli_path: Some("/tmp/ownmesh".into()),
            cli_on_path: true,
            daemon_path: Some("/tmp/ownmeshd".into()),
            daemon_on_path: true,
        },
        config: ConfigObservation {
            path: Some("/tmp/config.toml".into()),
            present: true,
            readable: true,
            parse_ok: true,
            validate_ok: true,
            permissions_ok: true,
            message: None,
        },
        credentials: CredentialObservation {
            human_refresh_present: true,
            device_key_present: true,
            device_credential_present: true,
            auth_session_present: true,
            enrolled_device_id_present: true,
        },
        daemon: DaemonObservation {
            endpoint: Some("local".into()),
            reachable: true,
            message: None,
        },
        control_plane: ControlPlaneObservation {
            configured: true,
            url: Some("https://example.workers.dev".into()),
            probed: false,
            reachable: None,
            http_status: None,
            message: None,
        },
        privacy_policy: PrivacyPolicyObservation {
            policy_present: true,
            policy_preset: Some("recommended".into()),
            policy_valid: true,
            telemetry_project: false,
            telemetry_crash_upload: false,
            telemetry_usage_analytics: false,
            relay_enabled: false,
            update_mode: Some("off".into()),
            update_channel: Some("stable".into()),
            update_network_off: true,
        },
        service: ServiceObservation {
            platform: "test".into(),
            supported: true,
            installed: true,
            running: Some(true),
            unit_path: None,
            message: None,
        },
    }
}

#[test]
fn doctor_passes_when_telemetry_and_relay_off() {
    let report = run_doctor(&base_input());
    assert!(report.ok);
    let tel = report
        .checks
        .iter()
        .find(|c| c.id == "privacy.telemetry")
        .unwrap();
    assert_eq!(tel.status, CheckStatus::Pass);
    let rel = report
        .checks
        .iter()
        .find(|c| c.id == "privacy.relay")
        .unwrap();
    assert_eq!(rel.status, CheckStatus::Pass);
}

#[test]
fn doctor_warns_when_telemetry_or_relay_opted_in() {
    let mut input = base_input();
    input.control_plane.configured = false;
    input.control_plane.url = None;
    input.privacy_policy.telemetry_project = true;
    input.privacy_policy.relay_enabled = true;
    let report = run_doctor(&input);
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "privacy.telemetry" && c.status == CheckStatus::Warn));
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "privacy.relay" && c.status == CheckStatus::Warn));
}

#[test]
fn support_bundle_always_redacted_and_strips_secrets() {
    let doctor = run_doctor(&DoctorInput::default());
    let mut sections = BTreeMap::new();
    sections.insert(
        "env".into(),
        "access_token=super-secret-value\npassword=hunter2\n innocuous".into(),
    );
    sections.insert("note".into(), "authorization: Bearer abc.def.ghi".into());
    let bundle = build_support_bundle(doctor, sections, 1_700_000_000);
    assert!(bundle.redacted);
    let env = bundle.sections.get("env").unwrap();
    assert!(env.contains("REDACTED"));
    assert!(!env.contains("super-secret-value"));
    assert!(!env.contains("hunter2"));
    let note = bundle.sections.get("note").unwrap();
    assert!(!note.contains("abc.def.ghi"));
}

#[test]
fn redact_text_covers_common_secret_keys() {
    for sample in [
        "refresh_token=r1",
        "client_secret=c1",
        "api_key=k1",
        "Authorization: Bearer zzz",
    ] {
        let out = redact_text(sample);
        assert!(out.contains("REDACTED"), "{sample} -> {out}");
    }
}
