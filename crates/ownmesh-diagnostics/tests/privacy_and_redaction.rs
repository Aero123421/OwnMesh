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
    prepare_support_bundle, redact_text, run_doctor, write_prepared_support_bundle,
    BinaryObservation, CheckStatus, ConfigObservation, ControlPlaneObservation,
    CredentialObservation, CredentialState, CredentialStoreObservation, DaemonObservation,
    DoctorInput, JournalsObservation, PrivacyPolicyObservation, PublicDiagnosticEvent,
    PublicJournalHealth, PublicPlatformFacts, PublicServiceFacts, ServiceObservation,
    SupportBundleError, SupportBundleInput,
};

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
            human_refresh_state: CredentialState::default(),
            device_key_state: CredentialState::default(),
            device_credential_state: CredentialState::default(),
            auth_session_present: true,
            enrolled_device_id_present: true,
        },
        credential_store: CredentialStoreObservation {
            metadata_present: true,
            backend_name: Some("preferred(os-keychain)".into()),
            fallback_policy: Some("primary_preferred_encrypted_file_fallback".into()),
            degraded: false,
            residual_fallback_entries: 0,
            read_error: None,
        },
        daemon: DaemonObservation {
            endpoint: Some("local".into()),
            reachable: true,
            pid: Some(1),
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
            hardening: None,
        },
        journals: JournalsObservation::default(),
        profile_discovery: ownmesh_diagnostics::ProfileDiscoveryObservation::default(),
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
fn doctor_surfaces_credential_fallback_provenance() {
    let mut input = base_input();
    input.credential_store.backend_name = Some("preferred(encrypted-file)".into());
    input.credential_store.degraded = true;
    input.credential_store.residual_fallback_entries = 2;
    let report = run_doctor(&input);
    let check = report
        .checks
        .iter()
        .find(|check| check.id == "credential.store")
        .unwrap();
    assert_eq!(check.status, CheckStatus::Warn);
    assert!(check.message.contains("encrypted-file"));
    assert!(check.message.contains("residual_fallback_entries=2"));
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
fn credential_states_are_explicit_without_values() {
    let mut input = base_input();
    input.credentials.human_refresh_present = false;
    input.credentials.human_refresh_state = CredentialState::Unknown;
    input.credentials.device_key_present = false;
    input.credentials.device_key_state = CredentialState::NotRequiredForCurrentMode;
    input.credentials.device_credential_present = false;
    input.credentials.device_credential_state = CredentialState::Missing;
    let report = run_doctor(&input);

    for (id, state) in [
        ("credential.human", CredentialState::Unknown),
        (
            "credential.device_key",
            CredentialState::NotRequiredForCurrentMode,
        ),
        ("credential.device_connect", CredentialState::Missing),
    ] {
        let check = report.checks.iter().find(|check| check.id == id).unwrap();
        assert_eq!(check.state, Some(state));
    }
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("not_required_for_current_mode"));
    assert!(!json.contains("refresh_token"));
}

fn support_input() -> SupportBundleInput {
    SupportBundleInput {
        doctor: run_doctor(&base_input()),
        platform: PublicPlatformFacts {
            os: "linux".into(),
            arch: "x86_64".into(),
            ownmesh_version: "1.2.17".into(),
        },
        service: PublicServiceFacts {
            platform: "systemd-user".into(),
            supported: true,
            installed: true,
            running: Some(true),
            hardening_summary: Some("baseline active".into()),
        },
        journal_health: PublicJournalHealth::default(),
        recent_events: vec![PublicDiagnosticEvent {
            kind: "service".into(),
            message: "daemon ready".into(),
        }],
    }
}

#[test]
fn support_bundle_is_typed_scanned_and_preview_bytes_are_exact_export() {
    let prepared = prepare_support_bundle(support_input(), 1_700_000_000).unwrap();
    assert_eq!(prepared.schema_version(), 2);
    assert_eq!(prepared.sha256_hex().len(), 64);
    assert_eq!(prepared.size(), prepared.bytes().len());
    let serialized = std::str::from_utf8(prepared.bytes()).unwrap();
    assert!(serialized.contains("journal_health"));
    assert!(!serialized.contains("sections"));

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("support.json");
    write_prepared_support_bundle(&path, &prepared).unwrap();
    let exported = std::fs::read(&path).unwrap();
    assert_eq!(exported, prepared.bytes());
    use sha2::{Digest, Sha256};
    let exported_digest: String = Sha256::digest(&exported)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    assert_eq!(exported_digest, prepared.sha256_hex());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn support_bundle_secret_scanner_fails_closed_without_echoing_secret() {
    let mut input = support_input();
    input.recent_events[0].message = "Authorization: Bearer super.secret.material".into();
    let error = prepare_support_bundle(input, 1_700_000_000).unwrap_err();
    assert_eq!(
        error,
        SupportBundleError::SuspiciousContent("recent_events".into())
    );
    let text = error.to_string();
    assert!(!text.contains("super.secret.material"));
}

#[test]
fn support_bundle_rejects_secret_query_parameters() {
    let mut input = support_input();
    input.recent_events[0].message =
        "request failed at https://example.test/callback?access_token=canary".into();
    let error = prepare_support_bundle(input, 1_700_000_000).unwrap_err();
    assert_eq!(
        error,
        SupportBundleError::SuspiciousContent("recent_events".into())
    );
    assert!(!error.to_string().contains("canary"));
}

#[test]
fn support_bundle_rejects_unlabeled_high_entropy_values() {
    let mut input = support_input();
    input.recent_events[0].message = "mF9qB0sT2Vx7Nz4Yk8Wc3Pd6Hr1La5Ue0Ji7Go2Qw9Rx4Kp6".into();
    let error = prepare_support_bundle(input, 1_700_000_000).unwrap_err();
    assert_eq!(
        error,
        SupportBundleError::SuspiciousContent("recent_events".into())
    );
}

#[test]
fn support_bundle_rejects_encoded_split_and_unicode_secret_forms() {
    for message in [
        r#"{"access_token":"json-canary"}"#,
        "Authorization:
Bearer split-line-canary",
        "Ａｕｔｈｏｒｉｚａｔｉｏｎ： Ｂｅａｒｅｒ full-width-canary",
        "request failed at https://example.test/callback?%61ccess_token=percent-canary",
        "-----BEGIN
PRIVATE KEY-----
canary",
    ] {
        let mut input = support_input();
        input.recent_events[0].message = message.into();
        let error = prepare_support_bundle(input, 1_700_000_000).unwrap_err();
        assert_eq!(
            error,
            SupportBundleError::SuspiciousContent("recent_events".into()),
            "scanner accepted {message:?}",
        );
        assert!(!error.to_string().contains("canary"));
    }
}

#[test]
fn support_bundle_rejects_base64_secret_containing_slash() {
    let mut input = support_input();
    input.recent_events[0].message = "mF9qB0sT2Vx7Nz4Yk8Wc3Pd6Hr1La5Ue0Ji7/Go2Qw9Rx4Kp6".into();
    let error = prepare_support_bundle(input, 1_700_000_000).unwrap_err();
    assert_eq!(
        error,
        SupportBundleError::SuspiciousContent("recent_events".into())
    );
}

#[test]
fn support_bundle_allows_bounded_paths_and_non_secret_status_text() {
    let mut input = support_input();
    input.recent_events[0].message =
        "/home/alice/.local/state/ownmesh/service-restart-pending".into();
    prepare_support_bundle(input, 1_700_000_000).unwrap();
}

#[test]
fn support_bundle_allows_long_but_low_entropy_diagnostic_text() {
    let mut input = support_input();
    input.recent_events[0].message = "service-restart-".repeat(8);
    prepare_support_bundle(input, 1_700_000_000).unwrap();
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
