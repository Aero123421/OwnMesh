//! §14 diagnostics: telemetry/relay doctor defaults + support bundle redaction (harden-07).

use ownmesh_diagnostics::{
    build_support_bundle, redact_text, run_doctor, CheckStatus, DoctorInput,
};
use std::collections::BTreeMap;

#[test]
fn doctor_passes_when_telemetry_and_relay_off() {
    let report = run_doctor(&DoctorInput {
        config_readable: true,
        daemon_reachable: true,
        identity_present: true,
        control_plane_url: Some("https://example.workers.dev".into()),
        telemetry_enabled: false,
        relay_enabled: false,
    });
    assert!(report.ok);
    let tel = report
        .checks
        .iter()
        .find(|c| c.id == "telemetry_default")
        .unwrap();
    assert_eq!(tel.status, CheckStatus::Pass);
    let rel = report
        .checks
        .iter()
        .find(|c| c.id == "relay_default")
        .unwrap();
    assert_eq!(rel.status, CheckStatus::Pass);
}

#[test]
fn doctor_warns_when_telemetry_or_relay_opted_in() {
    let report = run_doctor(&DoctorInput {
        config_readable: true,
        daemon_reachable: true,
        identity_present: true,
        control_plane_url: None,
        telemetry_enabled: true,
        relay_enabled: true,
    });
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "telemetry_default" && c.status == CheckStatus::Warn));
    assert!(report
        .checks
        .iter()
        .any(|c| c.id == "relay_default" && c.status == CheckStatus::Warn));
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
