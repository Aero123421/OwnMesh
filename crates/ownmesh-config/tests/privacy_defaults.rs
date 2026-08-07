//! §14 privacy default invariants (harden-07). Telemetry remains OFF by default.

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

use ownmesh_config::OwnMeshConfig;

#[test]
fn telemetry_and_crash_upload_default_off() {
    let cfg = OwnMeshConfig::default();
    cfg.validate().unwrap();
    assert!(!cfg.telemetry.project);
    assert!(!cfg.telemetry.crash_upload);
    assert!(!cfg.telemetry.usage_analytics);
}

#[test]
fn default_config_toml_has_no_secrets_and_false_telemetry() {
    let cfg = OwnMeshConfig::default();
    let text = toml::to_string_pretty(&cfg).unwrap();
    let lower = text.to_ascii_lowercase();
    for needle in [
        "refresh_token",
        "private_key",
        "client_secret",
        "password",
        "api_key",
    ] {
        assert!(!lower.contains(needle), "leaked {needle} in {text}");
    }
    assert!(
        lower.contains("project = false")
            || lower.contains("crash_upload = false")
            || !lower.contains("project = true"),
        "{text}"
    );
}

#[test]
fn update_defaults_are_conservative() {
    let cfg = OwnMeshConfig::default();
    assert_ne!(cfg.update.mode, "auto");
    assert_eq!(cfg.update.channel, "stable");
}
