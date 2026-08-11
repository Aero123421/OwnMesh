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

use ownmesh_config::{OwnMeshConfig, TelemetryConfig, UpdateConfig};

/// Authoritative privacy-default invariant for the whole product.
///
/// This test — not a source `grep` — is what CI runs to prove the §14/§25
/// defaults. It asserts the *values a fresh install actually gets*, so it keeps
/// holding regardless of whether a default is spelled as a literal, a
/// `#[derive(Default)]`, or a `#[serde(default = "...")]` helper.
#[test]
fn telemetry_defaults_are_all_off() {
    let expected = TelemetryConfig {
        project: false,
        crash_upload: false,
        usage_analytics: false,
    };
    assert_eq!(
        TelemetryConfig::default(),
        expected,
        "every telemetry toggle must default to OFF"
    );
    assert_eq!(OwnMeshConfig::default().telemetry, expected);
}

#[test]
fn update_network_defaults_to_off() {
    assert_eq!(
        UpdateConfig::default(),
        UpdateConfig {
            mode: "off".into(),
            channel: "stable".into(),
        },
        "update network access must default to OFF on the `stable` channel"
    );
    assert_eq!(OwnMeshConfig::default().update.mode, "off");
}

/// A user config that omits the privacy sections must still deserialize to OFF.
///
/// The serde `default` attributes are the real-world path: nobody hand-writes
/// `[telemetry]` into `config.toml`, so an omitted section flipping to ON would
/// be invisible in `OwnMeshConfig::default()` alone.
#[test]
fn omitted_privacy_sections_deserialize_to_off() {
    let cfg: OwnMeshConfig = toml::from_str("schema_version = 1\n").expect("minimal config parses");
    cfg.validate().expect("minimal config validates");
    assert_eq!(cfg.telemetry, TelemetryConfig::default());
    assert!(!cfg.telemetry.project);
    assert!(!cfg.telemetry.crash_upload);
    assert!(!cfg.telemetry.usage_analytics);
    assert_eq!(cfg.update.mode, "off");
    assert_eq!(cfg.update.channel, "stable");
}

/// A serialized default config must not carry any enabled privacy toggle, and
/// must never carry secret-shaped fields.
#[test]
fn serialized_default_config_is_private_and_secret_free() {
    let cfg = OwnMeshConfig::default();
    let text = toml::to_string_pretty(&cfg).expect("serialize default config");
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

    for toggle in ["project", "crash_upload", "usage_analytics"] {
        assert!(
            lower.contains(&format!("{toggle} = false")),
            "`{toggle}` must be serialized as false; got:\n{text}"
        );
        assert!(
            !lower.contains(&format!("{toggle} = true")),
            "`{toggle}` must never be serialized as true; got:\n{text}"
        );
    }
    assert!(
        lower.contains("mode = \"off\""),
        "update mode must be serialized as \"off\"; got:\n{text}"
    );
}

/// Only `off` keeps the update subsystem entirely off the network. Guard the
/// exact vocabulary so a future mode rename cannot silently become the default.
#[test]
fn update_mode_vocabulary_is_stable_and_off_is_the_default() {
    for mode in ["off", "check", "notify", "download", "auto"] {
        let cfg: OwnMeshConfig = toml::from_str(&format!(
            "schema_version = 1\n[update]\nmode = \"{mode}\"\n"
        ))
        .expect("update mode parses");
        cfg.validate().expect("documented update mode validates");
    }
    let rejected: OwnMeshConfig =
        toml::from_str("schema_version = 1\n[update]\nmode = \"sneaky\"\n").expect("parses");
    assert!(
        rejected.validate().is_err(),
        "undocumented update modes must fail validation"
    );
    assert_eq!(UpdateConfig::default().mode, "off");
}
