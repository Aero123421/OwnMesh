//! Auth/token secret redaction tests (harden-07).

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

use ownmesh_identity::{SecretBytes, SecretString};

#[test]
fn secret_string_redacts_debug_display_and_json() {
    let s = SecretString::new("refresh-token-value-do-not-leak");
    let dbg = format!("{s:?}");
    let disp = format!("{s}");
    assert!(dbg.to_ascii_lowercase().contains("redacted"));
    assert!(!dbg.contains("refresh-token-value"));
    assert!(disp.contains("REDACTED") || disp.contains("redacted"));
    assert!(!disp.contains("refresh-token-value"));

    let json = serde_json::to_string(&s).unwrap_or_else(|_| "{}".into());
    assert!(
        !json.contains("refresh-token-value"),
        "json leaked secret: {json}"
    );
}

#[test]
fn secret_bytes_redacts() {
    let b = SecretBytes::new(b"device-seed-bytes-012345".to_vec());
    let dbg = format!("{b:?}");
    assert!(dbg.to_ascii_lowercase().contains("redacted"));
    assert!(!dbg.contains("device-seed-bytes"));
}
