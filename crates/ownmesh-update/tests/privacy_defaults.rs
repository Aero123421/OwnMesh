//! §14 update privacy defaults (harden-07).

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

use ownmesh_update::{
    default_sends_nothing_to_vendor, network_check_allowed, UpdateMode, UpdateSettings,
};

#[test]
fn defaults_send_nothing() {
    let s = UpdateSettings::default();
    assert_eq!(s.mode, UpdateMode::Off);
    assert!(!s.telemetry_enabled);
    assert!(!s.crash_reports_opt_in);
    assert!(default_sends_nothing_to_vendor(&s));
    assert!(!network_check_allowed(&s));
}

#[test]
fn enabling_check_does_not_enable_telemetry() {
    let s = UpdateSettings {
        mode: UpdateMode::Check,
        telemetry_enabled: false,
        crash_reports_opt_in: false,
        ..UpdateSettings::default()
    };
    assert!(network_check_allowed(&s));
    assert!(!s.telemetry_enabled);
    assert!(!s.crash_reports_opt_in);
}
