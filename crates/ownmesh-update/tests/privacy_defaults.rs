//! §14 update privacy defaults (harden-07).

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
