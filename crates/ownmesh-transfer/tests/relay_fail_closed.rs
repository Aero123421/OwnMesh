//! §12 fail-closed transfer invariants (harden-07).

use ownmesh_transfer::{
    plan_transfer, requires_relay, PlanRequest, TransferConfig, TransferConsent, TransferError,
    TransportKind,
};
use tempfile::tempdir;

fn consent() -> TransferConsent {
    TransferConsent {
        sender_principal: "s".into(),
        receiver_principal: "r".into(),
        sender_ok: true,
        receiver_ok: true,
    }
}

#[test]
fn default_relay_disabled() {
    let cfg = TransferConfig::default();
    assert!(!cfg.relay_enabled);
    assert!(cfg.relay_endpoint.is_none());
}

#[test]
fn no_path_no_lan_fails_closed_without_relay() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("a.bin");
    std::fs::write(&src, b"x").unwrap();
    let err = plan_transfer(
        &TransferConfig::default(),
        &PlanRequest {
            source: src,
            dest: dir.path().join("b.bin"),
            direct_path_available: false,
            lan_available: false,
            consent: consent(),
        },
    )
    .unwrap_err();
    assert_eq!(err, TransferError::NoDirectPathRelayDisabled);
}

#[test]
fn enabled_but_unconfigured_relay_does_not_fallback() {
    let dir = tempdir().unwrap();
    let src = dir.path().join("a.bin");
    std::fs::write(&src, b"x").unwrap();
    let cfg = TransferConfig {
        relay_enabled: true,
        relay_endpoint: Some(String::new()),
        max_bytes: 1_000_000,
    };
    let err = plan_transfer(
        &cfg,
        &PlanRequest {
            source: src,
            dest: dir.path().join("b.bin"),
            direct_path_available: false,
            lan_available: false,
            consent: consent(),
        },
    )
    .unwrap_err();
    assert_eq!(err, TransferError::RelayNotConfigured);
}

#[test]
fn cloud_relay_marked_as_requires_relay() {
    assert!(requires_relay(TransportKind::CloudRelay));
    assert!(!requires_relay(TransportKind::LocalLoopback));
    assert!(!requires_relay(TransportKind::LanDirect));
}
