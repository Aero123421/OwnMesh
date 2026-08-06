//! Broker client auth / replay unit surface (harden-07 / fix-2).

use ownmesh_broker_client::{
    build_request, build_request_with_capability, verify_request, verify_request_mac, BrokerSecret,
    CapabilitySigningKey, CapabilityToken, ElevatedCommand, PeerBind, ReplayCache,
    ELEVATED_CAPABILITY_SCOPE,
};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn peer() -> PeerBind {
    PeerBind::new(7, 1000, "/bin/ownmeshd")
}

#[test]
fn valid_request_verifies_and_replay_cache_blocks_second_insert() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    let peer = peer();
    let cap = CapabilityToken::issue_for_operation(
        &sk,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "op1",
        now(),
        60,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "op1",
        ElevatedCommand {
            program: "echo".into(),
            args: vec!["ok".into()],
            cwd: None,
            env: vec![],
        },
        Some(cap),
        now(),
        60,
    );
    verify_request(&secret, &vk, &req, &peer, now()).unwrap();
    let mut cache = ReplayCache::new();
    cache.check_and_insert(&req).unwrap();
    assert!(cache.check_and_insert(&req).is_err());
}

#[test]
fn capability_token_expiry_enforced_when_present() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    let peer = peer();
    let cap = CapabilityToken::issue(
        &sk,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        now() - 120,
        1,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "op_cap",
        ElevatedCommand {
            program: "echo".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        },
        Some(cap),
        now(),
        30,
    );
    let _ = verify_request(&secret, &vk, &req, &peer, now());
    assert!(req.capability.as_ref().unwrap().verify(&vk, now()).is_err());
}

#[test]
fn request_without_capability_has_valid_mac_only() {
    let secret = BrokerSecret::generate();
    let req = build_request(
        &secret,
        "ownmeshd",
        "op1",
        ElevatedCommand {
            program: "echo".into(),
            args: vec!["ok".into()],
            cwd: None,
            env: vec![],
        },
        now(),
        60,
    );
    assert!(req.capability.is_none());
    verify_request_mac(&secret, &req, now()).unwrap();
}
