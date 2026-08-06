//! Broker client auth / replay unit surface (harden-07).

use ownmesh_broker_client::{
    build_request, verify_request, BrokerSecret, ElevatedCommand, ReplayCache,
};

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[test]
fn valid_request_verifies_and_replay_cache_blocks_second_insert() {
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
    verify_request(&secret, &req, now()).unwrap();
    let mut cache = ReplayCache::new();
    cache.check_and_insert(&req).unwrap();
    assert!(cache.check_and_insert(&req).is_err());
}

#[test]
fn capability_token_expiry_enforced_when_present() {
    use ownmesh_broker_client::{build_request_with_capability, CapabilityToken};

    let secret = BrokerSecret::generate();
    let cap = CapabilityToken::issue(&secret, "ownmeshd", "elevated", now() - 120, 1);
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
    let _ = verify_request(&secret, &req, now());
    assert!(req
        .capability
        .as_ref()
        .unwrap()
        .verify(&secret, now())
        .is_err());
}
