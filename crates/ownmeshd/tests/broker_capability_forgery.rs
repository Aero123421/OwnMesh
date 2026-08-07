//! fix-2: MAC-secret holders (ownmeshd-equivalent) cannot mint valid capabilities.
//!
//! Capability tokens are Ed25519-signed by a broker-only key. The request MAC
//! secret (`broker.secret`) is intentionally insufficient to forge a token that
//! verifies under the broker's public verify key.

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

use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, verify_request, BrokerSecret,
    CapabilitySigningKey, CapabilityToken, ElevatedCommand, PeerBind, ELEVATED_CAPABILITY_SCOPE,
};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn peer() -> PeerBind {
    PeerBind::new(std::process::id() as i32, 1000, "ownmeshd")
}

fn echo_cmd() -> ElevatedCommand {
    ElevatedCommand {
        program: "echo".into(),
        args: vec!["x".into()],
        cwd: None,
        env: vec![],
    }
}

#[test]
fn ownmeshd_readable_mac_secret_cannot_mint_broker_capability() {
    // Broker generates independent keys.
    let broker_signing = CapabilitySigningKey::generate();
    let broker_verify = broker_signing.verify_key();

    // ownmeshd only has the request MAC secret (broker.secret).
    let mac_secret = BrokerSecret::generate();
    let peer = peer();
    let now = now_unix();

    // Attacker tries to treat MAC secret bytes as an Ed25519 seed and mint.
    let attacker_key =
        CapabilitySigningKey::from_bytes(mac_secret.as_bytes()).expect("32-byte secret");
    let forged = CapabilityToken::issue_for_operation(
        &attacker_key,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "op_elevate",
        now,
        300,
    );

    assert!(
        forged.verify(&broker_verify, now).is_err(),
        "capability minted from MAC secret must not verify under broker key"
    );

    let req = build_request_with_capability(
        &mac_secret,
        "ownmeshd",
        "op_elevate",
        echo_cmd(),
        Some(forged),
        now,
        60,
    );
    // Request MAC is valid (attacker has secret).
    assert_eq!(req.mac, compute_mac(&mac_secret, &req));
    // Strict capability verification fails.
    assert!(verify_request(&mac_secret, &broker_verify, &req, &peer, now).is_err());
}

#[test]
fn random_signature_capability_rejected() {
    let broker_signing = CapabilitySigningKey::generate();
    let broker_verify = broker_signing.verify_key();
    let mac_secret = BrokerSecret::generate();
    let peer = peer();
    let now = now_unix();

    let mut forged = CapabilityToken::issue_for_operation(
        &broker_signing,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "op",
        now,
        60,
    );
    // Tamper signature while keeping claims.
    forged.signature = "ab".repeat(64);

    let req = build_request_with_capability(
        &mac_secret,
        "ownmeshd",
        "op",
        echo_cmd(),
        Some(forged),
        now,
        60,
    );
    assert!(verify_request(&mac_secret, &broker_verify, &req, &peer, now).is_err());
}

#[test]
fn client_build_request_never_embeds_capability() {
    let mac_secret = BrokerSecret::generate();
    let req = build_request(&mac_secret, "ownmeshd", "op", echo_cmd(), now_unix(), 60);
    assert!(
        req.capability.is_none(),
        "ownmeshd/client must not mint capabilities locally"
    );
}

#[test]
fn genuine_broker_mint_still_verifies() {
    let broker_signing = CapabilitySigningKey::generate();
    let broker_verify = broker_signing.verify_key();
    let mac_secret = BrokerSecret::generate();
    let peer = peer();
    let now = now_unix();
    let cap = CapabilityToken::issue_for_operation(
        &broker_signing,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "op_ok",
        now,
        60,
    );
    let req = build_request_with_capability(
        &mac_secret,
        "ownmeshd",
        "op_ok",
        echo_cmd(),
        Some(cap),
        now,
        60,
    );
    verify_request(&mac_secret, &broker_verify, &req, &peer, now).expect("genuine mint");
}

#[test]
fn peer_bind_mismatch_rejected_even_with_valid_signature() {
    let broker_signing = CapabilitySigningKey::generate();
    let broker_verify = broker_signing.verify_key();
    let mac_secret = BrokerSecret::generate();
    let peer = peer();
    let other = PeerBind::new(peer.pid + 1, peer.uid, peer.exe_path.clone());
    let now = now_unix();
    let cap = CapabilityToken::issue_for_operation(
        &broker_signing,
        &other,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "op",
        now,
        60,
    );
    let req = build_request_with_capability(
        &mac_secret,
        "ownmeshd",
        "op",
        echo_cmd(),
        Some(cap),
        now,
        60,
    );
    assert!(verify_request(&mac_secret, &broker_verify, &req, &peer, now).is_err());
}
