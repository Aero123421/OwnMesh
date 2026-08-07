//! Adversarial broker boundary tests (req 11 / sec-09 / fix-2).
//! Complements `security_boundary.rs` with an `execute_verified` cross-cut:
//! forged MAC, replay, mismatched capability scope & operation, MAC-secret mint forgery.

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

use ownmesh_broker::execute_verified;
use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, verify_request, BrokerSecret,
    CapabilitySigningKey, CapabilityToken, ElevatedCommand, PeerBind, ReplayCache,
    ELEVATED_CAPABILITY_SCOPE,
};

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn test_peer() -> PeerBind {
    PeerBind::new(4242, 1000, "/usr/bin/ownmeshd")
}

fn test_keys() -> (
    CapabilitySigningKey,
    ownmesh_broker_client::CapabilityVerifyKey,
) {
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    (sk, vk)
}

fn echo_cmd(arg: &str) -> ElevatedCommand {
    if cfg!(windows) {
        ElevatedCommand {
            program: "cmd.exe".into(),
            args: vec!["/C".into(), format!("echo {arg}")],
            cwd: None,
            env: vec![],
        }
    } else {
        ElevatedCommand {
            program: "echo".into(),
            args: vec![arg.into()],
            cwd: None,
            env: vec![],
        }
    }
}

fn signed(
    secret: &BrokerSecret,
    sk: &CapabilitySigningKey,
    peer: &PeerBind,
    caller: &str,
    op: &str,
    cmd: ElevatedCommand,
    now: i64,
    ttl: i64,
) -> ownmesh_broker_client::BrokerRequest {
    build_request_with_capability(
        secret,
        caller,
        op,
        cmd,
        Some(CapabilityToken::issue_for_operation(
            sk,
            peer,
            caller,
            ELEVATED_CAPABILITY_SCOPE,
            op,
            now,
            ttl.max(60),
        )),
        now,
        ttl,
    )
}

#[test]
fn execute_verified_rejects_forged_mac() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let mut req = signed(
        &secret,
        &sk,
        &peer,
        "ownmeshd",
        "op_forge",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    req.mac = "ff".repeat(32);
    let mut replay = ReplayCache::new();
    let err = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix())
        .expect_err("forged mac");
    let m = err.to_ascii_lowercase();
    assert!(
        m.contains("signature") || m.contains("mac") || m.contains("invalid"),
        "{err}"
    );
}

#[test]
fn execute_verified_rejects_replay() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let req = signed(
        &secret,
        &sk,
        &peer,
        "ownmeshd",
        "op_replay",
        echo_cmd("once"),
        now_unix(),
        60,
    );
    let mut replay = ReplayCache::new();
    let _ = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix())
        .expect("first ok");
    let err = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix())
        .expect_err("replay");
    assert!(err.to_ascii_lowercase().contains("replay"), "{err}");
}

#[test]
fn execute_verified_rejects_mismatched_capability() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let now = now_unix();
    let mut replay = ReplayCache::new();

    let bad_scope = CapabilityToken::issue_for_operation(
        &sk,
        &peer,
        "ownmeshd",
        "wrong.scope",
        "op_scope",
        now,
        120,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "op_scope",
        echo_cmd("x"),
        Some(bad_scope),
        now,
        60,
    );
    assert!(verify_request(&secret, &vk, &req, &peer, now).is_err());
    let err =
        execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now).expect_err("bad scope");
    assert!(!err.is_empty(), "{err}");

    let bad_op = CapabilityToken::issue_for_operation(
        &sk,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "bound_only",
        now,
        120,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "other_op",
        echo_cmd("x"),
        Some(bad_op),
        now,
        60,
    );
    let err = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now)
        .expect_err("op mismatch");
    assert!(!err.is_empty(), "{err}");
}

#[test]
fn execute_verified_rejects_mac_secret_forged_capability() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let evil = CapabilitySigningKey::from_bytes(secret.as_bytes()).unwrap();
    let forged = CapabilityToken::issue_for_operation(
        &evil,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "op_forge_cap",
        now_unix(),
        120,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "op_forge_cap",
        echo_cmd("x"),
        Some(forged),
        now_unix(),
        60,
    );
    // MAC is valid (attacker has secret) but capability signature is not under broker key.
    assert_eq!(req.mac, compute_mac(&secret, &req));
    let mut replay = ReplayCache::new();
    let err = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix())
        .expect_err("forged capability");
    let m = err.to_ascii_lowercase();
    assert!(
        m.contains("signature") || m.contains("invalid") || m.contains("unauthor"),
        "{err}"
    );
}

#[test]
fn build_request_does_not_mint_capability_from_mac_secret() {
    let secret = BrokerSecret::generate();
    let req = build_request(&secret, "ownmeshd", "op", echo_cmd("x"), now_unix(), 60);
    assert!(
        req.capability.is_none(),
        "clients must not mint capabilities from BrokerSecret"
    );
}
