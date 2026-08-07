//! Privileged broker boundary tests (harden-07 / sec-01 / fix-2).

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
    clippy::semicolon_if_nothing_returned,
    clippy::single_match,
    clippy::single_match_else,
    clippy::unnested_or_patterns
)]

use ownmesh_broker::{enforce_bind_is_networkless, execute_verified, load_or_create_secret};
use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, default_broker_endpoint,
    resolve_broker_endpoint, verify_request, verify_request_mac, BrokerEndpoint, BrokerRequest,
    BrokerSecret, CapabilitySigningKey, CapabilityToken, ElevatedCommand, PeerBind, ReplayCache,
    ELEVATED_CAPABILITY_SCOPE,
};
use std::net::SocketAddr;
use tempfile::tempdir;

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

fn signed_request(
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
fn networkless_rejects_non_loopback_and_unspecified() {
    for s in [
        "0.0.0.0:8080",
        "1.2.3.4:9",
        "10.0.0.5:22",
        "172.16.0.1:443",
        "192.168.1.1:80",
        "[::]:443",
        "[2001:db8::1]:1",
    ] {
        let addr: SocketAddr = s.parse().unwrap();
        let err = enforce_bind_is_networkless(addr).unwrap_err();
        assert!(
            err.contains("networkless") || err.contains("loopback"),
            "{s} => {err}"
        );
    }
    let ok: SocketAddr = "127.0.0.1:0".parse().unwrap();
    enforce_bind_is_networkless(ok).unwrap();
    let ok6: SocketAddr = "[::1]:0".parse().unwrap();
    let _ = enforce_bind_is_networkless(ok6);
}

#[test]
fn default_and_resolved_endpoints_are_local_only() {
    let dir = tempdir().unwrap();
    let ep = default_broker_endpoint(dir.path());
    match &ep {
        BrokerEndpoint::LoopbackTcp(addr) => assert!(addr.ip().is_loopback()),
        BrokerEndpoint::UnixSocket(path) => {
            assert!(path.is_absolute() || path.starts_with(dir.path()))
        }
        BrokerEndpoint::NamedPipe(name) => assert!(!name.contains("://")),
    }
    ep.enforce_networkless().unwrap();
    let remoteish = resolve_broker_endpoint(dir.path(), Some("tcp:8.8.8.8:53"));
    match remoteish {
        Ok(ep) => assert!(ep.enforce_networkless().is_err()),
        Err(_) => {}
    }
}

#[test]
fn forged_mac_and_peer_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let mut req = signed_request(
        &secret,
        &sk,
        &peer,
        "ownmeshd",
        "op_forge",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    req.mac = "00".repeat(32);
    assert!(verify_request(&secret, &vk, &req, &peer, now_unix()).is_err());

    // Valid MAC + trusted principal label, but capability bound to a different peer.
    let mut replay = ReplayCache::new();
    let other = PeerBind::new(peer.pid + 7, peer.uid, peer.exe_path.clone());
    let mismatched = signed_request(
        &secret,
        &sk,
        &other,
        "ownmeshd",
        "op_unauth",
        echo_cmd("nope"),
        now_unix(),
        60,
    );
    let err = execute_verified(
        &secret,
        &sk,
        &vk,
        &mut replay,
        &mismatched,
        &peer,
        now_unix(),
    )
    .unwrap_err();
    assert!(
        err.to_ascii_lowercase().contains("unauthor")
            || err.to_ascii_lowercase().contains("signature"),
        "{err}"
    );
}

#[test]
fn replayed_nonce_rejected_even_with_valid_mac() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let req = signed_request(
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
    let _first = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix()).unwrap();
    let err =
        execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix()).unwrap_err();
    assert!(err.to_ascii_lowercase().contains("replay"), "{err}");
}

#[test]
fn expired_request_rejected() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let past = now_unix().saturating_sub(600);
    let req = signed_request(
        &secret,
        &sk,
        &peer,
        "ownmeshd",
        "op_exp",
        echo_cmd("old"),
        past,
        1,
    );
    assert!(verify_request(&secret, &vk, &req, &peer, now_unix()).is_err());
}

#[test]
fn tampered_args_invalidate_mac() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let mut req = signed_request(
        &secret,
        &sk,
        &peer,
        "ownmeshd",
        "op_tamper",
        echo_cmd("clean"),
        now_unix(),
        60,
    );
    req.command.args.push("--evil".into());
    assert!(verify_request(&secret, &vk, &req, &peer, now_unix()).is_err());
    let mac = compute_mac(&secret, &req);
    req.mac = mac;
    verify_request(&secret, &vk, &req, &peer, now_unix()).unwrap();
}

#[test]
fn missing_capability_is_never_minted_by_generic_verify_path() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let req = build_request(
        &secret,
        "ownmeshd",
        "op_nocap",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    assert!(req.capability.is_none());
    assert!(verify_request(&secret, &vk, &req, &peer, now_unix()).is_err());
    verify_request_mac(&secret, &req, now_unix()).unwrap();

    let mut replay = ReplayCache::new();
    let err = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix())
        .expect_err("generic path must not mint");
    assert!(err.to_ascii_lowercase().contains("mint denied"), "{err}");
}

#[test]
fn scope_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let now = now_unix();
    let cap = CapabilityToken::issue_for_operation(
        &sk,
        &peer,
        "ownmeshd",
        "not.elevated",
        "op_scope",
        now,
        120,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "op_scope",
        echo_cmd("x"),
        Some(cap),
        now,
        60,
    );
    assert!(verify_request(&secret, &vk, &req, &peer, now).is_err());
}

#[test]
fn operation_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let (sk, vk) = test_keys();
    let peer = test_peer();
    let now = now_unix();
    let cap = CapabilityToken::issue_for_operation(
        &sk,
        &peer,
        "ownmeshd",
        ELEVATED_CAPABILITY_SCOPE,
        "bound_op",
        now,
        120,
    );
    let req = build_request_with_capability(
        &secret,
        "ownmeshd",
        "different_op",
        echo_cmd("x"),
        Some(cap),
        now,
        60,
    );
    assert!(verify_request(&secret, &vk, &req, &peer, now).is_err());
}

#[test]
fn secret_file_roundtrip_and_malformed_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("secret.bin");
    let secret = load_or_create_secret(&path).unwrap();
    let again = load_or_create_secret(&path).unwrap();
    assert_eq!(secret.as_bytes(), again.as_bytes());
    let (_sk, vk) = test_keys();
    let peer = test_peer();

    let bad = BrokerRequest {
        protocol_version: 1,
        request_id: String::new(),
        operation_id: String::new(),
        nonce: String::new(),
        issued_at_unix: now_unix(),
        expires_at_unix: now_unix() + 30,
        caller_principal: "ownmeshd".into(),
        capability: None,
        command: ElevatedCommand {
            program: String::new(),
            args: vec![],
            cwd: None,
            env: vec![],
        },
        mac: "dead".into(),
    };
    assert!(verify_request(&secret, &vk, &bad, &peer, now_unix()).is_err());
}
