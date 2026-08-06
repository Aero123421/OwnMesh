//! Privileged broker boundary tests (harden-07 / sec-01).

use ownmesh_broker::{enforce_bind_is_networkless, execute_verified, load_or_create_secret};
use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, default_broker_endpoint,
    resolve_broker_endpoint, verify_request, BrokerEndpoint, BrokerRequest, BrokerSecret,
    CapabilityToken, ElevatedCommand, ReplayCache, ELEVATED_CAPABILITY_SCOPE,
};
use std::net::SocketAddr;
use tempfile::tempdir;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
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
            secret,
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
fn forged_mac_and_wrong_caller_rejected() {
    let secret = BrokerSecret::generate();
    let mut req = signed_request(
        &secret,
        "ownmeshd",
        "op_forge",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    req.mac = "00".repeat(32);
    assert!(verify_request(&secret, &req, now_unix()).is_err());

    let mut replay = ReplayCache::new();
    let good = signed_request(
        &secret,
        "not-allowed",
        "op_unauth",
        echo_cmd("nope"),
        now_unix(),
        60,
    );
    let resp = execute_verified(
        &secret,
        &mut replay,
        &["ownmeshd".into()],
        &good,
        now_unix(),
    )
    .unwrap();
    assert!(!resp.ok);
    assert_eq!(resp.error.as_deref(), Some("unauthorized caller"));
}

#[test]
fn replayed_nonce_rejected_even_with_valid_mac() {
    let secret = BrokerSecret::generate();
    let req = signed_request(
        &secret,
        "ownmeshd",
        "op_replay",
        echo_cmd("once"),
        now_unix(),
        60,
    );
    let mut replay = ReplayCache::new();
    let _first =
        execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix()).unwrap();
    let err =
        execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix()).unwrap_err();
    assert!(err.to_ascii_lowercase().contains("replay"), "{err}");
}

#[test]
fn expired_request_rejected() {
    let secret = BrokerSecret::generate();
    let past = now_unix().saturating_sub(600);
    let req = signed_request(&secret, "ownmeshd", "op_exp", echo_cmd("old"), past, 1);
    assert!(verify_request(&secret, &req, now_unix()).is_err());
}

#[test]
fn tampered_args_invalidate_mac() {
    let secret = BrokerSecret::generate();
    let mut req = signed_request(
        &secret,
        "ownmeshd",
        "op_tamper",
        echo_cmd("clean"),
        now_unix(),
        60,
    );
    req.command.args.push("--evil".into());
    assert!(verify_request(&secret, &req, now_unix()).is_err());
    let mac = compute_mac(&secret, &req);
    req.mac = mac;
    verify_request(&secret, &req, now_unix()).unwrap();
}

#[test]
fn missing_capability_token_rejected() {
    let secret = BrokerSecret::generate();
    let mut req = build_request(
        &secret,
        "ownmeshd",
        "op_nocap",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    req.capability = None;
    req.mac = compute_mac(&secret, &req);
    assert!(verify_request(&secret, &req, now_unix()).is_err());

    let mut replay = ReplayCache::new();
    let err =
        execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix()).unwrap_err();
    assert!(
        err.to_ascii_lowercase().contains("token") || err.to_ascii_lowercase().contains("invalid"),
        "{err}"
    );
}

#[test]
fn scope_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let now = now_unix();
    let cap = CapabilityToken::issue_for_operation(
        &secret,
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
    assert!(verify_request(&secret, &req, now).is_err());
}

#[test]
fn operation_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let now = now_unix();
    let cap = CapabilityToken::issue_for_operation(
        &secret,
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
    assert!(verify_request(&secret, &req, now).is_err());
}

#[test]
fn secret_file_roundtrip_and_malformed_rejected() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("secret.bin");
    let secret = load_or_create_secret(&path).unwrap();
    let again = load_or_create_secret(&path).unwrap();
    assert_eq!(secret.as_bytes(), again.as_bytes());

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
    assert!(verify_request(&secret, &bad, now_unix()).is_err());
}
