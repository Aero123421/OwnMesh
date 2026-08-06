//! Adversarial broker boundary tests (req 11 / sec-09).
//! Complements `security_boundary.rs` with an execute_verified cross-cut:
//! forged MAC, replay, missing/mismatched capability scope & operation.

use ownmesh_broker::execute_verified;
use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, verify_request, BrokerSecret,
    CapabilityToken, ElevatedCommand, ReplayCache, ELEVATED_CAPABILITY_SCOPE,
};

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

fn signed(
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
fn execute_verified_rejects_forged_mac() {
    let secret = BrokerSecret::generate();
    let mut req = signed(
        &secret,
        "ownmeshd",
        "op_forge",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    req.mac = "ff".repeat(32);
    let mut replay = ReplayCache::new();
    let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix())
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
    let req = signed(
        &secret,
        "ownmeshd",
        "op_replay",
        echo_cmd("once"),
        now_unix(),
        60,
    );
    let mut replay = ReplayCache::new();
    let _ = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix())
        .expect("first ok");
    let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix())
        .expect_err("replay");
    assert!(err.to_ascii_lowercase().contains("replay"), "{err}");
}

#[test]
fn execute_verified_rejects_missing_and_mismatched_capability() {
    let secret = BrokerSecret::generate();
    let now = now_unix();
    let mut replay = ReplayCache::new();

    let mut missing = build_request(&secret, "ownmeshd", "op_nocap", echo_cmd("x"), now, 60);
    missing.capability = None;
    missing.mac = compute_mac(&secret, &missing);
    let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &missing, now)
        .expect_err("missing cap");
    assert!(
        err.to_ascii_lowercase().contains("token")
            || err.to_ascii_lowercase().contains("invalid")
            || err.to_ascii_lowercase().contains("capability"),
        "{err}"
    );

    let bad_scope = CapabilityToken::issue_for_operation(
        &secret,
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
    assert!(verify_request(&secret, &req, now).is_err());
    let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now)
        .expect_err("bad scope");
    assert!(!err.is_empty(), "{err}");

    let bad_op = CapabilityToken::issue_for_operation(
        &secret,
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
    let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now)
        .expect_err("op mismatch");
    assert!(!err.is_empty(), "{err}");
}
