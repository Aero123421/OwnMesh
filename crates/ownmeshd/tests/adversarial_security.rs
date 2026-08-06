//! Adversarial integration tests for OwnMesh local trust-boundary P0 fixes (req 11 / sec-09).
//!
//! Cross-cuts elevated fail-closed, structured→raw_shell reclassification, session principal
//! binding, client revoke on hello/dispatch, broker MAC/capability binding, corrupt session
//! persistence, and non-loopback HTTP issuer rejection.
//!
//! `ownmeshd` is a binary crate, so this harness path-includes the daemon runtime module
//! (no production code changes) and drives it through the public IPC surface.

#[allow(dead_code)]
#[path = "../src/runtime.rs"]
mod runtime;

use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, verify_request, BrokerSecret,
    CapabilityToken, ElevatedCommand, ReplayCache, ELEVATED_CAPABILITY_SCOPE,
};
use ownmesh_config::{validate_control_plane_base_url, OwnMeshPaths};
use ownmesh_ipc::{
    app_error, generate_token, methods, write_token_file, AuthGate, ClientIdentity, ClientOptions,
    Endpoint, IpcBus, IpcClient, IpcError, IpcServer, ServerConfig,
};
use ownmesh_policy::{preset_document, AccessPreset, Decision, PolicyDocument, PolicyRule};
use runtime::{runtime_handler, session_methods, DaemonRuntime};
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::Mutex;

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// In-process daemon matching `daemon::start_test_daemon` (not exported from the bin crate).
async fn start_test_daemon(
    paths: &OwnMeshPaths,
) -> (
    Arc<IpcServer>,
    tokio::task::JoinHandle<()>,
    Endpoint,
    Arc<Mutex<DaemonRuntime>>,
) {
    paths.ensure_layout().unwrap();
    let token = generate_token();
    write_token_file(&paths.runtime_dir, &token).unwrap();
    let runtime = DaemonRuntime::open(paths).expect("runtime");
    let revoked = runtime.revoked_clients_handle();
    let runtime = Arc::new(Mutex::new(runtime));
    let handler = runtime_handler(Arc::clone(&runtime));
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let server = Arc::new(IpcServer::new(
        ServerConfig::new(
            endpoint.clone(),
            AuthGate::new(token),
            "ownmeshd",
            env!("CARGO_PKG_VERSION"),
        )
        .with_revoked_clients(revoked),
        handler,
    ));
    let serve = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = serve.serve().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (server, handle, endpoint, runtime)
}

fn named_client(
    endpoint: Endpoint,
    runtime_dir: impl Into<std::path::PathBuf>,
    name: &str,
) -> IpcClient {
    IpcClient::new(
        endpoint,
        runtime_dir,
        ClientIdentity::new(name, "0.1.0"),
        ClientOptions {
            request_timeout: Duration::from_secs(15),
            max_reconnect_attempts: 3,
            reconnect_base_delay: Duration::from_millis(30),
        },
    )
}

fn assert_remote_code(err: IpcError, expected: i64) {
    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, expected, "message={message}");
        }
        other => panic!("expected Remote({expected}), got {other:?}"),
    }
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

fn signed_broker_request(
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

// ---------------------------------------------------------------------------
// (1) elevated=true fail-closed when broker missing / unreachable / rejecting
// ---------------------------------------------------------------------------

#[tokio::test]
async fn elevated_without_broker_is_fail_closed() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
    let client = named_client(endpoint, paths.runtime_dir.clone(), "ownmesh");

    {
        let mut g = runtime.lock().await;
        g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
    }

    let err = client
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                "args": if cfg!(windows) {
                    vec!["/C", "echo should-not-run"]
                } else {
                    vec!["should-not-run"]
                },
                "kind": "structured",
                "elevated": true,
                "idempotency_key": "adv-elev-no-broker",
            })),
        )
        .await
        .expect_err("elevated without broker must fail closed");

    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INTERNAL);
            let m = message.to_ascii_lowercase();
            assert!(
                m.contains("broker") && (m.contains("unavailable") || m.contains("not configured")),
                "unexpected message: {message}"
            );
            assert!(!m.contains("fallback"), "{message}");
        }
        other => panic!("unexpected: {other:?}"),
    }

    server.request_shutdown();
    let _ = handle.await;
}

#[tokio::test]
async fn elevated_with_unreachable_broker_is_fail_closed() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();

    // Secret present → runtime treats broker as configured, but nothing listens.
    let broker_dir = paths.state_dir.join("broker");
    std::fs::create_dir_all(&broker_dir).unwrap();
    let secret = BrokerSecret::generate();
    std::fs::write(broker_dir.join("broker.secret"), secret.as_bytes()).unwrap();
    // Bind to an unused loopback port that nothing serves.
    std::fs::write(broker_dir.join("broker.addr"), b"127.0.0.1:1").unwrap();

    let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
    let client = named_client(endpoint, paths.runtime_dir.clone(), "ownmesh");

    {
        let mut g = runtime.lock().await;
        g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
    }

    let err = client
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                "args": if cfg!(windows) {
                    vec!["/C", "echo unreachable"]
                } else {
                    vec!["unreachable"]
                },
                "kind": "structured",
                "elevated": true,
                "idempotency_key": "adv-elev-unreachable",
            })),
        )
        .await
        .expect_err("elevated with dead broker must fail closed");

    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INTERNAL);
            let m = message.to_ascii_lowercase();
            assert!(
                m.contains("broker")
                    && (m.contains("unavailable") || m.contains("error") || m.contains("fail")),
                "unexpected message: {message}"
            );
            assert!(!m.contains("fallback"), "{message}");
            // Must not silently succeed via local exec.
            assert!(!m.is_empty());
        }
        other => panic!("unexpected: {other:?}"),
    }

    server.request_shutdown();
    let _ = handle.await;
}

// ---------------------------------------------------------------------------
// (2) structured disguise of shell binary + shell flags → raw_shell policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn structured_shell_disguise_denied_by_raw_shell_policy() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
    let client = named_client(endpoint, paths.runtime_dir.clone(), "ownmesh");

    {
        let mut g = runtime.lock().await;
        g.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("deny only raw_shell".into()),
            rules: vec![
                PolicyRule {
                    id: "deny-raw".into(),
                    decision: Decision::Deny,
                    priority: 100,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("raw_shell".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: Some("raw shell denied".into()),
                },
                PolicyRule {
                    id: "allow-structured".into(),
                    decision: Decision::Allow,
                    priority: 10,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("structured".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: Some("structured allowed".into()),
                },
            ],
        });
    }

    let shells: Vec<(&str, Vec<&str>)> = if cfg!(windows) {
        vec![
            ("cmd.exe", vec!["/C", "echo disguise"]),
            ("cmd", vec!["/c", "echo disguise"]),
            ("powershell.exe", vec!["-Command", "echo disguise"]),
            ("powershell", vec!["-c", "echo disguise"]),
            ("pwsh.exe", vec!["-Command", "Write-Output x"]),
        ]
    } else {
        vec![
            ("/bin/sh", vec!["-c", "echo disguise"]),
            ("sh", vec!["-c", "echo disguise"]),
            ("/bin/bash", vec!["-c", "echo disguise"]),
            ("bash", vec!["-lc", "echo disguise"]),
            ("/bin/zsh", vec!["-c", "echo disguise"]),
        ]
    };

    for (i, (program, args)) in shells.into_iter().enumerate() {
        let result = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "kind": "structured",
                    "program": program,
                    "args": args,
                    "idempotency_key": format!("adv-disguise-{i}"),
                })),
            )
            .await;
        let denied = match result {
            Err(e) => e,
            Ok(v) => panic!("disguised shell {program} must be denied as raw_shell, got Ok({v})"),
        };
        match denied {
            IpcError::Remote { code, message } => {
                assert_eq!(code, app_error::POLICY_DENIED, "program={program}");
                assert!(
                    message.to_ascii_lowercase().contains("denied"),
                    "program={program} message={message}"
                );
            }
            other => panic!("program={program} unexpected: {other:?}"),
        }
    }

    server.request_shutdown();
    let _ = handle.await;
}

// ---------------------------------------------------------------------------
// (3) self-reported principal/from must never bind session identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn self_reported_principal_rejected_on_all_session_ops() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;
    let owner = named_client(endpoint.clone(), paths.runtime_dir.clone(), "chatgpt");
    let attacker = named_client(endpoint.clone(), paths.runtime_dir.clone(), "attacker");

    // Owner opens a real session (authenticated principal binds automatically).
    let opened = owner
        .call(
            session_methods::OPEN,
            Some(json!({ "title": "adv-principal", "kind": "pty" })),
        )
        .await
        .expect("open");
    let sid = opened["id"].as_str().unwrap().to_owned();
    assert_eq!(opened["controller"]["principal_id"], "chatgpt");

    // open with spoofed principal
    let err = owner
        .call(
            session_methods::OPEN,
            Some(json!({
                "title": "spoof-open",
                "principal": "root",
            })),
        )
        .await
        .expect_err("spoofed open principal");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // claim with spoofed principal
    let err = owner
        .call(
            session_methods::CLAIM,
            Some(json!({ "id": sid, "principal": "human" })),
        )
        .await
        .expect_err("spoofed claim");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // attach with spoofed principal
    let err = attacker
        .call(
            session_methods::ATTACH,
            Some(json!({
                "id": sid,
                "principal": "chatgpt",
                "read_only": true,
            })),
        )
        .await
        .expect_err("spoofed attach");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // release with spoofed principal
    let err = attacker
        .call(
            session_methods::RELEASE,
            Some(json!({ "id": sid, "principal": "chatgpt" })),
        )
        .await
        .expect_err("spoofed release");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // give with spoofed from
    let err = attacker
        .call(
            session_methods::GIVE,
            Some(json!({
                "id": sid,
                "from": "chatgpt",
                "to": "attacker",
            })),
        )
        .await
        .expect_err("spoofed give from");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // replay with spoofed principal (and without reader ACL)
    let err = attacker
        .call(
            session_methods::REPLAY,
            Some(json!({
                "id": sid,
                "from_seq": 1,
                "principal": "chatgpt",
            })),
        )
        .await
        .expect_err("spoofed replay");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // write with spoofed principal
    let err = attacker
        .call(
            session_methods::WRITE,
            Some(json!({
                "id": sid,
                "data": "pwn",
                "principal": "chatgpt",
            })),
        )
        .await
        .expect_err("spoofed write");
    assert_remote_code(err, app_error::UNAUTHORIZED);

    // Non-reader/controller ACL (no spoof fields) must still deny stranger ops.
    // session.list is filtered (not an error) and checked separately below.
    for (method, params) in [
        (
            session_methods::ATTACH,
            json!({ "id": sid, "read_only": true }),
        ),
        (session_methods::CLAIM, json!({ "id": sid })),
        (session_methods::SHOW, json!({ "id": sid })),
        (
            session_methods::RESIZE,
            json!({ "id": sid, "cols": 80, "rows": 24 }),
        ),
        (session_methods::CLOSE, json!({ "id": sid })),
        (session_methods::TERMINATE, json!({ "id": sid })),
        (
            session_methods::PUSH_OUTPUT,
            json!({ "id": sid, "data": "x" }),
        ),
        (session_methods::WRITE, json!({ "id": sid, "data": "x" })),
        (session_methods::REPLAY, json!({ "id": sid, "from_seq": 1 })),
    ] {
        let result = attacker.call(method, Some(params)).await;
        let err = match result {
            Err(e) => e,
            Ok(v) => panic!("{method} must deny stranger, got Ok({v})"),
        };
        match err {
            IpcError::Remote { code, .. } => {
                assert!(
                    code == app_error::POLICY_DENIED
                        || code == app_error::CONFLICT
                        || code == app_error::UNAUTHORIZED
                        || code == app_error::INVALID_PARAMS,
                    "{method} unexpected code {code}"
                );
            }
            other => panic!("{method} unexpected: {other:?}"),
        }
    }

    // LIST for stranger returns empty (filtered), never other principals' sessions.
    let listed = attacker
        .call(session_methods::LIST, None)
        .await
        .expect("list ok");
    let sessions = listed["sessions"].as_array().unwrap();
    assert!(
        sessions.iter().all(|s| s["id"] != sid),
        "stranger must not see foreign session: {listed}"
    );

    server.request_shutdown();
    let _ = handle.await;
}

// ---------------------------------------------------------------------------
// (4) revoke effective on hello + live dispatch
// ---------------------------------------------------------------------------

#[tokio::test]
async fn revoke_blocks_hello_and_dispatch() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
    let admin = named_client(endpoint.clone(), paths.runtime_dir.clone(), "ownmesh");
    let agent = named_client(endpoint.clone(), paths.runtime_dir.clone(), "chatgpt");

    {
        let mut g = runtime.lock().await;
        g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
    }

    agent.status().await.expect("pre-revoke status");
    let _ = agent
        .call(methods::POLICY_SHOW, None)
        .await
        .expect("pre-revoke dispatch");

    let revoked = admin
        .call(methods::TOKEN_REVOKE, Some(json!({ "client": "chatgpt" })))
        .await
        .expect("revoke");
    assert_eq!(revoked["revoked"], "chatgpt");
    assert_eq!(revoked["ok"], true);

    // Live connection: dispatch denied.
    let live = agent
        .call(methods::POLICY_SHOW, None)
        .await
        .expect_err("live dispatch after revoke");
    assert_remote_code(live, app_error::TOKEN_REVOKED);

    // Fresh hello denied.
    agent.disconnect().await;
    let hello = agent.status().await.expect_err("hello after revoke");
    assert_remote_code(hello, app_error::TOKEN_REVOKED);

    server.request_shutdown();
    let _ = handle.await;
}

// ---------------------------------------------------------------------------
// (5) broker MAC forge / replay / capability scope & operation mismatch
// ---------------------------------------------------------------------------

#[test]
fn broker_forged_mac_rejected() {
    let secret = BrokerSecret::generate();
    let mut req = signed_broker_request(
        &secret,
        "ownmeshd",
        "op_forge",
        echo_cmd("x"),
        now_unix(),
        60,
    );
    req.mac = "00".repeat(32);
    assert!(verify_request(&secret, &req, now_unix()).is_err());
}

#[test]
fn broker_replayed_nonce_rejected() {
    let secret = BrokerSecret::generate();
    let req = signed_broker_request(
        &secret,
        "ownmeshd",
        "op_replay",
        echo_cmd("once"),
        now_unix(),
        60,
    );
    verify_request(&secret, &req, now_unix()).expect("first verify ok");
    let mut replay = ReplayCache::new();
    replay.check_and_insert(&req).expect("first insert");
    let err = replay.check_and_insert(&req).expect_err("replay");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(msg.contains("replay"), "{msg}");
}

#[test]
fn broker_missing_capability_rejected() {
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
    let err = verify_request(&secret, &req, now_unix()).expect_err("missing cap");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("token") || msg.contains("invalid") || msg.contains("capability"),
        "{msg}"
    );
}

#[test]
fn broker_capability_scope_mismatch_rejected() {
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
fn broker_capability_operation_mismatch_rejected() {
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
fn broker_tampered_args_invalidate_mac() {
    let secret = BrokerSecret::generate();
    let mut req = signed_broker_request(
        &secret,
        "ownmeshd",
        "op_tamper",
        echo_cmd("clean"),
        now_unix(),
        60,
    );
    req.command.args.push("--evil".into());
    assert!(verify_request(&secret, &req, now_unix()).is_err());
}

// ---------------------------------------------------------------------------
// (6) corrupt sessions.json → explicit open failure (no silent empty)
// ---------------------------------------------------------------------------

#[test]
fn corrupt_sessions_json_fails_runtime_open() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let sessions_path = paths.state_dir.join("sessions").join("sessions.json");
    std::fs::create_dir_all(sessions_path.parent().unwrap()).unwrap();
    std::fs::write(&sessions_path, b"{not-valid-json[[[").expect("write corrupt sessions");

    let err = match DaemonRuntime::open(&paths) {
        Ok(_) => panic!("corrupt sessions.json must fail open"),
        Err(e) => e,
    };
    assert!(
        err.contains("failed to load sessions") || err.to_ascii_lowercase().contains("session"),
        "err={err}"
    );
}

#[test]
fn corrupt_revoked_clients_state_fails_runtime_open() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let revoked_path = paths.state_dir.join("revoked-clients.json");
    std::fs::write(&revoked_path, b"{not-a-client-list").expect("write corrupt revocations");

    let err = match DaemonRuntime::open(&paths) {
        Ok(_) => panic!("corrupt revocation state must fail open"),
        Err(e) => e,
    };
    assert!(
        err.to_ascii_lowercase().contains("revoked")
            && err.to_ascii_lowercase().contains("corrupt"),
        "err={err}"
    );
}

// ---------------------------------------------------------------------------
// (7) non-loopback HTTP issuer rejected
// ---------------------------------------------------------------------------

#[test]
fn non_loopback_http_issuer_rejected() {
    for bad in [
        "http://example.test",
        "http://example.test/oauth",
        "http://192.168.1.10",
        "http://10.0.0.1:443",
        "http://8.8.8.8:80",
        "http://[2001:db8::1]:8080",
    ] {
        let err = validate_control_plane_base_url(bad).expect_err(&format!("must reject {bad}"));
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("non-loopback")
                || msg.contains("https")
                || msg.contains("loopback")
                || msg.contains("http"),
            "bad={bad} msg={msg}"
        );
    }

    // Positive controls: loopback http + any https still accepted.
    for ok in [
        "http://127.0.0.1:8750",
        "http://localhost:9",
        "http://[::1]:8080",
        "https://cp.example.test",
    ] {
        validate_control_plane_base_url(ok).unwrap_or_else(|e| panic!("ok={ok} err={e}"));
    }
}
