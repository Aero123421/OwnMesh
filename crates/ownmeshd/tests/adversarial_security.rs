//! Adversarial integration tests for OwnMesh local trust-boundary P0 fixes (req 11 / sec-09).
//!
//! Cross-cuts elevated fail-closed, structured→raw_shell reclassification, session principal
//! binding, client revoke on hello/dispatch, broker MAC/capability binding, corrupt session
//! persistence, and non-loopback HTTP issuer rejection.
//!
//! `ownmeshd` is a binary crate, so this harness path-includes the daemon runtime module
//! (no production code changes) and drives it through the public IPC surface.

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

#[allow(dead_code)]
#[path = "../src/runtime.rs"]
mod runtime;

use ownmesh_broker_client::{
    build_request, build_request_with_capability, compute_mac, verify_request, BrokerSecret,
    CapabilitySigningKey, CapabilityToken, ElevatedCommand, PeerBind, ReplayCache,
    ELEVATED_CAPABILITY_SCOPE,
};
use ownmesh_config::{validate_control_plane_base_url, OwnMeshPaths};
use ownmesh_ipc::{
    app_error, current_os_user_id, methods, AuthGate, ClientIdentity, ClientOptions, Endpoint,
    IpcBus, IpcClient, IpcError, IpcServer, ServerConfig,
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
    let legacy = paths.runtime_dir.join(ownmesh_ipc::AUTH_TOKEN_FILE_NAME);
    let _ = std::fs::remove_file(legacy);
    let runtime = DaemonRuntime::open(paths).expect("runtime");
    let revoked = runtime.revoked_clients_handle();
    let runtime = Arc::new(Mutex::new(runtime));
    let handler = runtime_handler(Arc::clone(&runtime));
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let server = Arc::new(IpcServer::new(
        ServerConfig::new(
            endpoint.clone(),
            AuthGate::local_user(),
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
    named_client_with_cred(endpoint, runtime_dir, name, None)
}

fn named_client_with_cred(
    endpoint: Endpoint,
    runtime_dir: impl Into<std::path::PathBuf>,
    name: &str,
    credential: Option<String>,
) -> IpcClient {
    let client = IpcClient::new(
        endpoint,
        runtime_dir,
        ClientIdentity::new(name, "0.1.0"),
        ClientOptions {
            request_timeout: Duration::from_secs(15),
            max_reconnect_attempts: 3,
            reconnect_base_delay: Duration::from_millis(30),
        },
    );
    match credential {
        Some(c) => client.with_client_credential(c),
        None => client,
    }
}

/// Direct runtime dispatch as an OS-shaped human principal.
///
/// Ordinary IPC human-operator methods are fail-closed (no presence proof). Tests that
/// exercise approval *execution* mechanics (pins, grants, TOCTOU) call the runtime handler
/// directly — never via a forgeable same-UID uncredentialed IPC socket.
async fn direct_human_approve(
    runtime: &Arc<Mutex<DaemonRuntime>>,
    approval_id: &str,
    temporary_grant: bool,
    grant_seconds: Option<i64>,
) -> Result<serde_json::Value, IpcError> {
    let human = ClientIdentity::new(format!("user:{}", current_os_user_id()), "0.1.0");
    let mut params = json!({
        "id": approval_id,
        "temporary_grant": temporary_grant,
    });
    if let Some(secs) = grant_seconds {
        params["grant_seconds"] = json!(secs);
    }
    let mut guard = runtime.lock().await;
    guard
        .dispatch(methods::APPROVAL_APPROVE, Some(params), &human)
        .await
}

async fn direct_human_token_revoke(
    runtime: &Arc<Mutex<DaemonRuntime>>,
    principal: &str,
) -> Result<serde_json::Value, IpcError> {
    let human = ClientIdentity::new(format!("user:{}", current_os_user_id()), "0.1.0");
    let mut guard = runtime.lock().await;
    guard
        .dispatch(
            methods::TOKEN_REVOKE,
            Some(json!({ "principal": principal })),
            &human,
        )
        .await
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

fn test_peer() -> PeerBind {
    PeerBind::new(4242, 1000, "ownmeshd")
}

fn signed_broker_request(
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

// ---------------------------------------------------------------------------
// (1) elevated=true is production-unsupported (broker artifacts irrelevant)
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
        .expect_err("elevated must be production unsupported");

    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INTERNAL);
            let m = message.to_ascii_lowercase();
            assert!(
                m.contains("unsupported")
                    && (m.contains("elevated") || m.contains("broker") || m.contains("mint")),
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
async fn elevated_with_broker_artifacts_is_still_unsupported() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();

    // Residual secrets/records must not enable elevated exec.
    let broker_dir = paths.state_dir.join("broker");
    std::fs::create_dir_all(&broker_dir).unwrap();
    let secret = BrokerSecret::generate();
    std::fs::write(broker_dir.join("broker.secret"), secret.as_bytes()).unwrap();
    std::fs::write(broker_dir.join("broker.addr"), b"127.0.0.1:1").unwrap();
    std::fs::write(
        broker_dir.join("broker-install.json"),
        serde_json::to_string_pretty(&serde_json::json!({
            "installed": true,
            "support": "supported",
            "endpoint": "unix:/tmp/forged.sock",
            "endpoint_kind": "unix_socket",
            "secret_file": broker_dir.join("broker.secret").display().to_string(),
            "signing_key_file": broker_dir.join("private").join("broker.cap.signing").display().to_string(),
            "verify_key_file": broker_dir.join("broker.cap.verify").display().to_string(),
            "trusted_executable": "/bin/true",
            "socket_owner_uid": 0,
            "socket_group_gid": 0,
            "socket_mode": 384,
            "allowed_uids": [0],
            "notes": ["forged"],
            "installed_at_unix": 1,
            "unit_path": null
        }))
        .unwrap(),
    )
    .unwrap();

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
                "idempotency_key": "adv-elev-artifacts",
            })),
        )
        .await
        .expect_err("elevated with broker artifacts must still be unsupported");

    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INTERNAL);
            let m = message.to_ascii_lowercase();
            assert!(m.contains("unsupported"), "unexpected message: {message}");
            assert!(!m.contains("fallback"), "{message}");
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
            ("env", vec!["pwsh.exe", "-Command", "Write-Output x"]),
            ("env", vec!["-S", "powershell -Command echo-disguise"]),
        ]
    } else {
        vec![
            ("/bin/sh", vec!["-c", "echo disguise"]),
            ("sh", vec!["-c", "echo disguise"]),
            ("/bin/bash", vec!["-c", "echo disguise"]),
            ("bash", vec!["-lc", "echo disguise"]),
            ("/bin/zsh", vec!["-c", "echo disguise"]),
            ("env", vec!["bash", "-lc", "echo disguise"]),
            ("/usr/bin/env", vec!["-S", "sh -c 'echo disguise'"]),
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let alias = dir.path().join("apparently-structured");
        symlink("/bin/sh", &alias).expect("create shell alias");
        let denied = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "kind": "structured",
                    "program": alias,
                    "args": ["--version"],
                    "idempotency_key": "adv-symlink-shell",
                })),
            )
            .await
            .expect_err("resolved shell symlink must be denied as raw_shell");
        assert_remote_code(denied, app_error::POLICY_DENIED);
    }

    server.request_shutdown();
    let _ = handle.await;
}

#[cfg(unix)]
#[tokio::test]
async fn approval_delay_cannot_swap_structured_symlink_to_shell() {
    use std::os::unix::fs::symlink;

    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
    let client = named_client(endpoint, paths.runtime_dir.clone(), "ownmesh");
    let alias = dir.path().join("mutable-command");
    let shell_marker = dir.path().join("shell-must-not-run");
    symlink("/bin/echo", &alias).unwrap();

    {
        let mut guard = runtime.lock().await;
        guard.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("ask structured, deny raw".into()),
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
                    description: None,
                },
                PolicyRule {
                    id: "ask-structured".into(),
                    decision: Decision::Ask,
                    priority: 10,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("structured".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: None,
                },
            ],
        });
    }

    let pending = client
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": alias,
                "args": ["-c", format!("touch '{}'", shell_marker.display())],
                "idempotency_key": "approval-symlink-swap",
            })),
        )
        .await
        .expect("enqueue structured command");
    let approval_id = pending["approval_id"].as_str().unwrap().to_owned();

    std::fs::remove_file(&alias).unwrap();
    symlink("/bin/sh", &alias).unwrap();
    // IPC approve is fail-closed; exercise pin revalidation via direct runtime dispatch.
    let approved = direct_human_approve(&runtime, &approval_id, false, None)
        .await
        .expect("approval must execute the safely pinned canonical echo target");
    assert_eq!(approved["approval_required"], false);
    assert!(
        !shell_marker.exists(),
        "the swapped shell alias must never be reopened or executed"
    );

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
    let owner_cred = server.issue_client_credential("chatgpt").unwrap();
    let attacker_cred = server.issue_client_credential("attacker").unwrap();
    let owner = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "label-chatgpt",
        Some(owner_cred),
    );
    let attacker = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "label-attacker",
        Some(attacker_cred),
    );

    // Owner opens a real session (authenticated principal binds automatically).
    let opened = owner
        .call(
            session_methods::OPEN,
            Some(json!({ "title": "adv-principal", "kind": "pty" })),
        )
        .await
        .expect("open");
    let sid = opened["id"].as_str().unwrap().to_owned();
    assert_eq!(opened["controller"]["principal_id"], "client:chatgpt");

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
    let agent_cred = server.issue_client_credential("Agent-ChatGPT").unwrap();
    let agent = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "label-chatgpt",
        Some(agent_cred.clone()),
    );

    {
        let mut g = runtime.lock().await;
        g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
    }

    agent.status().await.expect("pre-revoke status");
    let _ = agent
        .call(methods::POLICY_SHOW, None)
        .await
        .expect("pre-revoke dispatch");

    // Revoke through a case/whitespace alias. Ordinary IPC token.revoke is fail-closed;
    // exercise canonicalization via direct runtime dispatch.
    let _ = admin;
    let revoked = direct_human_token_revoke(&runtime, " CLIENT:AGENT-CHATGPT ")
        .await
        .expect("revoke");
    assert_eq!(revoked["revoked"], "client:agent-chatgpt");
    assert_eq!(revoked["ok"], true);
    let persisted = std::fs::read_to_string(paths.state_dir.join("revoked-clients.json")).unwrap();
    assert!(persisted.contains("client:agent-chatgpt"), "{persisted}");
    assert!(!persisted.contains("AGENT"), "{persisted}");

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

    // Alias bypass: same credential + different self-reported HELLO name still revoked.
    let alias = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "ChatGPT ",
        Some(agent_cred),
    );
    let alias_err = alias.status().await.expect_err("alias hello after revoke");
    match alias_err {
        IpcError::Remote { code, .. } => assert_eq!(code, app_error::TOKEN_REVOKED),
        IpcError::Unauthorized(_) => {}
        other => panic!("unexpected alias err: {other:?}"),
    }

    server.request_shutdown();
    let _ = handle.await;
}

/// Attack E2E: leftover daemon.token file must not authenticate, and startup cleanup removes it.
#[tokio::test]
async fn attack_legacy_daemon_token_file_cannot_authenticate() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();

    let legacy_path = paths.runtime_dir.join(ownmesh_ipc::AUTH_TOKEN_FILE_NAME);
    let stolen = "preexisting-shared-daemon-token";
    std::fs::write(&legacy_path, format!("{stolen}\n")).unwrap();
    assert!(legacy_path.exists());

    let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;
    // Test daemon mirrors production start: legacy token file is deleted.
    assert!(
        !legacy_path.exists(),
        "legacy daemon.token must be removed at daemon start"
    );

    let evil = IpcClient::new(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        ClientIdentity::new("admin", "0.0.0"),
        ClientOptions {
            max_reconnect_attempts: 0,
            request_timeout: Duration::from_secs(5),
            reconnect_base_delay: Duration::from_millis(20),
        },
    )
    .with_legacy_shared_token(stolen);
    let err = evil
        .status()
        .await
        .expect_err("shared daemon.token path must stay disabled");
    assert!(
        matches!(
            err,
            IpcError::Unauthorized(_) | IpcError::Remote { .. } | IpcError::Disconnected(_)
        ),
        "{err:?}"
    );

    // OS-peer client without shared token still works.
    let honest = named_client(endpoint, paths.runtime_dir.clone(), "ownmesh");
    honest.status().await.expect("os peer auth still works");

    server.request_shutdown();
    let _ = handle.await;
}

#[tokio::test]
async fn legacy_process_scoped_revoke_rpc_blocks_stable_user_principal() {
    let stable = format!("user:{}", current_os_user_id());
    assert_ne!(stable, "user:");

    for suffix in [":exe:C:\\OwnMesh\\ownmesh.exe", ":pid:424242"] {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
        let client = named_client(
            endpoint,
            paths.runtime_dir.clone(),
            "legacy-revoke-attacker",
        );
        client.status().await.expect("pre-revoke status");

        let legacy = format!("{stable}{suffix}");
        // IPC token.revoke is fail-closed; canonicalize legacy keys via direct dispatch.
        let revoked = direct_human_token_revoke(&runtime, &legacy)
            .await
            .expect("legacy revoke RPC");
        assert_eq!(revoked["revoked"], stable);

        let persisted = std::fs::read_to_string(paths.state_dir.join("revoked-clients.json"))
            .expect("persisted revocations");
        assert_eq!(
            serde_json::from_str::<Vec<String>>(&persisted).unwrap(),
            vec![stable.clone()]
        );

        let denied = client
            .status()
            .await
            .expect_err("stable user must remain revoked after legacy-key RPC");
        assert_remote_code(denied, app_error::TOKEN_REVOKED);

        server.request_shutdown();
        let _ = handle.await;
    }
}

/// Attack E2E: mid-connection re-HELLO cannot switch principal or dodge revocation.
#[tokio::test]
async fn attack_rehello_cannot_switch_principal_or_bypass_revoke() {
    use ownmesh_ipc::connect;
    use ownmesh_ipc::{
        methods as ipc_methods, read_frame, write_frame, HelloParams, RpcRequest, RpcResponse,
    };

    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
    let admin = named_client(endpoint.clone(), paths.runtime_dir.clone(), "ownmesh");
    let agent_cred = server.issue_client_credential("chatgpt").unwrap();
    let other_cred = server.issue_client_credential("other-agent").unwrap();

    let mut conn = connect(&endpoint).await.expect("connect");
    let hello = RpcRequest::new(
        ipc_methods::HELLO,
        Some(json!(HelloParams {
            token: String::new(),
            client_name: "label-chatgpt".into(),
            owner: Some("spoofed-owner".into()),
            client_version: Some("1.0.0".into()),
            client_credential: Some(agent_cred.clone()),
        })),
    );
    write_frame(&mut conn, &hello.to_bytes().unwrap())
        .await
        .unwrap();
    let first = RpcResponse::from_bytes(&read_frame(&mut conn).await.unwrap()).unwrap();
    let first_val = first.into_result().expect("hello");
    assert_eq!(first_val["principal"], "client:chatgpt");

    // Revoke the bound principal while the connection is live (direct dispatch;
    // ordinary IPC token.revoke is fail-closed without presence proof).
    let _ = admin;
    let revoked = direct_human_token_revoke(&runtime, "client:chatgpt")
        .await
        .expect("revoke");
    assert_eq!(revoked["revoked"], "client:chatgpt");

    // Attempt to re-HELLO as a different principal on the same connection.
    let rehello = RpcRequest::new(
        ipc_methods::HELLO,
        Some(json!(HelloParams {
            token: String::new(),
            client_name: "other-agent".into(),
            owner: Some("spoofed-other-owner".into()),
            client_version: Some("9.9.9".into()),
            client_credential: Some(other_cred),
        })),
    );
    write_frame(&mut conn, &rehello.to_bytes().unwrap())
        .await
        .unwrap();
    let second = RpcResponse::from_bytes(&read_frame(&mut conn).await.unwrap()).unwrap();
    match second.into_result() {
        Err(IpcError::Remote { code, message }) => {
            assert_eq!(code, app_error::UNAUTHORIZED);
            assert!(
                message.to_ascii_lowercase().contains("already bound"),
                "{message}"
            );
        }
        other => panic!("re-HELLO must not rebind, got {other:?}"),
    }

    // Dispatch under the original (now revoked) principal must still fail closed.
    let status = RpcRequest::new(ipc_methods::STATUS, None);
    write_frame(&mut conn, &status.to_bytes().unwrap())
        .await
        .unwrap();
    let denied = RpcResponse::from_bytes(&read_frame(&mut conn).await.unwrap()).unwrap();
    match denied.into_result() {
        Err(IpcError::Remote { code, .. }) => assert_eq!(code, app_error::TOKEN_REVOKED),
        other => panic!("expected TOKEN_REVOKED after failed rebind, got {other:?}"),
    }

    server.request_shutdown();
    let _ = handle.await;
}

/// Attack E2E: shared token + self-reported name cannot mint a foreign principal.
#[tokio::test]
async fn attack_shared_token_and_name_spoof_cannot_impersonate() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;

    // Victim principal exists as a server-managed credential.
    let victim_cred = server.issue_client_credential("victim-admin").unwrap();
    let victim = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "whatever",
        Some(victim_cred),
    );
    let handler_probe: std::sync::Arc<
        dyn Fn(
                String,
                Option<serde_json::Value>,
                ClientIdentity,
            ) -> std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<serde_json::Value, IpcError>> + Send>,
            > + Send
            + Sync,
    > = std::sync::Arc::new(|_m, _p, client| {
        Box::pin(async move { Ok(json!({ "principal": client.client_name })) })
    });
    let _ = handler_probe; // identity checked via session open instead

    let opened = victim
        .call(
            session_methods::OPEN,
            Some(json!({ "title": "victim-session" })),
        )
        .await
        .expect("victim open");
    assert_eq!(opened["controller"]["principal_id"], "client:victim-admin");

    // Attacker presents a shared token + claims victim name — must fail closed.
    let spoof = IpcClient::new(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        ClientIdentity::new("victim-admin", "0.0.0"),
        ClientOptions {
            max_reconnect_attempts: 0,
            ..ClientOptions::default()
        },
    )
    .with_legacy_shared_token("stolen-daemon-token");
    let err = spoof.status().await.expect_err("shared token must fail");
    assert!(
        matches!(
            err,
            IpcError::Unauthorized(_) | IpcError::Remote { .. } | IpcError::Disconnected(_)
        ),
        "{err:?}"
    );

    // Attacker without credential but claiming victim-admin gets OS principal, not victim.
    let name_only = IpcClient::new(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        ClientIdentity::new("victim-admin", "0.0.0"),
        ClientOptions {
            max_reconnect_attempts: 0,
            request_timeout: Duration::from_secs(5),
            reconnect_base_delay: Duration::from_millis(20),
        },
    );
    // Can connect (OS peer ok) but cannot act as victim-admin on victim session.
    name_only.status().await.expect("os peer auth ok");
    let denied = name_only
        .call(session_methods::SHOW, Some(json!({ "id": opened["id"] })))
        .await
        .expect_err("name spoof must not unlock victim session");
    match denied {
        IpcError::Remote { code, .. } => {
            assert!(
                code == app_error::POLICY_DENIED || code == app_error::UNAUTHORIZED,
                "code={code}"
            );
        }
        other => panic!("{other:?}"),
    }

    server.request_shutdown();
    let _ = handle.await;
}

// ---------------------------------------------------------------------------
// (5) broker MAC forge / replay / capability scope & operation mismatch
// ---------------------------------------------------------------------------

#[test]
fn broker_forged_mac_rejected() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    let peer = test_peer();
    let mut req = signed_broker_request(
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
}

#[test]
fn broker_replayed_nonce_rejected() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    let peer = test_peer();
    let req = signed_broker_request(
        &secret,
        &sk,
        &peer,
        "ownmeshd",
        "op_replay",
        echo_cmd("once"),
        now_unix(),
        60,
    );
    verify_request(&secret, &vk, &req, &peer, now_unix()).expect("first verify ok");
    let mut replay = ReplayCache::new();
    replay.check_and_insert(&req).expect("first insert");
    let err = replay.check_and_insert(&req).expect_err("replay");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(msg.contains("replay"), "{msg}");
}

#[test]
fn broker_missing_capability_rejected() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    let peer = test_peer();
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
    let err = verify_request(&secret, &vk, &req, &peer, now_unix()).expect_err("missing cap");
    let msg = err.to_string().to_ascii_lowercase();
    assert!(
        msg.contains("token") || msg.contains("invalid") || msg.contains("capability"),
        "{msg}"
    );
    let _ = sk;
}

#[test]
fn broker_capability_scope_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
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
fn broker_capability_operation_mismatch_rejected() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
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
fn broker_tampered_args_invalidate_mac() {
    let secret = BrokerSecret::generate();
    let sk = CapabilitySigningKey::generate();
    let vk = sk.verify_key();
    let peer = test_peer();
    let mut req = signed_broker_request(
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

/// Production daemon-start fixture: a leftover `config_written` journal (new config +
/// old strong policy) must be recovered **before** policy is loaded into the runtime.
#[test]
fn production_daemon_start_recovers_config_written_journal_before_policy_use() {
    use ownmesh_config::{
        atomic_write, save_config_and_policy_transactional, ConfigPolicyTransaction, OwnMeshConfig,
        PolicyFile,
    };

    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();

    let old_cfg = OwnMeshConfig {
        active_instance: Some("stable".into()),
        instances: vec![ownmesh_config::InstanceConfig {
            id: "stable".into(),
            base_url: "https://stable.example.test".into(),
            display_name: None,
        }],
        ..OwnMeshConfig::default()
    };
    let old_policy = PolicyFile {
        schema_version: 1,
        preset: Some("full_access".into()),
    };
    save_config_and_policy_transactional(&paths, &old_cfg, &old_policy).unwrap();

    let new_cfg = OwnMeshConfig {
        active_instance: Some("half-applied".into()),
        instances: vec![ownmesh_config::InstanceConfig {
            id: "half-applied".into(),
            base_url: "https://half.example.test".into(),
            display_name: None,
        }],
        ..OwnMeshConfig::default()
    };
    let new_policy = PolicyFile {
        schema_version: 1,
        preset: Some("workspace_only".into()),
    };
    // Render via a successful transactional write to a sibling layout, then copy bytes.
    let render_dir = tempdir().unwrap();
    let render_paths = OwnMeshPaths::for_base(render_dir.path());
    save_config_and_policy_transactional(&render_paths, &new_cfg, &new_policy).unwrap();
    let new_config = std::fs::read_to_string(render_paths.config_file()).unwrap();
    let new_policy_text = std::fs::read_to_string(render_paths.policy_file()).unwrap();
    let old_config = std::fs::read_to_string(paths.config_file()).unwrap();
    let old_policy_text = std::fs::read_to_string(paths.policy_file()).unwrap();

    let tx = ConfigPolicyTransaction {
        schema_version: 1,
        phase: "config_written".into(),
        old_config: Some(old_config),
        old_policy: Some(old_policy_text.clone()),
        new_config: new_config.clone(),
        new_policy: new_policy_text,
    };
    let tx_path = paths.config_dir.join("setup-config-policy.txn.json");
    let rendered = serde_json::to_vec_pretty(&tx).unwrap();
    atomic_write(&tx_path, &rendered).unwrap();
    atomic_write(&paths.config_file(), new_config.as_bytes()).unwrap();
    // Policy intentionally left as old strong full_access — the H6 hazard window.

    let runtime = DaemonRuntime::open(&paths).expect("daemon open must recover then start");
    drop(runtime);

    assert!(
        !tx_path.exists(),
        "journal must be cleared after successful recovery at daemon start"
    );
    let cfg_raw = std::fs::read_to_string(paths.config_file()).unwrap();
    assert!(
        cfg_raw.contains("stable") && !cfg_raw.contains("half-applied"),
        "config must be restored to pre-transaction pair before policy use: {cfg_raw}"
    );
    let pol_raw = std::fs::read_to_string(paths.policy_file()).unwrap();
    assert_eq!(pol_raw, old_policy_text);
    assert!(
        pol_raw.contains("full_access"),
        "recovered policy must be the old pair, not a silent default"
    );
}

/// When rollback cannot complete, daemon start must fail closed and preserve the journal.
#[test]
fn production_daemon_start_preserves_journal_when_recovery_rollback_fails() {
    use ownmesh_config::{atomic_write, ConfigPolicyTransaction};

    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();

    let old_cfg_text = "schema_version = 1\nlang = \"en-US\"\n";
    let old_pol_text = "schema_version = 1\npreset = \"full_access\"\n";
    let new_cfg_text = "schema_version = 1\nlang = \"ja-JP\"\n";
    let new_pol_text = "schema_version = 1\npreset = \"recommended\"\n";
    atomic_write(&paths.config_file(), new_cfg_text.as_bytes()).unwrap();
    atomic_write(&paths.policy_file(), old_pol_text.as_bytes()).unwrap();

    let tx = ConfigPolicyTransaction {
        schema_version: 1,
        phase: "config_written".into(),
        old_config: Some(old_cfg_text.into()),
        old_policy: Some(old_pol_text.into()),
        new_config: new_cfg_text.into(),
        new_policy: new_pol_text.into(),
    };
    let tx_path = paths.config_dir.join("setup-config-policy.txn.json");
    atomic_write(&tx_path, &serde_json::to_vec_pretty(&tx).unwrap()).unwrap();

    // Fault-inject restore target: config path becomes a non-empty directory.
    std::fs::remove_file(paths.config_file()).unwrap();
    std::fs::create_dir(paths.config_file()).unwrap();
    std::fs::write(paths.config_file().join("blocker"), b"1").unwrap();

    let err = match DaemonRuntime::open(&paths) {
        Ok(_) => panic!("daemon must refuse start when recovery cannot complete"),
        Err(e) => e,
    };
    assert!(
        err.to_ascii_lowercase().contains("policy")
            || err.to_ascii_lowercase().contains("journal")
            || err.to_ascii_lowercase().contains("recover")
            || err.to_ascii_lowercase().contains("rollback"),
        "err={err}"
    );
    assert!(
        tx_path.is_file(),
        "journal must be preserved after failed recovery at daemon start"
    );
}

#[test]
fn revoked_state_aliases_are_canonicalized_on_load_and_rewritten() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let revoked_path = paths.state_dir.join("revoked-clients.json");
    std::fs::write(
        &revoked_path,
        br#"[
            " AGENT\\Path\\..\\ChatGPT ",
            "agent/chatgpt",
            " USER : ALICE : EXE : C:\\OwnMesh\\ownmesh.exe ",
            "user:alice:pid:12345",
            "user:alice:exe:c:/crafted:pid:99"
        ]"#,
    )
    .unwrap();

    let runtime = DaemonRuntime::open(&paths).expect("canonicalize legacy revocations");
    let guard = runtime.revoked_clients_handle();
    let guard = guard.read().unwrap();
    assert_eq!(guard.len(), 2);
    assert!(guard.contains("agent/chatgpt"));
    assert!(guard.contains("user:alice"));
    drop(guard);

    let rewritten = std::fs::read_to_string(revoked_path).unwrap();
    assert_eq!(
        serde_json::from_str::<Vec<String>>(&rewritten).unwrap(),
        vec!["agent/chatgpt", "user:alice"]
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

#[cfg(target_os = "linux")]
#[test]
fn broker_install_loader_ignores_even_trusted_looking_installed_true_records() {
    use std::os::unix::fs::PermissionsExt;

    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let euid = status
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .and_then(|line| line.split_whitespace().nth(2))
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap();
    if euid != 0 {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        assert!(runtime::load_broker_client(&paths).0.is_none());
        return;
    }

    let base = std::path::PathBuf::from("/run").join(format!(
        "ownmeshd-loader-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    let paths = OwnMeshPaths {
        config_dir: base.join("config"),
        state_dir: base.join("state"),
        runtime_dir: base.join("runtime"),
        cache_dir: base.join("cache"),
    };
    let broker = paths.state_dir.join("broker");
    let private = broker.join("private");
    let socket_parent = broker.join("runtime");
    for dir in [&base, &paths.state_dir, &broker, &private, &socket_parent] {
        std::fs::create_dir(dir).unwrap();
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o711)).unwrap();

    let secret_path = broker.join("broker.secret");
    let signing_path = private.join("broker.cap.signing");
    let verify_path = broker.join("broker.cap.verify");
    let signing = CapabilitySigningKey::generate();
    std::fs::write(&secret_path, [7_u8; 32]).unwrap();
    std::fs::write(&signing_path, signing.to_bytes()).unwrap();
    std::fs::write(&verify_path, signing.verify_key().to_bytes()).unwrap();
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&signing_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&verify_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    let trusted_executable = std::fs::canonicalize("/usr/bin/true").unwrap();
    let socket_path = socket_parent.join("ownmesh-broker.sock");
    let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let record = serde_json::json!({
        "installed": true,
        "support": "supported",
        "endpoint": socket_path.display().to_string(),
        "endpoint_kind": "unix_socket",
        "secret_file": secret_path.display().to_string(),
        "signing_key_file": signing_path.display().to_string(),
        "verify_key_file": verify_path.display().to_string(),
        "trusted_executable": trusted_executable.display().to_string(),
        "socket_owner_uid": 0,
        "socket_group_gid": 0,
        "socket_mode": 0o600,
        "allowed_uids": [0]
    });
    let install_path = broker.join("broker-install.json");
    std::fs::write(&install_path, serde_json::to_vec_pretty(&record).unwrap()).unwrap();
    std::fs::set_permissions(&install_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(
        runtime::load_broker_client(&paths).0.is_none()
            && runtime::load_broker_client(&paths).1.is_none(),
        "production loader must ignore handwritten installed=true records"
    );

    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o640)).unwrap();
    assert!(runtime::load_broker_client(&paths).0.is_none());
    std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o733)).unwrap();
    assert!(
        runtime::load_broker_client(&paths).0.is_none(),
        "writable signing-key parent must be rejected"
    );
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o711)).unwrap();

    std::fs::remove_file(&verify_path).unwrap();
    std::os::unix::fs::symlink("/etc/passwd", &verify_path).unwrap();
    assert!(
        runtime::load_broker_client(&paths).0.is_none(),
        "verify-key symlink must be rejected"
    );
    std::fs::remove_file(&verify_path).unwrap();
    std::fs::write(&verify_path, signing.verify_key().to_bytes()).unwrap();
    std::fs::set_permissions(&verify_path, std::fs::Permissions::from_mode(0o644)).unwrap();

    std::fs::remove_file(&signing_path).unwrap();
    std::fs::hard_link(&secret_path, &signing_path).unwrap();
    assert!(
        runtime::load_broker_client(&paths).0.is_none(),
        "secret/signing hard-link alias must be rejected"
    );
    std::fs::remove_file(&signing_path).unwrap();
    std::fs::write(&signing_path, signing.to_bytes()).unwrap();
    std::fs::set_permissions(&signing_path, std::fs::Permissions::from_mode(0o600)).unwrap();

    drop(listener);
    std::fs::remove_file(&socket_path).unwrap();
    assert!(
        runtime::load_broker_client(&paths).0.is_none(),
        "missing socket must never be trusted"
    );
    std::fs::write(&socket_path, b"/etc/passwd-like leaf").unwrap();
    std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(
        runtime::load_broker_client(&paths).0.is_none(),
        "regular endpoint leaf must never be trusted"
    );

    std::fs::remove_dir_all(base).unwrap();
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

// ---------------------------------------------------------------------------
// (8) production registry: no credentialed self-approval / management bypass
// ---------------------------------------------------------------------------

/// Production-shaped daemon: registry-backed AuthGate (strict uncredentialed).
async fn start_production_test_daemon(
    paths: &OwnMeshPaths,
) -> (
    Arc<IpcServer>,
    tokio::task::JoinHandle<()>,
    Endpoint,
    Arc<Mutex<DaemonRuntime>>,
) {
    paths.ensure_layout().unwrap();
    let legacy = paths.runtime_dir.join(ownmesh_ipc::AUTH_TOKEN_FILE_NAME);
    let _ = std::fs::remove_file(legacy);
    let runtime = DaemonRuntime::open(paths).expect("runtime");
    let revoked = runtime.revoked_clients_handle();
    let runtime = Arc::new(Mutex::new(runtime));
    let handler = runtime_handler(Arc::clone(&runtime));
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let user_id = current_os_user_id();
    let (auth, _) = AuthGate::for_user(&user_id)
        .with_daemon_registry(&paths.state_dir)
        .expect("registry");
    let server = Arc::new(IpcServer::new(
        ServerConfig::new(
            endpoint.clone(),
            auth,
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

fn assert_unauthorized(err: IpcError) {
    match err {
        IpcError::Unauthorized(_) => {}
        IpcError::Remote { code, .. } if code == app_error::UNAUTHORIZED => {}
        other => panic!("expected unauthorized, got {other:?}"),
    }
}

#[tokio::test]
async fn production_agent_cannot_self_approve_or_use_management_for_human_ops() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_production_test_daemon(&paths).await;

    let management_secret =
        ownmesh_ipc::read_management_credential(&paths.state_dir).expect("management delivery");
    let management = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "mgmt-label",
        Some(management_secret),
    );
    let provisioned: ownmesh_ipc::CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(json!({ "client_id": "agent-chatgpt" })),
            )
            .await
            .expect("provision agent"),
    )
    .unwrap();
    assert_eq!(provisioned.principal, "client:agent-chatgpt");

    let agent = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "agent-label",
        Some(provisioned.credential),
    );
    // Second same-UID unauthenticated IPC connection (forgeable "user:<uid>").
    let forged_human = named_client(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "forged-human-presence",
    );

    {
        let mut guard = runtime.lock().await;
        guard.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("ask writes".into()),
            rules: vec![PolicyRule {
                id: "ask-write".into(),
                decision: Decision::Ask,
                priority: 10,
                capability: "filesystem.write".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                description: None,
            }],
        });
    }

    let pending = agent
        .call(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "agent-write.txt",
                "content": "needs-human",
                "idempotency_key": "agent-self-approve",
            })),
        )
        .await
        .expect("agent enqueue");
    assert_eq!(pending["approval_required"], true);
    let approval_id = pending["approval_id"].as_str().unwrap().to_owned();

    // Same agent credential cannot approve its own Ask.
    let self_approve = agent
        .call(
            methods::APPROVAL_APPROVE,
            Some(json!({
                "id": approval_id,
                "temporary_grant": false,
                // Client-supplied identity must be ignored even if present.
                "approver_principal_id": "user:spoofed-human",
                "principal_id": format!("user:{}", current_os_user_id()),
            })),
        )
        .await
        .expect_err("agent self-approve must fail");
    assert_unauthorized(self_approve);

    // Management credential is not a human boundary either.
    let mgmt_approve = management
        .call(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": approval_id })),
        )
        .await
        .expect_err("management cannot approve");
    assert_unauthorized(mgmt_approve);

    for (method, params) in [
        (
            methods::POLICY_PRESET,
            Some(json!({ "preset": "full_access" })),
        ),
        (methods::DAEMON_UNLOCK, None),
        (
            methods::TOKEN_REVOKE,
            Some(json!({ "principal": "client:agent-chatgpt" })),
        ),
    ] {
        assert_unauthorized(
            agent
                .call(method, params.clone())
                .await
                .expect_err(&format!("{method} denied for agent")),
        );
        assert_unauthorized(
            management
                .call(method, params.clone())
                .await
                .expect_err(&format!("{method} denied for management")),
        );
        // Two-connection presence forgery: uncredentialed same-UID must also be denied.
        assert_unauthorized(forged_human.call(method, params).await.expect_err(&format!(
            "{method} denied for forged uncredentialed presence"
        )));
    }

    // C1 regression: second unauthenticated same-UID IPC must not approve.
    let forged_approve = forged_human
        .call(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": approval_id, "temporary_grant": false })),
        )
        .await
        .expect_err("forged uncredentialed presence must not approve");
    assert_unauthorized(forged_approve);

    // Approval remains pending — no ordinary IPC path can decide it.
    let still = agent
        .call(methods::APPROVAL_SHOW, Some(json!({ "id": approval_id })))
        .await
        .expect("show pending");
    assert_eq!(still["state"], "pending");

    server.request_shutdown();
    let _ = handle.await;
}

/// Production registry: credentialed agent opens a second unauthenticated connection and
/// must not obtain human-operator powers (approve/deny/preset/unlock/revoke).
#[tokio::test]
async fn production_two_connection_presence_forgery_denied() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_production_test_daemon(&paths).await;

    let management_secret =
        ownmesh_ipc::read_management_credential(&paths.state_dir).expect("management delivery");
    let management = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "mgmt",
        Some(management_secret),
    );
    let provisioned: ownmesh_ipc::CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(json!({ "client_id": "dual-conn-agent" })),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let agent = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "dual-conn-agent-label",
        Some(provisioned.credential),
    );
    // Second connection: no client credential → maps to user:<uid> (forgeable).
    let second = named_client(endpoint.clone(), paths.runtime_dir.clone(), "second-sock");

    {
        let mut guard = runtime.lock().await;
        guard.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("ask".into()),
            rules: vec![PolicyRule {
                id: "ask-write".into(),
                decision: Decision::Ask,
                priority: 10,
                capability: "filesystem.write".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                description: None,
            }],
        });
    }

    let pending = agent
        .call(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "dual.txt",
                "content": "x",
                "idempotency_key": "dual-conn",
            })),
        )
        .await
        .unwrap();
    let approval_id = pending["approval_id"].as_str().unwrap().to_owned();

    for method in [
        methods::APPROVAL_APPROVE,
        methods::APPROVAL_DENY,
        methods::POLICY_PRESET,
        methods::DAEMON_UNLOCK,
        methods::TOKEN_REVOKE,
    ] {
        let params = match method {
            methods::APPROVAL_APPROVE | methods::APPROVAL_DENY => {
                Some(json!({ "id": approval_id }))
            }
            methods::POLICY_PRESET => Some(json!({ "preset": "full_access" })),
            methods::TOKEN_REVOKE => Some(json!({ "principal": "client:dual-conn-agent" })),
            _ => None,
        };
        assert_unauthorized(second.call(method, params).await.expect_err(&format!(
            "{method} must fail on second uncredentialed connection"
        )));
    }

    server.request_shutdown();
    let _ = handle.await;
}

/// Benign native binary used as the pre-approval pin target.
fn sample_native_binary() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from("/bin/echo")
    }
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        system_root.join("System32").join("where.exe")
    }
}

#[tokio::test]
async fn production_approval_rejects_executable_content_swap_toctou() {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_production_test_daemon(&paths).await;

    let management_secret =
        ownmesh_ipc::read_management_credential(&paths.state_dir).expect("management delivery");
    let management = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "mgmt",
        Some(management_secret),
    );
    let provisioned: ownmesh_ipc::CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(json!({ "client_id": "exec-agent" })),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let agent = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "exec-agent-label",
        Some(provisioned.credential),
    );

    // Keep a native extension so Windows still classifies the path as structured.
    let tool = dir.path().join(if cfg!(windows) {
        "pinned-tool.exe"
    } else {
        "pinned-tool"
    });
    std::fs::copy(sample_native_binary(), &tool).expect("copy sample native binary");
    #[cfg(unix)]
    std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    let marker = dir.path().join("pwned-marker");

    {
        let mut guard = runtime.lock().await;
        guard.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("ask structured".into()),
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
                    description: None,
                },
                PolicyRule {
                    id: "ask-structured".into(),
                    decision: Decision::Ask,
                    priority: 10,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("structured".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: None,
                },
            ],
        });
    }

    let pending = agent
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": tool,
                "args": ["ok"],
                "idempotency_key": "exec-toctou-pin",
            })),
        )
        .await
        .expect("enqueue structured");
    assert_eq!(pending["approval_required"], true);
    let approval_id = pending["approval_id"].as_str().unwrap().to_owned();

    // Replace the canonical path after enqueue / before human approval.
    // Unix: shebang script. Windows: different PE bytes (cmd.exe) under the same path.
    let swapped = dir.path().join("pinned-tool.swapped");
    #[cfg(unix)]
    {
        std::fs::write(
            &swapped,
            format!("#!/bin/sh\ntouch '{}'\n", marker.display()),
        )
        .unwrap();
        std::fs::set_permissions(&swapped, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        let system_root = std::env::var_os("SystemRoot").map_or_else(
            || std::path::PathBuf::from(r"C:\Windows"),
            std::path::PathBuf::from,
        );
        std::fs::copy(system_root.join("System32").join("cmd.exe"), &swapped)
            .expect("copy replacement pe");
    }
    std::fs::rename(&swapped, &tool).unwrap();

    let denied = direct_human_approve(&runtime, &approval_id, false, None)
        .await
        .expect_err("content-swapped executable must fail closed");
    match denied {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::POLICY_DENIED, "{message}");
            let lower = message.to_ascii_lowercase();
            assert!(
                lower.contains("identity")
                    || lower.contains("digest")
                    || lower.contains("classification")
                    || lower.contains("re-authorized")
                    || lower.contains("drift"),
                "{message}"
            );
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(!marker.exists(), "swapped payload must never execute");

    server.request_shutdown();
    let _ = handle.await;
}

/// command.run temporary grants are never safe: versioned interpreters such as
/// `python3.12` can stay structured under the same pinned executable while argv
/// changes (`--version` → `-c payload`). Production handler must refuse
/// temporary_grant issuance before approval mutation, keep one-shot approval,
/// and never Allow on legacy/forged grant rows without re-approval.
#[tokio::test]
async fn production_command_run_temporary_grant_never_issued_or_matched() {
    use ownmesh_policy::{ExecutableIdentityBinding, TemporaryGrant};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_production_test_daemon(&paths).await;

    let management_secret =
        ownmesh_ipc::read_management_credential(&paths.state_dir).expect("management delivery");
    let management = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "mgmt",
        Some(management_secret),
    );
    let provisioned: ownmesh_ipc::CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(json!({ "client_id": "grant-agent" })),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let agent = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "grant-agent-label",
        Some(provisioned.credential),
    );

    // python3.12 is intentionally NOT an exact INTERPRETER_BINARIES stem match, so
    // classification stays structured — the historical temporary-grant hole.
    let python = dir.path().join(if cfg!(windows) {
        "python3.12.exe"
    } else {
        "python3.12"
    });
    // gawk is also absent from the interpreter denylist and stays structured.
    let gawk = dir
        .path()
        .join(if cfg!(windows) { "gawk.exe" } else { "gawk" });
    let plain = dir.path().join(if cfg!(windows) {
        "plain-tool.exe"
    } else {
        "plain-tool"
    });
    for tool in [&python, &gawk, &plain] {
        std::fs::copy(sample_native_binary(), tool).expect("copy sample native binary");
        #[cfg(unix)]
        std::fs::set_permissions(tool, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    let raw_script = dir.path().join(if cfg!(windows) {
        "raw-tool.cmd"
    } else {
        "raw-tool.sh"
    });
    #[cfg(unix)]
    {
        std::fs::write(&raw_script, "#!/bin/sh\necho ok\n").unwrap();
        std::fs::set_permissions(&raw_script, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    #[cfg(windows)]
    {
        std::fs::write(&raw_script, "@echo off\r\necho ok\r\n").unwrap();
    }

    {
        let mut guard = runtime.lock().await;
        guard.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("ask all command.run; never auto-allow".into()),
            rules: vec![
                PolicyRule {
                    id: "ask-structured".into(),
                    decision: Decision::Ask,
                    priority: 10,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("structured".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: None,
                },
                PolicyRule {
                    id: "ask-raw".into(),
                    decision: Decision::Ask,
                    priority: 10,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: Some("raw_shell".into()),
                    path_prefix: None,
                    program_equals: None,
                    description: None,
                },
            ],
        });
    }

    // --- structured python3.12: temporary_grant refused before approval mutation ---
    let pending_py = agent
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": &python,
                "args": ["--version"],
                "idempotency_key": "cmd-grant-py-version",
            })),
        )
        .await
        .expect("enqueue python3.12 --version");
    assert_eq!(pending_py["approval_required"], true);
    let py_approval = pending_py["approval_id"].as_str().unwrap().to_owned();
    // Provisioned client_id "grant-agent" → server principal `client:grant-agent`.
    let agent_principal = "client:grant-agent".to_owned();

    let grant_denied = direct_human_approve(&runtime, &py_approval, true, Some(600))
        .await
        .expect_err("command.run temporary_grant must be refused");
    match grant_denied {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INVALID_PARAMS, "{message}");
            let lower = message.to_ascii_lowercase();
            assert!(
                lower.contains("command.run") && lower.contains("not permitted"),
                "expected systemic command.run grant refusal, got: {message}"
            );
        }
        other => panic!("unexpected grant refusal error: {other:?}"),
    }
    // Approval must remain pending (no state mutation on grant refusal).
    {
        let guard = runtime.lock().await;
        assert!(
            guard.grants_for_test().is_empty(),
            "no command.run grant may be persisted"
        );
        // Re-approve path below requires the same approval id still pending.
    }

    // One-shot human approval still executes the approved operation once.
    let approved_once = direct_human_approve(&runtime, &py_approval, false, None)
        .await
        .expect("one-shot command.run approval must still work");
    assert_eq!(approved_once["approval_required"], false);
    {
        let guard = runtime.lock().await;
        assert!(
            guard.grants_for_test().is_empty(),
            "one-shot approval must not mint a grant"
        );
    }

    // Same pinned python3.12 executable with argv changed to -c payload must re-Ask.
    let py_payload = agent
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": &python,
                "args": ["-c", "print('pwn')"],
                "idempotency_key": "cmd-grant-py-payload",
            })),
        )
        .await
        .expect("python argv change must re-enter policy");
    assert_eq!(
        py_payload["approval_required"], true,
        "same program argv change must not Allow without re-approval: {py_payload}"
    );
    assert_ne!(py_payload["decision"], "allow");

    // --- gawk interpreter (structured): temporary_grant also refused ---
    let pending_gawk = agent
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": &gawk,
                "args": ["BEGIN{print 1}"],
                "idempotency_key": "cmd-grant-gawk",
            })),
        )
        .await
        .expect("enqueue gawk");
    assert_eq!(pending_gawk["approval_required"], true);
    let gawk_approval = pending_gawk["approval_id"].as_str().unwrap().to_owned();
    let gawk_denied = direct_human_approve(&runtime, &gawk_approval, true, Some(600))
        .await
        .expect_err("gawk temporary_grant must be refused");
    match gawk_denied {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INVALID_PARAMS, "{message}");
            assert!(
                message.to_ascii_lowercase().contains("not permitted"),
                "{message}"
            );
        }
        other => panic!("unexpected gawk grant refusal: {other:?}"),
    }

    // --- plain structured binary: same systemic refusal ---
    let pending_plain = agent
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": &plain,
                "args": [],
                "idempotency_key": "cmd-grant-plain",
            })),
        )
        .await
        .expect("enqueue plain structured");
    let plain_approval = pending_plain["approval_id"].as_str().unwrap().to_owned();
    let plain_denied = direct_human_approve(&runtime, &plain_approval, true, None)
        .await
        .expect_err("plain structured temporary_grant must be refused");
    match plain_denied {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INVALID_PARAMS, "{message}");
            assert!(
                message.to_ascii_lowercase().contains("not permitted"),
                "{message}"
            );
        }
        other => panic!("unexpected plain grant refusal: {other:?}"),
    }

    // --- raw_shell script: temporary_grant refused; one-shot still works ---
    let pending_raw = agent
        .call(
            methods::OPS_EXEC,
            Some(json!({
                "kind": "structured",
                "program": &raw_script,
                "args": [],
                "executable_pin": {
                    "path": &raw_script,
                    "content_sha256": "aa".repeat(32),
                    "len": 1,
                    "policy_kind": "structured"
                },
                "idempotency_key": "cmd-grant-raw",
            })),
        )
        .await
        .expect("enqueue raw script");
    assert_eq!(pending_raw["approval_required"], true);
    let raw_approval = pending_raw["approval_id"].as_str().unwrap().to_owned();
    let raw_denied = direct_human_approve(&runtime, &raw_approval, true, None)
        .await
        .expect_err("raw_shell temporary_grant must be refused");
    match raw_denied {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INVALID_PARAMS, "{message}");
            assert!(
                message.to_ascii_lowercase().contains("not permitted"),
                "{message}"
            );
        }
        other => panic!("unexpected raw grant refusal: {other:?}"),
    }
    let raw_once = direct_human_approve(&runtime, &raw_approval, false, None)
        .await
        .expect("one-shot raw_shell approval must still work");
    assert_eq!(raw_once["approval_required"], false);

    // --- legacy/forged fully-bound command.run grants must never Allow ---
    let py_canon = python.to_string_lossy().into_owned();
    let gawk_canon = gawk.to_string_lossy().into_owned();
    let forged_identity = |path: &str, kind: &str| ExecutableIdentityBinding {
        path: path.into(),
        content_sha256: "ab".repeat(32),
        len: 64,
        device: Some(1),
        inode: Some(2),
        policy_kind: kind.into(),
    };
    {
        let mut guard = runtime.lock().await;
        for grant in [
            TemporaryGrant {
                id: "legacy-unbound".into(),
                capability: "command.run".into(),
                principal_id: agent_principal.clone(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: None,
                program_equals: None,
                elevated: None,
                executable_identity: None,
            },
            TemporaryGrant {
                id: "forged-python-bound".into(),
                capability: "command.run".into(),
                principal_id: agent_principal.clone(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: Some("structured".into()),
                program_equals: Some(py_canon.clone()),
                elevated: Some(false),
                executable_identity: Some(forged_identity(&py_canon, "structured")),
            },
            TemporaryGrant {
                id: "forged-gawk-bound".into(),
                capability: "command.run".into(),
                principal_id: agent_principal.clone(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: Some("structured".into()),
                program_equals: Some(gawk_canon.clone()),
                elevated: Some(false),
                executable_identity: Some(forged_identity(&gawk_canon, "structured")),
            },
            TemporaryGrant {
                id: "forged-raw-bound".into(),
                capability: "command.run".into(),
                principal_id: agent_principal.clone(),
                expires_unix: 9_999_999_999,
                path_prefix: None,
                kind: Some("raw_shell".into()),
                program_equals: Some(raw_script.to_string_lossy().into_owned()),
                elevated: Some(false),
                executable_identity: Some(forged_identity(
                    raw_script.to_string_lossy().as_ref(),
                    "raw_shell",
                )),
            },
        ] {
            guard.inject_grant_for_test(grant);
        }
        assert!(
            guard.grants_for_test().len() >= 4,
            "forged grants must be present for match regression"
        );
    }

    // Client-supplied forged pin/facts must not help either.
    for (label, program, args, key) in [
        (
            "python3.12 -c via forged grant",
            python.as_path(),
            vec!["-c".to_owned(), "print(1)".to_owned()],
            "forged-grant-py-c",
        ),
        (
            "gawk via forged grant",
            gawk.as_path(),
            vec!["BEGIN{system(\"id\")}".to_owned()],
            "forged-grant-gawk",
        ),
        (
            "plain structured via forged grant",
            plain.as_path(),
            vec![],
            "forged-grant-plain",
        ),
        (
            "raw_shell via forged grant",
            raw_script.as_path(),
            vec![],
            "forged-grant-raw",
        ),
    ] {
        let again = agent
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "kind": "structured",
                    "program": program,
                    "args": args,
                    "executable_pin": {
                        "path": program,
                        "content_sha256": "ff".repeat(32),
                        "len": 1,
                        "policy_kind": "structured"
                    },
                    "idempotency_key": key,
                })),
            )
            .await
            .unwrap_or_else(|e| panic!("{label}: expected policy re-entry, got err {e:?}"));
        assert_eq!(
            again["approval_required"], true,
            "{label} must not Allow via legacy/forged command.run grant: {again}"
        );
        assert_ne!(
            again["decision"], "allow",
            "{label} decision must not be allow: {again}"
        );
        let reason = again["reason"].as_str().unwrap_or("");
        assert!(
            !reason.contains("temporary grant"),
            "{label}: grant overlay must not match: {reason}"
        );
    }

    server.request_shutdown();
    let _ = handle.await;
}

/// Filesystem temporary grants keep path-capable reuse semantics (unchanged).
#[tokio::test]
async fn production_filesystem_temporary_grant_still_works() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    let (server, handle, endpoint, runtime) = start_production_test_daemon(&paths).await;

    let management_secret =
        ownmesh_ipc::read_management_credential(&paths.state_dir).expect("management delivery");
    let management = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "mgmt",
        Some(management_secret),
    );
    let provisioned: ownmesh_ipc::CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(json!({ "client_id": "fs-grant-agent" })),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    let agent = named_client_with_cred(
        endpoint.clone(),
        paths.runtime_dir.clone(),
        "fs-grant-agent-label",
        Some(provisioned.credential),
    );

    {
        let mut guard = runtime.lock().await;
        guard.set_policy_for_test(PolicyDocument {
            preset: AccessPreset::Custom,
            note: Some("ask filesystem.write".into()),
            rules: vec![PolicyRule {
                id: "ask-write".into(),
                decision: Decision::Ask,
                priority: 10,
                capability: "filesystem.write".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                description: None,
            }],
        });
    }

    let pending = agent
        .call(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "fs-grant-a.txt",
                "content": "one",
                "idempotency_key": "fs-grant-approve",
            })),
        )
        .await
        .expect("enqueue fs write");
    assert_eq!(pending["approval_required"], true);
    let approval_id = pending["approval_id"].as_str().unwrap().to_owned();

    let approved = direct_human_approve(&runtime, &approval_id, true, Some(600))
        .await
        .expect("fs temporary_grant must still be issued");
    assert_eq!(approved["approval_required"], false);
    {
        let guard = runtime.lock().await;
        assert_eq!(guard.grants_for_test().len(), 1);
        assert_eq!(guard.grants_for_test()[0].capability, "filesystem.write");
    }

    let second = agent
        .call(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "fs-grant-b.txt",
                "content": "two",
                "idempotency_key": "fs-grant-reuse",
            })),
        )
        .await
        .expect("fs grant reuse");
    assert_eq!(second["approval_required"], false);
    assert_eq!(second["decision"], "allow");

    server.request_shutdown();
    let _ = handle.await;
}
