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
    let approved = client
        .call(
            methods::APPROVAL_APPROVE,
            Some(json!({
                "id": approval_id,
                "temporary_grant": false,
            })),
        )
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

    // Revoke through a case/whitespace alias. The server-defined client namespace,
    // persisted value, and checks must converge on the same canonical principal.
    let revoked = admin
        .call(
            methods::TOKEN_REVOKE,
            Some(json!({ "principal": " CLIENT:AGENT-CHATGPT " })),
        )
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
        let (server, handle, endpoint, _runtime) = start_test_daemon(&paths).await;
        let client = named_client(
            endpoint,
            paths.runtime_dir.clone(),
            "legacy-revoke-attacker",
        );
        client.status().await.expect("pre-revoke status");

        let legacy = format!("{stable}{suffix}");
        let revoked = client
            .call(methods::TOKEN_REVOKE, Some(json!({ "principal": legacy })))
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

    // Revoke the bound principal while the connection is live.
    let revoked = admin
        .call(
            methods::TOKEN_REVOKE,
            Some(json!({ "client": "client:chatgpt" })),
        )
        .await
        .expect("revoke");
    assert_eq!(revoked["revoked"], "client:chatgpt");
    let _ = runtime; // runtime already shares revoked set via server config

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
