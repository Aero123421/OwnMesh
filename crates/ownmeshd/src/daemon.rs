//! Foreground daemon loop: local IPC + policy-gated operations.

use crate::runtime::{runtime_handler, DaemonRuntime};
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_identity::{
    load_or_create_device_key, PreferredSecretStore, DEFAULT_KEYCHAIN_SERVICE,
};
use ownmesh_ipc::{
    generate_token, write_token_file, AuthGate, ClientIdentity, ClientOptions, Endpoint, IpcBus,
    IpcClient, IpcServer, MethodHandler, ServerConfig,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Run ownmeshd until Ctrl-C / shutdown signal.
pub fn run_foreground() -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            tracing::error!(error = %err, "runtime build failed");
            ExitCode::Internal
        })?;
    rt.block_on(run_async())
}

async fn run_async() -> Result<(), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        tracing::error!(error = %err, "path discovery failed");
        ExitCode::UsageConfig
    })?;
    paths.ensure_layout().map_err(|err| {
        tracing::error!(error = %err, "failed to create data directories");
        ExitCode::UsageConfig
    })?;

    let cfg = load_config(&paths).map_err(|err| {
        tracing::error!(error = %err, "config load failed");
        ExitCode::UsageConfig
    })?;
    tracing::info!(lang = %cfg.lang, "config loaded");

    let public = ensure_device_identity(&paths).map_err(|err| {
        tracing::error!(error = %err, "device identity bootstrap failed");
        ExitCode::Internal
    })?;
    // Public fingerprint only — never log key material.
    tracing::info!(fingerprint = %public.fingerprint, "device identity ready");

    let token = generate_token();
    write_token_file(&paths.runtime_dir, &token).map_err(|err| {
        tracing::error!(error = %err, "failed to write daemon token");
        ExitCode::Internal
    })?;

    let handler = build_handler(&paths).map_err(|err| {
        tracing::error!(error = %err, "runtime bootstrap failed");
        ExitCode::Internal
    })?;

    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let server = Arc::new(IpcServer::new(
        ServerConfig {
            endpoint: endpoint.clone(),
            auth: AuthGate::new(token),
            server_name: env!("CARGO_PKG_NAME").into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
        },
        handler,
    ));

    tracing::info!(endpoint = %endpoint.display(), "ownmeshd starting");

    let serve = Arc::clone(&server);
    let serve_task = tokio::spawn(async move {
        if let Err(err) = serve.serve().await {
            tracing::error!(error = %err, "ipc server terminated with error");
        }
    });

    wait_for_shutdown().await?;

    server.request_shutdown();
    let _ = tokio::time::timeout(Duration::from_secs(2), serve_task).await;
    tracing::info!("ownmeshd stopped");
    Ok(())
}

fn build_handler(paths: &OwnMeshPaths) -> Result<MethodHandler, String> {
    let runtime = DaemonRuntime::open(paths)?;
    Ok(runtime_handler(Arc::new(Mutex::new(runtime))))
}

fn ensure_device_identity(
    paths: &OwnMeshPaths,
) -> Result<ownmesh_identity::DevicePublicIdentity, String> {
    let store = PreferredSecretStore::open(DEFAULT_KEYCHAIN_SERVICE, paths.keystore_dir())
        .map_err(|e| e.to_string())?;
    let key = load_or_create_device_key(&store).map_err(|e| e.to_string())?;
    Ok(key.public_identity())
}

async fn wait_for_shutdown() -> Result<(), ExitCode> {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|err| {
                tracing::error!(error = %err, "signal hook failed");
                ExitCode::Internal
            })?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => {
                result.map_err(|err| {
                    tracing::error!(error = %err, "ctrl-c hook failed");
                    ExitCode::Internal
                })?;
                tracing::info!("ctrl-c received");
            }
            _ = sigterm.recv() => {
                tracing::info!("SIGTERM received");
            }
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await.map_err(|err| {
            tracing::error!(error = %err, "ctrl-c hook failed");
            ExitCode::Internal
        })?;
        tracing::info!("ctrl-c received");
        Ok(())
    }
}

/// Probe a running daemon and print status.
pub fn probe_status() -> Result<(), ExitCode> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| ExitCode::Internal)?;
    rt.block_on(async {
        let paths = OwnMeshPaths::discover().map_err(|_| ExitCode::UsageConfig)?;
        let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
        let client = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
            ClientOptions {
                request_timeout: Duration::from_secs(2),
                max_reconnect_attempts: 1,
                reconnect_base_delay: Duration::from_millis(50),
            },
        );
        match client.status().await {
            Ok(status) => {
                println!(
                    "ownmeshd {version} state={state} pid={pid}",
                    version = status.version,
                    state = status.state,
                    pid = status.pid
                );
                Ok(())
            }
            Err(err) => {
                eprintln!("ownmeshd not reachable: {err}");
                Err(ExitCode::DeviceOffline)
            }
        }
    })
}

/// Test helper: start an in-process daemon server for the given paths.
#[cfg(test)]
pub async fn start_test_daemon(
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
    let runtime = Arc::new(Mutex::new(runtime));
    let handler = runtime_handler(Arc::clone(&runtime));
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let server = Arc::new(IpcServer::new(
        ServerConfig {
            endpoint: endpoint.clone(),
            auth: AuthGate::new(token),
            server_name: "ownmeshd".into(),
            server_version: env!("CARGO_PKG_VERSION").into(),
        },
        handler,
    ));
    let serve = Arc::clone(&server);
    let handle = tokio::spawn(async move {
        let _ = serve.serve().await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (server, handle, endpoint, runtime)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_ipc::{app_error, methods, ClientIdentity, ClientOptions, IpcClient, IpcError};
    use ownmesh_policy::{preset_document, AccessPreset, PolicyDocument, PolicyRule, Decision};
    use serde_json::json;
    use tempfile::tempdir;

    fn test_client(endpoint: Endpoint, runtime_dir: impl Into<std::path::PathBuf>) -> IpcClient {
        IpcClient::new(
            endpoint,
            runtime_dir,
            ClientIdentity::new("ownmesh", "0.1.0"),
            ClientOptions {
                request_timeout: Duration::from_secs(15),
                max_reconnect_attempts: 3,
                reconnect_base_delay: Duration::from_millis(30),
            },
        )
    }

    #[tokio::test]
    async fn cli_and_tui_clients_get_status() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;

        let cli = test_client(endpoint.clone(), paths.runtime_dir.clone());
        let tui = IpcClient::new(
            endpoint,
            paths.runtime_dir.clone(),
            ClientIdentity::new("ownmesh-tui", "0.1.0"),
            ClientOptions::default(),
        );

        let s1 = cli.status().await.expect("cli status");
        let s2 = tui.status().await.expect("tui status");
        assert_eq!(s1.state, "running");
        assert_eq!(s2.state, "running");
        assert_eq!(s1.version, s2.version);

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn unauthenticated_process_is_rejected() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;

        let evil = IpcClient::new(
            endpoint,
            paths.runtime_dir,
            ClientIdentity::new("untrusted", "0.0.0"),
            ClientOptions {
                max_reconnect_attempts: 0,
                ..ClientOptions::default()
            },
        )
        .with_token("not-a-valid-token");

        let err = evil.status().await.expect_err("must fail");
        assert!(
            matches!(
                err,
                IpcError::Unauthorized(_) | IpcError::Remote { .. } | IpcError::Disconnected(_)
            ),
            "{err:?}"
        );

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn policy_allow_ask_deny_on_exec_fs_logs() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
        let client = test_client(endpoint, paths.runtime_dir.clone());

        // Full Access: allow exec without ask.
        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        }
        let allow = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                    "args": if cfg!(windows) {
                        vec!["/C", "echo policy-allow"]
                    } else {
                        vec!["policy-allow"]
                    },
                    "idempotency_key": "allow-exec-1",
                })),
            )
            .await
            .expect("allow exec");
        assert_eq!(allow["approval_required"], false);
        assert!(allow["result"]["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("policy-allow"));

        // Write + read under Full Access.
        let wrote = client
            .call(
                methods::OPS_FS_WRITE,
                Some(json!({
                    "path": "hello.txt",
                    "content": "hi-fs",
                    "idempotency_key": "fs-write-1",
                })),
            )
            .await
            .expect("fs write");
        assert_eq!(wrote["approval_required"], false);
        let read = client
            .call(
                methods::OPS_FS_READ,
                Some(json!({ "path": "hello.txt" })),
            )
            .await
            .expect("fs read");
        assert_eq!(read["result"]["content"], "hi-fs");

        // Logs readable.
        let logs = client
            .call(
                methods::OPS_LOGS_QUERY,
                Some(json!({ "provider": "audit", "limit": 10 })),
            )
            .await
            .expect("logs");
        assert_eq!(logs["approval_required"], false);
        assert!(logs["result"]["lines"].as_array().is_some());

        // Custom deny for command.run
        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(PolicyDocument {
                preset: AccessPreset::Custom,
                note: None,
                rules: vec![PolicyRule {
                    id: "deny-cmd".into(),
                    decision: Decision::Deny,
                    priority: 100,
                    capability: "command.run".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    description: Some("deny all commands".into()),
                }],
            });
        }
        let denied = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "program": "echo",
                    "args": ["nope"],
                })),
            )
            .await
            .expect_err("must deny");
        match denied {
            IpcError::Remote { code, message } => {
                assert_eq!(code, app_error::POLICY_DENIED);
                assert!(message.contains("denied"), "{message}");
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Ask on filesystem.write
        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(PolicyDocument {
                preset: AccessPreset::Custom,
                note: None,
                rules: vec![PolicyRule {
                    id: "ask-write".into(),
                    decision: Decision::Ask,
                    priority: 50,
                    capability: "filesystem.write".into(),
                    when_elevated: None,
                    when_kind: None,
                    path_prefix: None,
                    program_equals: None,
                    description: Some("ask writes".into()),
                }],
            });
        }
        let ask = client
            .call(
                methods::OPS_FS_WRITE,
                Some(json!({
                    "path": "ask-me.txt",
                    "content": "pending",
                })),
            )
            .await
            .expect("ask response");
        assert_eq!(ask["approval_required"], true);
        assert!(ask["approval_id"].as_str().unwrap().starts_with("apr_"));

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn ask_queue_requires_approval_before_exec() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
        let client = test_client(endpoint, paths.runtime_dir.clone());

        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(preset_document(AccessPreset::Recommended));
        }

        let marker = paths.state_dir.join("workspace").join("approved-only.txt");
        assert!(!marker.exists());

        let pending = client
            .call(
                methods::OPS_FS_WRITE,
                Some(json!({
                    "path": "approved-only.txt",
                    "content": "after-approve",
                    "idempotency_key": "ask-write-e2e",
                })),
            )
            .await
            .expect("enqueue");
        assert_eq!(pending["approval_required"], true);
        let approval_id = pending["approval_id"].as_str().unwrap().to_owned();
        assert!(!marker.exists(), "must not execute before approval");

        let listed = client
            .call(methods::APPROVAL_LIST, None)
            .await
            .expect("list");
        let approvals = listed["approvals"].as_array().unwrap();
        assert!(approvals.iter().any(|a| a["id"] == approval_id));

        let approved = client
            .call(
                methods::APPROVAL_APPROVE,
                Some(json!({
                    "id": approval_id,
                    "temporary_grant": true,
                    "grant_seconds": 600,
                })),
            )
            .await
            .expect("approve");
        assert_eq!(approved["approval_required"], false);
        assert_eq!(approved["result"]["bytes_written"], 13);
        assert!(marker.exists(), "must execute after approval");

        // Temporary grant should allow subsequent write without ask.
        let second = client
            .call(
                methods::OPS_FS_WRITE,
                Some(json!({
                    "path": "granted.txt",
                    "content": "granted",
                    "idempotency_key": "grant-write-1",
                })),
            )
            .await
            .expect("grant allow");
        assert_eq!(second["approval_required"], false);
        assert_eq!(second["decision"], "allow");

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn idempotency_key_prevents_operation_rerun() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
        let client = test_client(endpoint, paths.runtime_dir.clone());

        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        }

        let key = "idem-op-42";
        let first = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                    "args": if cfg!(windows) {
                        vec!["/C", "echo once-only"]
                    } else {
                        vec!["once-only"]
                    },
                    "idempotency_key": key,
                })),
            )
            .await
            .expect("first");
        assert_eq!(first["replayed"], false);
        assert!(first["result"]["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("once-only"));

        let second = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                    "args": if cfg!(windows) {
                        vec!["/C", "echo once-only"]
                    } else {
                        vec!["once-only"]
                    },
                    "idempotency_key": key,
                })),
            )
            .await
            .expect("second");
        assert_eq!(second["replayed"], true);
        assert_eq!(first["result"]["stdout"], second["result"]["stdout"]);
        // operation_id from first completion is preserved in journal body
        assert_eq!(first["operation_id"], second["operation_id"]);

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn full_access_preset_has_no_hidden_hard_deny() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
        let client = test_client(endpoint, paths.runtime_dir.clone());

        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        }

        let shown = client
            .call(methods::POLICY_SHOW, None)
            .await
            .expect("policy show");
        assert_eq!(shown["preset"], "full_access");
        assert_eq!(shown["full_access_no_hidden_deny"], true);

        let validated = client
            .call(methods::POLICY_VALIDATE, None)
            .await
            .expect("validate");
        assert_eq!(validated["ok"], true);
        assert_eq!(validated["full_access_no_hidden_deny"], true);

        // Elevated raw shell still allowed under Full Access (no hidden deny).
        let elevated = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                    "args": if cfg!(windows) {
                        vec!["/C", "echo elevated-ok"]
                    } else {
                        vec!["elevated-ok"]
                    },
                    "kind": "raw_shell",
                    "elevated": true,
                    "idempotency_key": "fa-elevated-1",
                })),
            )
            .await
            .expect("full access elevated");
        assert_eq!(elevated["approval_required"], false);
        assert_eq!(elevated["decision"], "allow");

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn lockdown_unlock_and_token_revoke() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, runtime) = start_test_daemon(&paths).await;
        let client = test_client(endpoint, paths.runtime_dir.clone());

        {
            let mut g = runtime.lock().await;
            g.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        }

        client
            .call(methods::DAEMON_LOCKDOWN, None)
            .await
            .expect("lockdown");
        assert!(runtime.lock().await.is_lockdown());

        let blocked = client
            .call(
                methods::OPS_EXEC,
                Some(json!({ "program": "echo", "args": ["x"] })),
            )
            .await
            .expect_err("lockdown blocks ops");
        match blocked {
            IpcError::Remote { code, .. } => assert_eq!(code, app_error::LOCKDOWN),
            other => panic!("{other:?}"),
        }

        // Local recovery path still works.
        client
            .call(methods::DAEMON_UNLOCK, None)
            .await
            .expect("unlock");
        assert!(!runtime.lock().await.is_lockdown());

        let ok = client
            .call(
                methods::OPS_EXEC,
                Some(json!({
                    "program": if cfg!(windows) { "cmd.exe" } else { "echo" },
                    "args": if cfg!(windows) {
                        vec!["/C", "echo unlocked"]
                    } else {
                        vec!["unlocked"]
                    },
                    "idempotency_key": "after-unlock",
                })),
            )
            .await
            .expect("after unlock");
        assert_eq!(ok["approval_required"], false);

        let revoked = client
            .call(
                methods::TOKEN_REVOKE,
                Some(json!({ "client": "chatgpt" })),
            )
            .await
            .expect("token revoke");
        assert_eq!(revoked["revoked"], "chatgpt");
        assert_eq!(revoked["ok"], true);

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn session_handoff_observer_reads_during_controller_transfer() {
        use crate::runtime::session_methods;

        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;
        let client = test_client(endpoint, paths.runtime_dir.clone());

        let opened = client
            .call(
                session_methods::OPEN,
                Some(json!({
                    "title": "handoff",
                    "principal": "chatgpt",
                    "kind": "pty",
                })),
            )
            .await
            .expect("open");
        let sid = opened["id"].as_str().unwrap().to_owned();

        client
            .call(
                session_methods::PUSH_OUTPUT,
                Some(json!({
                    "id": sid,
                    "data": "hello from agent\n",
                })),
            )
            .await
            .expect("push");

        let given = client
            .call(
                session_methods::GIVE,
                Some(json!({
                    "id": sid,
                    "from": "chatgpt",
                    "to": "human",
                })),
            )
            .await
            .expect("give");
        assert_eq!(given["lease"]["principal_id"], "human");
        let readers = given["readers"].as_array().unwrap();
        assert!(readers.iter().any(|r| r == "chatgpt"));
        assert!(readers.iter().any(|r| r == "human"));

        // Observer (chatgpt) can still replay output.
        let replay = client
            .call(
                session_methods::REPLAY,
                Some(json!({
                    "id": sid,
                    "from_seq": 1,
                    "principal": "chatgpt",
                })),
            )
            .await
            .expect("observer replay");
        let chunks = replay["chunks"].as_array().unwrap();
        assert!(chunks.iter().any(|c| c["data"]
            .as_str()
            .unwrap_or("")
            .contains("hello from agent")));

        // Observer cannot write stdin.
        let denied = client
            .call(
                session_methods::WRITE,
                Some(json!({
                    "id": sid,
                    "data": "nope",
                    "principal": "chatgpt",
                })),
            )
            .await
            .expect_err("observer write denied");
        match denied {
            IpcError::Remote { code, .. } => assert_eq!(code, app_error::CONFLICT),
            other => panic!("{other:?}"),
        }

        // Human controller can write.
        let wrote = client
            .call(
                session_methods::WRITE,
                Some(json!({
                    "id": sid,
                    "data": "from-human",
                    "principal": "human",
                })),
            )
            .await
            .expect("controller write");
        assert_eq!(wrote["accepted"], true);

        server.request_shutdown();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn session_survives_daemon_restart() {
        use crate::runtime::{session_methods, DaemonRuntime};

        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());

        // Phase 1: live daemon writes session + handoff + output.
        let sid = {
            let (server, handle, endpoint, _rt) = start_test_daemon(&paths).await;
            let client = test_client(endpoint, paths.runtime_dir.clone());
            let opened = client
                .call(
                    session_methods::OPEN,
                    Some(json!({
                        "title": "persist",
                        "principal": "chatgpt",
                    })),
                )
                .await
                .expect("open");
            let sid = opened["id"].as_str().unwrap().to_owned();
            client
                .call(
                    session_methods::PUSH_OUTPUT,
                    Some(json!({ "id": sid, "data": "before-restart\n" })),
                )
                .await
                .expect("push");
            client
                .call(
                    session_methods::GIVE,
                    Some(json!({
                        "id": sid,
                        "from": "chatgpt",
                        "to": "human",
                    })),
                )
                .await
                .expect("give");
            server.request_shutdown();
            let _ = handle.await;
            sid
        };

        // Phase 2: simulate process restart by constructing a fresh runtime from disk
        // (avoids Windows named-pipe first-instance races while proving persistence).
        let mut rt = DaemonRuntime::open(&paths).expect("reload runtime");
        let shown = rt
            .dispatch(session_methods::SHOW, Some(json!({ "id": sid })))
            .await
            .expect("show after restart");
        assert_eq!(shown["id"], sid);
        assert_eq!(shown["controller"]["principal_id"], "human");
        assert!(shown["observers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|o| o == "chatgpt"));

        let replay = rt
            .dispatch(
                session_methods::REPLAY,
                Some(json!({
                    "id": sid,
                    "principal": "chatgpt",
                    "from_seq": 1,
                })),
            )
            .await
            .expect("replay after restart");
        assert!(replay["chunks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["data"]
                .as_str()
                .unwrap_or("")
                .contains("before-restart")));
    }
}
