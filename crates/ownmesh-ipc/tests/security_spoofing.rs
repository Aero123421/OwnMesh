//! Black-box local IPC spoofing and daemon-managed credential tests.
//!
//! Registry storage internals are deliberately not imported here: external callers
//! must not be able to open or mutate stopped-daemon credential state.

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

use ownmesh_ipc::{
    app_error, canonicalize_principal_key, constant_time_eq, current_os_user_id, generate_token,
    methods, normalize_principal_part, read_management_credential, read_token_file, redact_secrets,
    write_token_file, AuthGate, ClientIdentity, ClientOptions, CredentialSecretResult, Endpoint,
    FrameDecoder, HelloParams, IpcBus, IpcClient, IpcError, IpcServer, OsPeerIdentity,
    PeerCredential, RedactedSecret, RpcRequest, ServerConfig, MAX_FRAME_BYTES,
};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn shared_token_and_self_reported_identity_never_select_principal() {
    let gate = AuthGate::for_user("1000");
    let os = OsPeerIdentity {
        pid: 9,
        user_id: "1000".into(),
        exe_path: Some("/bin/ownmesh".into()),
    };
    for (name, owner) in [("admin", "root"), ("root", "admin")] {
        let peer = PeerCredential {
            token: String::new(),
            client_name: name.into(),
            owner: Some(owner.into()),
            os_user_id: None,
            pid: None,
            client_credential: None,
        };
        assert_eq!(gate.resolve_principal(&os, &peer).unwrap(), "user:1000");
    }

    let peer = PeerCredential {
        token: "leftover-shared-token".into(),
        client_name: "ownmesh".into(),
        owner: None,
        os_user_id: Some("1000".into()),
        pid: Some(9),
        client_credential: None,
    };
    let err = gate.resolve_principal(&os, &peer).unwrap_err();
    assert_eq!(err.code(), "ipc_unauthorized");
    assert!(err.to_string().contains("disabled"));
}

#[test]
fn unknown_client_credential_is_rejected() {
    let gate = AuthGate::for_user("alice");
    let err = gate
        .resolve_principal(
            &OsPeerIdentity {
                pid: 1,
                user_id: "alice".into(),
                exe_path: None,
            },
            &PeerCredential {
                token: String::new(),
                client_name: "admin".into(),
                owner: Some("root".into()),
                os_user_id: None,
                pid: None,
                client_credential: Some("not-issued".into()),
            },
        )
        .unwrap_err();
    assert_eq!(err.code(), "ipc_unauthorized");
}

#[test]
fn stable_os_principal_and_alias_normalization() {
    let a = OsPeerIdentity {
        pid: 1,
        user_id: "1000".into(),
        exe_path: Some(r"C:\OwnMesh\bin\ownmesh.exe".into()),
    };
    let b = OsPeerIdentity {
        pid: 99_999,
        user_id: "1000".into(),
        exe_path: None,
    };
    assert_eq!(a.principal_key(), b.principal_key());
    assert_eq!(a.principal_key(), "user:1000");
    assert_eq!(
        normalize_principal_part(r"C:\OwnMesh\bin\..\ownmesh.exe"),
        normalize_principal_part("c:/ownmesh/ownmesh.exe")
    );
    for legacy in [
        "user:alice:exe:c:/ownmesh.exe",
        "user:alice:pid:123",
        "user:alice:exe:c:/crafted:pid:456",
    ] {
        assert_eq!(canonicalize_principal_key(legacy), "user:alice");
    }
}

#[test]
fn legacy_token_file_and_debug_output_do_not_leak_secrets() {
    let dir = tempdir().unwrap();
    let token = generate_token();
    write_token_file(dir.path(), &token).unwrap();
    assert_eq!(read_token_file(dir.path()).unwrap(), token);
    assert!(!redact_secrets(&format!("token={token}"), &[&token]).contains(&token));

    let secret = RedactedSecret::new("super-secret-material");
    assert!(constant_time_eq(
        secret.expose().as_bytes(),
        b"super-secret-material"
    ));
    for debug in [format!("{secret:?}"), format!("{secret}")] {
        assert!(!debug.contains("super-secret"));
    }
    let hello = HelloParams {
        token: "legacy-secret".into(),
        client_name: "label".into(),
        owner: Some("claim".into()),
        client_version: None,
        client_credential: Some(secret.expose().into()),
    };
    let request = RpcRequest::new(methods::HELLO, Some(serde_json::json!(hello.clone())));
    for debug in [format!("{hello:?}"), format!("{request:?}")] {
        assert!(!debug.contains("legacy-secret"));
        assert!(!debug.contains("super-secret-material"));
    }
}

#[test]
fn frame_decoder_rejects_oversize_and_tolerates_garbage() {
    let mut decoder = FrameDecoder::new();
    let error = decoder
        .push(&(u64::from(MAX_FRAME_BYTES) + 1).to_be_bytes())
        .unwrap_err();
    assert!(error.to_string().contains("frame") || error.to_string().contains("exceeds"));
    for chunk in [
        &b""[..],
        &[0xff, 0xff],
        &[0x00, 0x00, 0x00, 0x02, b'{', b'}'],
    ] {
        let _ = FrameDecoder::new().push(chunk);
    }
}

#[cfg(windows)]
#[test]
fn windows_current_user_is_attested_sid() {
    let user = current_os_user_id();
    assert!(user.starts_with("sid:"), "{user}");
    assert_eq!(user, current_os_user_id());
}

fn client(
    endpoint: Endpoint,
    runtime_dir: &std::path::Path,
    label: &str,
    credential: Option<String>,
) -> IpcClient {
    let base = IpcClient::new(
        endpoint,
        runtime_dir,
        ClientIdentity::new(label, "1"),
        ClientOptions {
            max_reconnect_attempts: 0,
            ..ClientOptions::default()
        },
    );
    match credential {
        Some(value) => base.with_client_credential(value),
        None => base,
    }
}

fn assert_unauthorized(error: IpcError) {
    assert!(
        matches!(error, IpcError::Unauthorized(_))
            || matches!(
                error,
                IpcError::Remote {
                    code: app_error::UNAUTHORIZED,
                    ..
                }
            ),
        "expected unauthorized, got {error:?}"
    );
}

#[tokio::test]
async fn narrow_server_issue_helper_enforces_client_namespace() {
    let dir = tempdir().unwrap();
    let endpoint = Endpoint::default_for(dir.path(), IpcBus::Daemon);
    let handler: ownmesh_ipc::MethodHandler = Arc::new(|_, _, identity| {
        Box::pin(async move { Ok(serde_json::json!({"principal": identity.client_name})) })
    });
    let server = Arc::new(IpcServer::new(
        ServerConfig::new(endpoint.clone(), AuthGate::local_user(), "test", "1"),
        handler,
    ));
    let secret = server.issue_client_credential("Agent-A").unwrap();
    assert!(server.issue_client_credential("path/escape").is_err());
    assert!(server
        .issue_client_credential("ownmesh-management")
        .is_err());
    let serve = Arc::clone(&server);
    let task = tokio::spawn(async move { serve.serve().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let value = client(endpoint, dir.path(), "admin-spoof", Some(secret))
        .call("who", None)
        .await
        .unwrap();
    assert_eq!(value["principal"], "client:agent-a");
    server.request_shutdown();
    task.await.unwrap();
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn production_registry_lifecycle_is_daemon_managed_and_survives_restart() {
    let dir = tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let runtime_dir = dir.path().join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let endpoint = Endpoint::default_for(&runtime_dir, IpcBus::Daemon);
    let user_id = current_os_user_id();

    let (auth, created) = AuthGate::for_user(&user_id)
        .with_daemon_registry(&state_dir)
        .unwrap();
    assert_eq!(created, ownmesh_ipc::BootstrapStatus::Created);
    let management_secret = read_management_credential(&state_dir).unwrap();
    let handler: ownmesh_ipc::MethodHandler = Arc::new(|_, _, identity| {
        Box::pin(async move { Ok(serde_json::json!({"principal": identity.client_name})) })
    });
    let server = Arc::new(IpcServer::new(
        ServerConfig::new(endpoint.clone(), auth, "production-like", "1"),
        Arc::clone(&handler),
    ));
    let serve = Arc::clone(&server);
    let task = tokio::spawn(async move { serve.serve().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let plain = client(endpoint.clone(), &runtime_dir, "client:agent-a", None);
    plain.ping().await.unwrap();
    plain.status().await.unwrap();
    assert_unauthorized(plain.call(methods::OPS_EXEC, None).await.unwrap_err());
    assert_unauthorized(
        plain
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(serde_json::json!({"client_id": "agent-a"})),
            )
            .await
            .unwrap_err(),
    );

    let management = client(
        endpoint.clone(),
        &runtime_dir,
        "spoofed-management-label",
        Some(management_secret.clone()),
    );
    let invalid = management
        .call(
            methods::CREDENTIAL_PROVISION,
            Some(serde_json::json!({
                "client_id": "agent-a",
                "principal": "admin",
                "bound_user_id": "attacker"
            })),
        )
        .await
        .unwrap_err();
    assert!(matches!(
        invalid,
        IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            ..
        }
    ));

    let provisioned: CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_PROVISION,
                Some(serde_json::json!({"client_id": "Agent-A"})),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(provisioned.client_id, "agent-a");
    assert_eq!(provisioned.principal, "client:agent-a");
    let old_agent = client(
        endpoint.clone(),
        &runtime_dir,
        "victim-admin",
        Some(provisioned.credential),
    );
    assert_eq!(
        old_agent.call("who", None).await.unwrap()["principal"],
        "client:agent-a"
    );

    let rotated: CredentialSecretResult = serde_json::from_value(
        management
            .call(
                methods::CREDENTIAL_ROTATE,
                Some(serde_json::json!({"client_id": "agent-a"})),
            )
            .await
            .unwrap(),
    )
    .unwrap();
    assert_unauthorized(old_agent.call("who", None).await.unwrap_err());

    server.request_shutdown();
    old_agent.disconnect().await;
    management.disconnect().await;
    plain.disconnect().await;
    task.await.unwrap();
    drop((server, old_agent, management, plain));
    tokio::time::sleep(Duration::from_millis(50)).await;

    let (auth, existing) = AuthGate::for_user(&user_id)
        .with_daemon_registry(&state_dir)
        .unwrap();
    assert_eq!(existing, ownmesh_ipc::BootstrapStatus::Existing);
    let restarted = Arc::new(IpcServer::new(
        ServerConfig::new(endpoint.clone(), auth, "production-like", "2"),
        handler,
    ));
    let serve = Arc::clone(&restarted);
    let task = tokio::spawn(async move { serve.serve().await.unwrap() });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let management = client(
        endpoint.clone(),
        &runtime_dir,
        "anything",
        Some(management_secret),
    );
    let agent = client(endpoint, &runtime_dir, "admin", Some(rotated.credential));
    assert_eq!(
        agent.call("who", None).await.unwrap()["principal"],
        "client:agent-a"
    );
    management
        .call(
            methods::CREDENTIAL_REVOKE,
            Some(serde_json::json!({"client_id": "agent-a"})),
        )
        .await
        .unwrap();
    assert_unauthorized(agent.call("who", None).await.unwrap_err());

    restarted.request_shutdown();
    task.await.unwrap();
}
