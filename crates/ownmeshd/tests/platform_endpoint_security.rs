//! fix-4: platform endpoint security for ownmeshd service socket wiring.
//!
//! Broker install/status Windows unsupported behavior is covered in
//! `ownmesh-broker` tests (`platform_endpoint_security` module / peer_credential).
//! This file focuses on `service_socket` config + transport ACL surface used by
//! the daemon.

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

use ownmesh_config::OwnMeshConfig;
use ownmesh_ipc::LocalListener;

#[test]
fn service_socket_config_rejects_world_writable_mode() {
    let mut cfg = OwnMeshConfig::default();
    cfg.service_socket.mode = Some("666".into());
    assert!(
        cfg.validate().is_err(),
        "0o666 must be rejected by schema validation"
    );
    cfg.service_socket.mode = Some("606".into());
    assert!(cfg.validate().is_err(), "other-read/write refused");
}

#[test]
fn service_socket_config_accepts_owner_group_allowed_uids() {
    let mut cfg = OwnMeshConfig::default();
    cfg.service_socket.path = Some("/tmp/ownmesh-test.sock".into());
    cfg.service_socket.owner = Some("1000".into());
    cfg.service_socket.group = Some("1000".into());
    cfg.service_socket.mode = Some("660".into());
    cfg.service_socket.allowed_uids = vec![1000];
    cfg.validate().expect("valid service_socket");
    assert_eq!(cfg.service_socket.mode_bits(), 0o660);
    assert_eq!(cfg.service_socket.owner_uid(), Some(1000));
    assert_eq!(cfg.service_socket.group_gid(), Some(1000));
}

#[test]
fn service_socket_group_bits_require_group() {
    let mut cfg = OwnMeshConfig::default();
    cfg.service_socket.mode = Some("660".into());
    // group unset → validation error
    assert!(cfg.validate().is_err());
    cfg.service_socket.group = Some("1000".into());
    cfg.validate().unwrap();
}

#[test]
fn local_listener_refuses_world_mode_configuration() {
    let err = LocalListener::configure_unix_security(None, None, Some(0o666), vec![])
        .expect_err("0666 refused");
    let msg = err.to_string();
    assert!(
        msg.contains("other") || msg.contains("fail-closed") || msg.contains("mode"),
        "{msg}"
    );
    LocalListener::clear_unix_security();
}

#[test]
fn local_listener_accepts_restrictive_mode() {
    LocalListener::configure_unix_security(None, None, Some(0o600), vec![1, 2]).expect("0600 ok");
    LocalListener::clear_unix_security();
}

#[test]
fn daemon_service_socket_fields_are_readable_from_config() {
    let mut cfg = OwnMeshConfig::default();
    cfg.service_socket.allowed_uids = vec![1, 2, 3];
    cfg.service_socket.mode = Some("600".into());
    cfg.validate().unwrap();
    assert_eq!(cfg.service_socket.allowed_uids, vec![1, 2, 3]);
    assert_eq!(cfg.service_socket.mode_bits(), 0o600);
    // Mirror what daemon.rs wires into LocalListener + AuthGate.
    LocalListener::configure_unix_security(
        cfg.service_socket.owner_uid(),
        cfg.service_socket.group_gid(),
        Some(cfg.service_socket.mode_bits()),
        cfg.service_socket.allowed_uids.clone(),
    )
    .unwrap();
    LocalListener::clear_unix_security();
}

// ─── Unix privilege boundary (cfg-gated; host may be Windows) ───────────────

#[cfg(unix)]
mod unix_socket_boundary {
    use super::*;
    use ownmesh_ipc::{
        current_os_user_id, methods, AuthGate, ClientIdentity, ClientOptions, Endpoint, IpcClient,
        IpcServer, ServerConfig,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;
    use std::time::Duration;
    use tempfile::tempdir;

    fn current_uid() -> u32 {
        current_os_user_id()
            .parse()
            .expect("unix os user id is decimal uid")
    }

    #[tokio::test]
    async fn allowed_peer_connect_hello_succeeds_disallowed_uid_rejected() {
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("svc.sock");
        let uid = current_uid();

        LocalListener::configure_unix_security(Some(uid), None, Some(0o600), vec![uid]).unwrap();

        let endpoint = Endpoint::UnixSocket(sock_path.clone());
        let auth = AuthGate::local_user().with_allowed_users(vec![uid.to_string()]);
        let server = Arc::new(IpcServer::new(
            ServerConfig::new(endpoint.clone(), auth, "ownmeshd-test", "0.0.0"),
            Arc::new(|_m, _p, _id| Box::pin(async { Ok(serde_json::json!({ "ok": true })) })),
        ));
        let serve = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve.serve().await;
        });
        tokio::time::sleep(Duration::from_millis(80)).await;

        let meta = std::fs::metadata(&sock_path).expect("socket exists");
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket mode must be 0600, got {mode:#o}");

        let client = IpcClient::new(
            endpoint.clone(),
            dir.path(),
            ClientIdentity::new("ownmesh-test", "0.0.0"),
            ClientOptions {
                request_timeout: Duration::from_secs(2),
                max_reconnect_attempts: 2,
                reconnect_base_delay: Duration::from_millis(20),
            },
        );
        // status() performs dial + ipc.hello + method dispatch.
        let _status = client.status().await.expect("allowed peer HELLO+status");
        let _ = methods::STATUS; // keep import meaningful for method name stability

        server.request_shutdown();
        let _ = handle.await;
        LocalListener::clear_unix_security();

        if uid != 0 {
            let sock2 = dir.path().join("svc2.sock");
            LocalListener::configure_unix_security(None, None, Some(0o600), vec![0]).unwrap();
            let endpoint2 = Endpoint::UnixSocket(sock2);
            let auth2 = AuthGate::local_user().with_allowed_users(vec!["0".into()]);
            let server2 = Arc::new(IpcServer::new(
                ServerConfig::new(endpoint2.clone(), auth2, "ownmeshd-test", "0.0.0"),
                Arc::new(|_m, _p, _id| Box::pin(async { Ok(serde_json::json!({ "ok": true })) })),
            ));
            let serve2 = Arc::clone(&server2);
            let handle2 = tokio::spawn(async move {
                let _ = serve2.serve().await;
            });
            tokio::time::sleep(Duration::from_millis(80)).await;

            let client2 = IpcClient::new(
                endpoint2,
                dir.path(),
                ClientIdentity::new("ownmesh-test", "0.0.0"),
                ClientOptions {
                    request_timeout: Duration::from_secs(2),
                    max_reconnect_attempts: 1,
                    reconnect_base_delay: Duration::from_millis(20),
                },
            );
            let err = client2
                .status()
                .await
                .expect_err("disallowed uid must fail");
            let msg = err.to_string().to_ascii_lowercase();
            assert!(
                msg.contains("unauthor")
                    || msg.contains("not permitted")
                    || msg.contains("allowed")
                    || msg.contains("fail-closed")
                    || msg.contains("disconnected")
                    || msg.contains("ipc"),
                "unexpected error: {msg}"
            );

            server2.request_shutdown();
            let _ = handle2.await;
            LocalListener::clear_unix_security();
        }
    }

    #[tokio::test]
    async fn acl_apply_failure_is_fail_closed() {
        let uid = current_uid();
        if uid == 0 {
            return;
        }
        let dir = tempdir().unwrap();
        let sock_path = dir.path().join("acl-fail.sock");
        LocalListener::configure_unix_security(Some(0), None, Some(0o600), vec![uid]).unwrap();

        let endpoint = Endpoint::UnixSocket(sock_path);
        let result = LocalListener::bind(endpoint).await;
        LocalListener::clear_unix_security();
        let err = match result {
            Ok(_) => panic!("chown to root without privilege must fail-closed"),
            Err(err) => err,
        };
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("fail-closed") || msg.contains("chown") || msg.contains("permission"),
            "{msg}"
        );
    }
}
