//! OwnMesh networkless privileged broker library.
//!
//! **Production elevated broker is unsupported** until a secure mint authority
//! is established. `run_broker` / install / status never bind or claim success.
//!
//! In-process test helpers may still exercise MAC/capability over loopback TCP
//! with a synthetic peer bind (`execute_verified*`, `handle_tcp_conn`) — these
//! paths are unreachable from production CLI entry points.
//!
//! Never opens outbound network connections or non-loopback listeners.
//!
//! References:
//! - https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights
//! - https://www.man7.org/linux/man-pages/man7/unix.7.html
//! - https://www.man7.org/linux/man-pages/man7/socket.7.html

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::doc_markdown,
    clippy::struct_excessive_bools,
    clippy::too_many_lines,
    clippy::needless_return,
    clippy::map_unwrap_or,
    clippy::cast_possible_wrap,
    clippy::too_many_arguments,
    clippy::single_match_else,
    clippy::unnecessary_wraps
)]

mod install;
pub mod peer;
mod serve;

pub use install::{
    broker_status, endpoint_kind_peer_enforceable, install_broker, install_broker_with_config,
    uninstall_broker, BrokerInstallConfig, InstallRecord, InstallStatus, INSTALL_FILE,
};
pub use peer::{
    assert_endpoint_peer_verifiable, endpoint_supports_peer_cred_enforcement,
    load_trusted_peer_policy, peer_uid_allowed, PeerCheck, TrustedPeerPolicy,
};
pub use serve::{
    default_signing_key_path, default_verify_key_path, enforce_bind_is_networkless,
    ensure_broker_key_separation, execute_verified, execute_verified_for_process, handle_tcp_conn,
    load_or_create_capability_keys, load_or_create_request_secret, load_or_create_secret,
    load_verify_key, production_elevated_broker_unsupported, run_broker,
    validate_daemon_dac_policy, validate_daemon_directory_custody_metadata,
    validate_request_secret_custody_metadata, validate_signing_custody_metadata,
    validate_signing_key_custody, validate_socket_custody_metadata, validate_verify_key_custody,
    validate_verify_key_custody_metadata, BrokerServeConfig, BrokerState, CustodyMetadata,
    SocketCustodyMetadata, UnixSocketSecurity, CAPABILITY_SIGNING_FILE, CAPABILITY_VERIFY_FILE,
};

use ownmesh_broker_client::DEFAULT_BROKER_ENDPOINT;

/// Stable crate name.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Package version.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Default endpoint basename.
#[must_use]
pub fn default_endpoint_name() -> &'static str {
    DEFAULT_BROKER_ENDPOINT
}

/// Unix epoch seconds.
#[must_use]
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_broker_client::{
        build_request, build_request_with_capability, connect_and_call, elevate, verify_request,
        BrokerEndpoint, BrokerRequest, BrokerSecret, CapabilitySigningKey, CapabilityToken,
        ElevatedCommand, PeerBind, ReplayCache, ELEVATED_CAPABILITY_SCOPE,
    };
    use std::net::SocketAddr;
    use std::path::PathBuf;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Mutex as AsyncMutex;

    fn test_peer() -> PeerBind {
        PeerBind::new(4242, peer::current_uid(), "ownmeshd-test")
    }

    fn test_keys() -> (
        CapabilitySigningKey,
        ownmesh_broker_client::CapabilityVerifyKey,
    ) {
        let sk = CapabilitySigningKey::generate();
        let vk = sk.verify_key();
        (sk, vk)
    }

    #[test]
    fn rejects_non_loopback_bind_config() {
        let addr: SocketAddr = "8.8.8.8:9".parse().unwrap();
        assert!(enforce_bind_is_networkless(addr).is_err());
        let addr: SocketAddr = "0.0.0.0:9".parse().unwrap();
        assert!(enforce_bind_is_networkless(addr).is_err());
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        assert!(enforce_bind_is_networkless(addr).is_ok());
    }

    #[test]
    fn networkless_enforcement_covers_common_non_loopback() {
        for s in ["0.0.0.0:1", "1.1.1.1:53", "10.0.0.1:80", "[::]:443"] {
            let addr: SocketAddr = s.parse().unwrap();
            let err = enforce_bind_is_networkless(addr).unwrap_err();
            assert!(
                err.contains("networkless") || err.contains("loopback"),
                "{err}"
            );
        }
    }

    #[test]
    fn peer_mismatch_rejected_not_principal_string() {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("sec");
        let secret = load_or_create_secret(&secret_path).unwrap();
        let (sk, vk) = test_keys();
        let peer = test_peer();
        let other = PeerBind::new(peer.pid + 1, peer.uid, peer.exe_path.clone());
        // Attacker sets caller_principal to a trusted label but wrong peer bind.
        let cap = CapabilityToken::issue_for_operation(
            &sk,
            &other,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            now_unix(),
            30,
        );
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "echo".into()
                },
                args: if cfg!(windows) {
                    vec!["/C".into(), "echo no".into()]
                } else {
                    vec!["no".into()]
                },
                cwd: None,
                env: vec![],
            },
            Some(cap),
            now_unix(),
            30,
        );
        let mut replay = ReplayCache::new();
        let err =
            execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix()).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("unauthor")
                || err.to_ascii_lowercase().contains("signature")
                || err.to_ascii_lowercase().contains("peer"),
            "{err}"
        );
    }

    #[test]
    fn replay_and_nonce_rejected() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = test_keys();
        let peer = test_peer();
        let now = now_unix();
        let cap = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            now,
            60,
        );
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "echo".into(),
                args: vec!["x".into()],
                cwd: None,
                env: vec![],
            },
            Some(cap),
            now,
            60,
        );
        let mut replay = ReplayCache::new();
        let _ = execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix()).unwrap();
        let err =
            execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix()).unwrap_err();
        assert!(err.to_lowercase().contains("replay"), "{err}");
    }

    #[test]
    fn malformed_request_rejected() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = test_keys();
        let peer = test_peer();
        // Missing mac / garbage
        let bad = BrokerRequest {
            protocol_version: 1,
            request_id: "r".into(),
            operation_id: "o".into(),
            nonce: "n".into(),
            issued_at_unix: now_unix(),
            expires_at_unix: now_unix() + 30,
            caller_principal: "ownmeshd".into(),
            capability: None,
            command: ElevatedCommand {
                program: "echo".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            mac: "deadbeef".into(),
        };
        assert!(verify_request(&secret, &vk, &bad, &peer, now_unix()).is_err());
        let mut replay = ReplayCache::new();
        let err =
            execute_verified(&secret, &sk, &vk, &mut replay, &bad, &peer, now_unix()).unwrap_err();
        assert!(!err.is_empty());

        // Empty program after valid mac path
        let mut req = build_request(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "echo".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            now_unix(),
            30,
        );
        req.command.program.clear();
        req.mac = ownmesh_broker_client::compute_mac(&secret, &req);
        assert!(verify_request(&secret, &vk, &req, &peer, now_unix()).is_err());
    }

    #[test]
    fn production_install_is_canonical_unsupported() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let st = broker_status(base).unwrap();
        assert!(!st.installed);
        assert_eq!(st.support, "unsupported");

        let err = install_broker(base, None).expect_err("production install is unsupported");
        assert!(
            err.contains("unsupported") && err.contains("no filesystem changes"),
            "{err}"
        );
        assert!(!base.join("broker").exists());
    }

    #[test]
    fn unsupported_install_and_uninstall_are_side_effect_free() {
        let dir = tempdir().unwrap();
        let install_base = dir.path().join("new-state");
        let err = install_broker_with_config(
            &install_base,
            BrokerInstallConfig {
                endpoint: Some(BrokerEndpoint::NamedPipe("ignored".into())),
                trusted_executable: PathBuf::from("ignored"),
                socket_security: UnixSocketSecurity {
                    owner_uid: 0,
                    group_gid: 0,
                    mode: 0o600,
                },
                allowed_uids: vec![0],
            },
        )
        .expect_err("configured production install is unsupported");
        assert!(err.contains("unsupported"), "{err}");
        assert!(!install_base.exists(), "install must not create state");

        let broker_dir = dir.path().join("existing-state").join("broker");
        std::fs::create_dir_all(&broker_dir).unwrap();
        let marker = broker_dir.join(INSTALL_FILE);
        let template = broker_dir.join("ownmesh-broker.service");
        std::fs::write(&marker, b"operator marker").unwrap();
        std::fs::write(&template, b"operator template").unwrap();

        let err = uninstall_broker(&dir.path().join("existing-state"))
            .expect_err("production uninstall is unsupported");
        assert!(
            err.contains("unsupported") && err.contains("no filesystem changes"),
            "{err}"
        );
        assert_eq!(std::fs::read(marker).unwrap(), b"operator marker");
        assert_eq!(std::fs::read(template).unwrap(), b"operator template");
    }

    #[test]
    fn windows_or_named_pipe_never_reports_installed_true() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        // Force a Named Pipe endpoint even on Unix — still unenforceable.
        let ep = BrokerEndpoint::NamedPipe(r"\\.\pipe\ownmesh-lib-test".into());
        assert!(!endpoint_supports_peer_cred_enforcement(&ep));
        let err = install_broker(base, Some(ep)).expect_err("named pipe install");
        assert!(err.to_ascii_lowercase().contains("unsupported"), "{err}");
        let st = broker_status(base).unwrap();
        assert!(!st.installed);
        assert_eq!(st.support, "unsupported");
    }

    #[test]
    fn legacy_installed_marker_cleared_without_peer_enforcement() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let broker = base.join("broker");
        std::fs::create_dir_all(&broker).unwrap();
        // Simulate a pre-fix marker that falsely claimed success on Named Pipe.
        let fake = serde_json::json!({
            "installed": true,
            "installed_at_unix": 1,
            "endpoint": r"\\.\pipe\ownmesh",
            "endpoint_kind": "named_pipe",
            "unit_path": null,
            "secret_file": broker.join("broker.secret").display().to_string(),
            "signing_key_file": "",
            "verify_key_file": "",
            "notes": ["legacy"],
            "support": "supported"
        });
        std::fs::write(
            broker.join("broker-install.json"),
            serde_json::to_string_pretty(&fake).unwrap(),
        )
        .unwrap();
        let st = broker_status(base).unwrap();
        assert!(!st.installed, "legacy installed=true must be cleared");
        assert_eq!(st.support, "unsupported");
    }

    #[test]
    fn mac_secret_holder_cannot_mint_under_broker_verify_key() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = test_keys();
        let peer = test_peer();
        // Derive a signing key from the MAC secret — must not verify under broker key.
        let evil = CapabilitySigningKey::from_bytes(secret.as_bytes()).unwrap();
        let forged = CapabilityToken::issue_for_operation(
            &evil,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            now_unix(),
            60,
        );
        assert!(forged.verify(&vk, now_unix()).is_err());
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "echo".into(),
                args: vec!["x".into()],
                cwd: None,
                env: vec![],
            },
            Some(forged),
            now_unix(),
            60,
        );
        let mut replay = ReplayCache::new();
        let err =
            execute_verified(&secret, &sk, &vk, &mut replay, &req, &peer, now_unix()).unwrap_err();
        assert!(
            err.to_ascii_lowercase().contains("signature")
                || err.to_ascii_lowercase().contains("invalid"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn e2e_loopback_exec_and_replay_defense() {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("secret.bin");
        let secret = load_or_create_secret(&secret_path).unwrap();
        let signing_key = CapabilitySigningKey::generate();
        let verify_key = signing_key.verify_key();
        let signing_for_request =
            CapabilitySigningKey::from_bytes(&signing_key.to_bytes()).unwrap();
        let secret_bytes = secret.as_bytes().to_vec();
        let peer = test_peer();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback());

        let state = Arc::new(AsyncMutex::new(BrokerState {
            secret: BrokerSecret::from_bytes(secret_bytes.clone()),
            signing_key,
            verify_key,
            replay: ReplayCache::new(),
        }));

        let st = Arc::clone(&state);
        let peer_srv = peer.clone();
        let server = tokio::spawn(async move {
            let (sock, peer_addr) = listener.accept().await.unwrap();
            assert!(peer_addr.ip().is_loopback());
            serve::handle_tcp_conn(sock, st, peer_srv).await.unwrap();
        });

        let endpoint = BrokerEndpoint::LoopbackTcp(addr);
        let secret = BrokerSecret::from_bytes(secret_bytes);
        let resp = elevate(
            &endpoint,
            &secret,
            "ownmeshd",
            "op_e2e",
            ElevatedCommand {
                program: if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "echo".into()
                },
                args: if cfg!(windows) {
                    vec!["/C".into(), "echo broker-ok".into()]
                } else {
                    vec!["broker-ok".into()]
                },
                cwd: None,
                env: vec![],
            },
            now_unix(),
            60,
        )
        .await
        .unwrap();
        assert!(!resp.ok, "synthetic TCP must not mint: {resp:?}");
        assert!(
            resp.error.as_deref().unwrap_or("").contains("mint denied"),
            "{resp:?}"
        );

        // A genuinely broker-signed capability is accepted once and replayed requests fail.
        let now = now_unix();
        let cap = CapabilityToken::issue_for_operation(
            &signing_for_request,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op_replay",
            now,
            60,
        );
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op_replay",
            ElevatedCommand {
                program: if cfg!(windows) {
                    "cmd.exe".into()
                } else {
                    "echo".into()
                },
                args: if cfg!(windows) {
                    vec!["/C".into(), "echo x".into()]
                } else {
                    vec!["x".into()]
                },
                cwd: None,
                env: vec![],
            },
            Some(cap),
            now,
            60,
        );
        // start second accept loop
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let st2 = Arc::clone(&state);
        let peer2 = peer.clone();
        let server2 = tokio::spawn(async move {
            for _ in 0..2 {
                let (sock, _) = listener2.accept().await.unwrap();
                let st = Arc::clone(&st2);
                let _ = serve::handle_tcp_conn(sock, st, peer2.clone()).await;
            }
        });
        let ep2 = BrokerEndpoint::LoopbackTcp(addr2);
        let r1 = connect_and_call(&ep2, &req).await.unwrap();
        assert!(
            r1.ok || r1.error.is_none() || r1.exit_code.is_some(),
            "{r1:?}"
        );
        let r2 = connect_and_call(&ep2, &req).await.unwrap();
        assert!(!r2.ok);
        assert!(
            r2.error
                .as_deref()
                .unwrap_or("")
                .to_lowercase()
                .contains("replay"),
            "{r2:?}"
        );

        let _ = server.await;
        let _ = server2.await;
    }

    #[tokio::test]
    async fn forged_capability_over_wire_rejected() {
        let dir = tempdir().unwrap();
        let secret = load_or_create_secret(&dir.path().join("s")).unwrap();
        let sk = CapabilitySigningKey::generate();
        let vk = sk.verify_key();
        let secret_bytes = secret.as_bytes().to_vec();
        let peer = test_peer();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(AsyncMutex::new(BrokerState {
            secret: BrokerSecret::from_bytes(secret_bytes.clone()),
            signing_key: sk,
            verify_key: vk,
            replay: ReplayCache::new(),
        }));
        let st = Arc::clone(&state);
        let peer_srv = peer.clone();
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            serve::handle_tcp_conn(sock, st, peer_srv).await.unwrap();
        });
        let secret = BrokerSecret::from_bytes(secret_bytes);
        // Mint with a key derived from the MAC secret (ownmeshd-equivalent attacker).
        let evil = CapabilitySigningKey::from_bytes(secret.as_bytes()).unwrap();
        let forged = CapabilityToken::issue_for_operation(
            &evil,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            now_unix(),
            30,
        );
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "echo".into(),
                args: vec!["x".into()],
                cwd: None,
                env: vec![],
            },
            Some(forged),
            now_unix(),
            30,
        );
        let resp = connect_and_call(&BrokerEndpoint::LoopbackTcp(addr), &req)
            .await
            .unwrap();
        assert!(!resp.ok);
        let err = resp.error.unwrap_or_default().to_ascii_lowercase();
        assert!(
            err.contains("signature") || err.contains("invalid") || err.contains("unauthor"),
            "{err}"
        );
        let _ = server.await;
    }
}
