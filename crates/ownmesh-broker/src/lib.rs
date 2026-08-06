//! `OwnMesh` networkless privileged broker library.
//!
//! Listens only on local IPC:
//! - Windows Named Pipe (default ACL grants creator/admin/LocalSystem; see Microsoft docs)
//! - Unix domain socket mode 0600 + Linux `SO_PEERCRED` peer checks
//! - Loopback TCP fallback for portable tests (`127.0.0.1` / `::1` only)
//!
//! Never opens outbound network connections or non-loopback listeners.
//!
//! References:
//! - <https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights>
//! - <https://www.man7.org/linux/man-pages/man7/unix.7.html>
//! - <https://www.man7.org/linux/man-pages/man7/socket.7.html>

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod install;
mod peer;
mod serve;

pub use install::{broker_status, install_broker, uninstall_broker, InstallRecord, InstallStatus};
pub use serve::{
    enforce_bind_is_networkless, execute_verified, load_or_create_secret, run_broker,
    BrokerServeConfig, BrokerState,
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
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_broker_client::{
        build_request, connect_and_call, elevate, verify_request, BrokerEndpoint, BrokerRequest,
        BrokerSecret, ElevatedCommand, ReplayCache,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tempfile::tempdir;
    use tokio::sync::Mutex as AsyncMutex;

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
    fn unprivileged_caller_rejected() {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("sec");
        let secret = load_or_create_secret(&secret_path).unwrap();
        let req = build_request(
            &secret,
            "evil",
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
            now_unix(),
            30,
        );
        let mut replay = ReplayCache::new();
        let resp =
            execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix()).unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("unauthorized caller"));
    }

    #[test]
    fn replay_and_nonce_rejected() {
        let secret = BrokerSecret::generate();
        let req = build_request(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "echo".into(),
                args: vec!["x".into()],
                cwd: None,
                env: vec![],
            },
            now_unix(),
            60,
        );
        let mut replay = ReplayCache::new();
        let _ =
            execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix()).unwrap();
        let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &req, now_unix())
            .unwrap_err();
        assert!(err.to_lowercase().contains("replay"), "{err}");
    }

    #[test]
    fn malformed_request_rejected() {
        let secret = BrokerSecret::generate();
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
        assert!(verify_request(&secret, &bad, now_unix()).is_err());
        let mut replay = ReplayCache::new();
        let err = execute_verified(&secret, &mut replay, &["ownmeshd".into()], &bad, now_unix())
            .unwrap_err();
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
        assert!(verify_request(&secret, &req, now_unix()).is_err());
    }

    #[test]
    fn install_status_uninstall_roundtrip() {
        let dir = tempdir().unwrap();
        let base = dir.path();
        let st = broker_status(base).unwrap();
        assert!(!st.installed);

        let rec = install_broker(base, None).unwrap();
        assert!(rec.installed);
        let st = broker_status(base).unwrap();
        assert!(st.installed);
        assert!(!st.endpoint_kind.is_empty());

        uninstall_broker(base).unwrap();
        let st = broker_status(base).unwrap();
        assert!(!st.installed);
    }

    #[tokio::test]
    async fn e2e_loopback_exec_and_replay_defense() {
        let dir = tempdir().unwrap();
        let secret_path = dir.path().join("secret.bin");
        let secret = load_or_create_secret(&secret_path).unwrap();
        let secret_bytes = secret.as_bytes().to_vec();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert!(addr.ip().is_loopback());

        let state = Arc::new(AsyncMutex::new(BrokerState {
            secret: BrokerSecret::from_bytes(secret_bytes.clone()),
            replay: ReplayCache::new(),
            allowed_callers: vec!["ownmeshd".into()],
            require_capability: false,
        }));

        let st = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let (sock, peer) = listener.accept().await.unwrap();
            assert!(peer.ip().is_loopback());
            serve::handle_tcp_conn(sock, st).await.unwrap();
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
        assert!(resp.ok, "{resp:?}");
        assert!(resp.stdout.contains("broker-ok"), "{resp:?}");

        // Same request body replay via connect_and_call must fail at server.
        let req = build_request(
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
            now_unix(),
            60,
        );
        // start second accept loop
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr2 = listener2.local_addr().unwrap();
        let st2 = Arc::clone(&state);
        let server2 = tokio::spawn(async move {
            for _ in 0..2 {
                let (sock, _) = listener2.accept().await.unwrap();
                let st = Arc::clone(&st2);
                let _ = serve::handle_tcp_conn(sock, st).await;
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
    async fn unprivileged_over_wire_rejected() {
        let dir = tempdir().unwrap();
        let secret = load_or_create_secret(&dir.path().join("s")).unwrap();
        let secret_bytes = secret.as_bytes().to_vec();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let state = Arc::new(AsyncMutex::new(BrokerState {
            secret: BrokerSecret::from_bytes(secret_bytes.clone()),
            replay: ReplayCache::new(),
            allowed_callers: vec!["ownmeshd".into()],
            require_capability: false,
        }));
        let st = Arc::clone(&state);
        let server = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            serve::handle_tcp_conn(sock, st).await.unwrap();
        });
        let secret = BrokerSecret::from_bytes(secret_bytes);
        let req = build_request(
            &secret,
            "not-allowed",
            "op",
            ElevatedCommand {
                program: "echo".into(),
                args: vec!["x".into()],
                cwd: None,
                env: vec![],
            },
            now_unix(),
            30,
        );
        let resp = connect_and_call(&BrokerEndpoint::LoopbackTcp(addr), &req)
            .await
            .unwrap();
        assert!(!resp.ok);
        assert_eq!(resp.error.as_deref(), Some("unauthorized caller"));
        let _ = server.await;
    }
}
