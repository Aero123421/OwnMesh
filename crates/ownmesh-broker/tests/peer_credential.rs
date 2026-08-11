//! sec-02: peer credential gate — unverifiable endpoints/connections are fail-closed.

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

use ownmesh_broker::peer::{
    assert_endpoint_peer_verifiable, loopback_tcp_peer_unverifiable_error,
    named_pipe_peer_unverifiable_error, peer_uid_allowed,
};
use ownmesh_broker::{run_broker, BrokerServeConfig};
use ownmesh_broker_client::{BrokerEndpoint, PeerCred};
use std::net::SocketAddr;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn production_refuses_loopback_tcp_endpoint() {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let err = assert_endpoint_peer_verifiable(&BrokerEndpoint::LoopbackTcp(addr)).unwrap_err();
    assert!(err.contains("fail-closed"), "{err}");
    assert!(
        err.to_ascii_lowercase().contains("loopback") || err.to_ascii_lowercase().contains("peer"),
        "{err}"
    );
    // Message is stable for operators / automation.
    assert_eq!(err, loopback_tcp_peer_unverifiable_error());
}

#[test]
fn production_refuses_named_pipe_without_safe_peer_cred() {
    let err = assert_endpoint_peer_verifiable(&BrokerEndpoint::NamedPipe(
        r"\\.\pipe\ownmesh-privileged-test".into(),
    ))
    .unwrap_err();
    assert!(err.contains("fail-closed"), "{err}");
    assert_eq!(err, named_pipe_peer_unverifiable_error());
}

#[test]
fn peer_uid_rejects_when_not_own_and_not_allowlisted() {
    let peer = PeerCred {
        pid: 42,
        uid: 1001,
        gid: 1001,
    };
    assert!(!peer_uid_allowed(&peer, &[], 1000), "empty list denies");
    assert!(!peer_uid_allowed(&peer, &[0, 1000], 1000));
    assert!(peer_uid_allowed(&peer, &[1001], 0));
    assert!(!peer_uid_allowed(&peer, &[], 1001));
}

#[tokio::test]
async fn run_broker_errors_on_loopback_tcp_before_accept() {
    let dir = tempdir().unwrap();
    let cfg = BrokerServeConfig {
        endpoint: BrokerEndpoint::LoopbackTcp("127.0.0.1:0".parse().unwrap()),
        secret_file: dir.path().join("secret.bin"),
        signing_key_file: dir.path().join("private").join("broker.cap.signing"),
        trusted_executable: dir.path().join("ownmeshd"),
        allowed_uids: vec![1000],
        socket_security: ownmesh_broker::UnixSocketSecurity {
            owner_uid: 0,
            group_gid: 0,
            mode: 0o600,
        },
        addr_file: None,
    };
    let err = tokio::time::timeout(Duration::from_secs(5), run_broker(cfg))
        .await
        .expect("run_broker should return promptly")
        .expect_err("LoopbackTcp must be rejected");
    assert!(
        err.contains("LoopbackTcp") && err.contains("fail-closed"),
        "{err}"
    );
}

#[tokio::test]
async fn run_broker_errors_on_named_pipe_before_accept() {
    let dir = tempdir().unwrap();
    let cfg = BrokerServeConfig {
        endpoint: BrokerEndpoint::NamedPipe(r"\\.\pipe\ownmesh-sec02-test".into()),
        secret_file: dir.path().join("secret.bin"),
        signing_key_file: dir.path().join("private").join("broker.cap.signing"),
        trusted_executable: dir.path().join("ownmeshd"),
        allowed_uids: vec![1000],
        socket_security: ownmesh_broker::UnixSocketSecurity {
            owner_uid: 0,
            group_gid: 0,
            mode: 0o600,
        },
        addr_file: None,
    };
    let err = tokio::time::timeout(Duration::from_secs(5), run_broker(cfg))
        .await
        .expect("run_broker should return promptly")
        .expect_err("NamedPipe must be rejected without safe peer cred");
    assert!(
        err.contains("NamedPipe") && err.contains("fail-closed"),
        "{err}"
    );
}

#[cfg(target_os = "linux")]
mod unix_peer {
    use super::*;
    use ownmesh_broker::peer::{authorize_unix_peer, check_unix_peer, current_uid};
    use ownmesh_broker::TrustedPeerPolicy;
    use std::sync::Arc;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn so_peercred_accepts_same_uid_and_rejects_disallowed_uid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let b_client = Arc::clone(&barrier);
        let client_path = path.clone();
        let client = tokio::spawn(async move {
            let stream = UnixStream::connect(client_path).await.unwrap();
            b_client.wait().await;
            stream
        });

        let (server, _) = listener.accept().await.unwrap();
        barrier.wait().await;

        let check = check_unix_peer(&server).expect("SO_PEERCRED + PID exe must succeed");
        assert_eq!(check.cred.uid, current_uid());
        assert!(check.method.contains("SO_PEERCRED"));

        // A merely claimed path/UID policy is insufficient for production minting;
        // it must have been loaded and pinned from root-controlled executable custody.
        let unpinned = TrustedPeerPolicy::new(
            std::path::PathBuf::from(&check.exe_path),
            vec![current_uid()],
        )
        .unwrap();
        let err = authorize_unix_peer(&server, &unpinned)
            .expect_err("untrusted executable custody must reject production stream");
        assert!(
            err.contains("not pinned") && err.contains("fail-closed"),
            "{err}"
        );

        // If the test binary itself happens to be installed under root-controlled
        // ancestry, exercise the positive production-stream path as well.
        if let Ok(pinned) = ownmesh_broker::load_trusted_peer_policy(
            std::path::Path::new(&check.exe_path),
            vec![current_uid()],
        ) {
            authorize_unix_peer(&server, &pinned)
                .expect("pinned exact executable and UID must be accepted");
        }

        drop(client.await.unwrap());
    }

    #[tokio::test]
    async fn run_broker_accepts_unix_socket_endpoint_gate() {
        // Only the peer-verifiable gate: binding a real long-lived broker is out of scope.
        let path = tempdir().unwrap().path().join("gate.sock");
        assert_endpoint_peer_verifiable(&BrokerEndpoint::UnixSocket(path)).unwrap();
    }
}
