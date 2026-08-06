//! sec-02: peer credential gate — unverifiable endpoints/connections are fail-closed.

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
    assert!(
        !peer_uid_allowed(&peer, &[], 1000),
        "empty list => own uid only"
    );
    assert!(!peer_uid_allowed(&peer, &[0, 1000], 1000));
    assert!(peer_uid_allowed(&peer, &[1001], 0));
    assert!(peer_uid_allowed(&peer, &[], 1001));
}

#[tokio::test]
async fn run_broker_errors_on_loopback_tcp_before_accept() {
    let dir = tempdir().unwrap();
    let cfg = BrokerServeConfig {
        endpoint: BrokerEndpoint::LoopbackTcp("127.0.0.1:0".parse().unwrap()),
        secret_file: dir.path().join("secret.bin"),
        allow_callers: vec!["ownmeshd".into()],
        addr_file: None,
    };
    let err = tokio::time::timeout(Duration::from_secs(5), run_broker(cfg))
        .await
        .expect("run_broker should return promptly")
        .expect_err("LoopbackTcp must be rejected");
    assert!(err.contains("fail-closed"), "{err}");
}

#[tokio::test]
async fn run_broker_errors_on_named_pipe_before_accept() {
    let dir = tempdir().unwrap();
    let cfg = BrokerServeConfig {
        endpoint: BrokerEndpoint::NamedPipe(r"\\.\pipe\ownmesh-sec02-test".into()),
        secret_file: dir.path().join("secret.bin"),
        allow_callers: vec!["ownmeshd".into()],
        addr_file: None,
    };
    let err = tokio::time::timeout(Duration::from_secs(5), run_broker(cfg))
        .await
        .expect("run_broker should return promptly")
        .expect_err("NamedPipe must be rejected without safe peer cred");
    assert!(err.contains("fail-closed"), "{err}");
}

#[cfg(unix)]
mod unix_peer {
    use super::*;
    use ownmesh_broker::peer::{authorize_unix_peer, check_unix_peer, current_uid};
    use std::sync::Arc;
    use tokio::net::{UnixListener, UnixStream};
    use tokio::sync::Barrier;

    #[tokio::test]
    async fn so_peercred_accepts_same_uid_and_rejects_disallowed_uid() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peer.sock");
        let listener = UnixListener::bind(&path).await.unwrap();
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

        let check = check_unix_peer(&server).expect("SO_PEERCRED must succeed on Unix");
        let cred = check.cred.expect("cred present");
        assert_eq!(cred.uid, current_uid());
        assert_eq!(check.method, "SO_PEERCRED");

        authorize_unix_peer(&server, &[])
            .expect("same-uid peer must be accepted with default policy");

        if current_uid() != 0 {
            let err = authorize_unix_peer(&server, &[0]).expect_err("uid 0-only list");
            assert!(
                err.contains("not permitted") && err.contains("fail-closed"),
                "{err}"
            );
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
