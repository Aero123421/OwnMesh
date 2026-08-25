//! Regression coverage for over-long Unix runtime paths (#155).
//!
//! A runtime directory can be a valid owner-controlled directory whose derived
//! socket pathname exceeds `sockaddr_un::sun_path`. These tests prove the
//! resolver produces an endpoint that actually binds and that a client derives
//! the identical endpoint from the same runtime directory.

#![cfg(unix)]

use ownmesh_ipc::{connect, Endpoint, IpcBus, LocalListener};
use std::path::PathBuf;

/// Runtime directory long enough that `{dir}/ownmesh-daemon.sock` cannot be bound.
fn over_limit_runtime_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ownmesh-long-{tag}-{}",
        "x".repeat(Endpoint::unix_path_capacity())
    ));
    std::fs::create_dir_all(&dir).expect("runtime dir is a valid filesystem path");
    dir
}

#[tokio::test]
async fn over_long_runtime_dir_still_binds_and_accepts() {
    let runtime = over_limit_runtime_dir("bind");
    let endpoint = Endpoint::default_for(&runtime, IpcBus::Daemon);
    endpoint
        .ensure_bindable()
        .expect("endpoint must be bindable");

    let listener = LocalListener::bind(endpoint.clone())
        .await
        .expect("bind must succeed for a long but valid runtime dir");

    // A client resolving from the same runtime dir reaches the same listener.
    let client_endpoint = Endpoint::default_for(&runtime, IpcBus::Daemon);
    assert_eq!(client_endpoint, endpoint);
    let accept = tokio::spawn(async move { listener.accept().await.map(|_| ()) });
    // Hold the client connection open across the accept. macOS resolves peer
    // credentials through `LOCAL_PEERCRED`, which fails closed with ENOTCONN
    // once the peer has gone; letting this bind drop early would race the
    // server's fail-closed credential check rather than test the endpoint.
    let client = connect(&client_endpoint)
        .await
        .expect("client connect must reach the bound listener");
    accept.await.expect("accept task").expect("accept");
    drop(client);

    let _ = std::fs::remove_dir_all(&runtime);
}

#[tokio::test]
async fn shortened_root_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;

    let runtime = over_limit_runtime_dir("mode");
    let endpoint = Endpoint::default_for(&runtime, IpcBus::SessionSupervisor);
    let Endpoint::UnixSocket(path) = &endpoint else {
        panic!("expected a unix socket endpoint");
    };
    let root = path.parent().expect("fallback root").to_path_buf();
    assert!(Endpoint::is_short_socket_root(&root));

    let listener = LocalListener::bind(endpoint.clone())
        .await
        .expect("bind must succeed");
    let mode = std::fs::symlink_metadata(&root)
        .expect("fallback root exists after bind")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "fallback root must not be group/world accessible"
    );

    drop(listener);
    let _ = std::fs::remove_dir_all(&runtime);
}

#[test]
fn distinct_over_long_runtime_dirs_do_not_share_an_endpoint() {
    let a = Endpoint::default_for(&over_limit_runtime_dir("iso-a"), IpcBus::Daemon);
    let b = Endpoint::default_for(&over_limit_runtime_dir("iso-b"), IpcBus::Daemon);
    assert_ne!(a, b);
    a.ensure_bindable().unwrap();
    b.ensure_bindable().unwrap();
}
