//! Production elevated broker is fixed as unsupported — no success wire E2E.
#![cfg(target_os = "linux")]

use ownmesh_broker::{
    broker_status, install_broker_with_config, production_elevated_broker_unsupported, run_broker,
    BrokerInstallConfig, BrokerServeConfig, UnixSocketSecurity,
};
use ownmesh_broker_client::BrokerEndpoint;
use std::path::PathBuf;
use std::time::Duration;

fn secure_run_dir() -> PathBuf {
    PathBuf::from(std::env::temp_dir()).join(format!(
        "ownmesh-broker-wire-unsup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

#[tokio::test]
async fn production_run_broker_is_explicitly_unsupported() {
    let base = secure_run_dir();
    let _ = std::fs::create_dir_all(&base);
    let err = run_broker(BrokerServeConfig {
        endpoint: BrokerEndpoint::UnixSocket(base.join("broker.sock")),
        secret_file: base.join("broker.secret"),
        signing_key_file: base.join("private").join("broker.cap.signing"),
        trusted_executable: std::env::current_exe().unwrap(),
        allowed_uids: vec![rustix::process::geteuid().as_raw()],
        socket_security: UnixSocketSecurity {
            owner_uid: rustix::process::geteuid().as_raw(),
            group_gid: 0,
            mode: 0o600,
        },
        addr_file: None,
    })
    .await
    .expect_err("production run_broker must be unsupported");
    assert!(
        err.contains("unsupported") && err.contains("fail-closed"),
        "expected production unsupported, got: {err}"
    );
    assert_eq!(err, production_elevated_broker_unsupported());
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn production_install_and_status_never_claim_success() {
    let base = secure_run_dir();
    let _ = std::fs::create_dir_all(&base);
    let endpoint_path = base.join("runtime").join("ownmesh-broker.sock");
    let uid = rustix::process::geteuid().as_raw();
    let install_err = install_broker_with_config(
        &base,
        BrokerInstallConfig {
            endpoint: Some(BrokerEndpoint::UnixSocket(endpoint_path)),
            trusted_executable: std::env::current_exe().unwrap(),
            socket_security: UnixSocketSecurity {
                owner_uid: uid,
                group_gid: 0,
                mode: 0o600,
            },
            allowed_uids: vec![uid],
        },
    )
    .expect_err("install must refuse success");
    assert!(
        install_err.to_ascii_lowercase().contains("unsupported"),
        "{install_err}"
    );
    assert!(
        !base.join("broker").exists(),
        "unsupported install must not create privileged state"
    );

    let st = broker_status(&base).unwrap();
    assert!(!st.installed, "{st:?}");
    assert_eq!(st.support, "unsupported");
    assert!(
        st.notes
            .iter()
            .any(|n| n.to_ascii_lowercase().contains("unsupported")),
        "{st:?}"
    );

    // Hand-written success record must not flip status to installed/supported.
    let broker_dir = base.join("broker");
    let _ = std::fs::create_dir_all(&broker_dir);
    let fake = serde_json::json!({
        "installed": true,
        "installed_at_unix": 1,
        "endpoint": "/tmp/fake.sock",
        "endpoint_kind": "unix_socket",
        "unit_path": null,
        "secret_file": broker_dir.join("broker.secret").display().to_string(),
        "signing_key_file": broker_dir.join("private").join("broker.cap.signing").display().to_string(),
        "verify_key_file": broker_dir.join("broker.cap.verify").display().to_string(),
        "trusted_executable": std::env::current_exe().unwrap().display().to_string(),
        "socket_owner_uid": uid,
        "socket_group_gid": 0,
        "socket_mode": 0o600,
        "allowed_uids": [uid],
        "notes": ["forged success"],
        "support": "supported"
    });
    std::fs::write(
        broker_dir.join("broker-install.json"),
        serde_json::to_string_pretty(&fake).unwrap(),
    )
    .unwrap();
    let st = broker_status(&base).unwrap();
    assert!(
        !st.installed,
        "forged installed=true must be cleared: {st:?}"
    );
    assert_eq!(st.support, "unsupported");

    // Even if a socket file appears, production serve remains unsupported.
    let ready = tokio::time::timeout(
        Duration::from_secs(2),
        run_broker(BrokerServeConfig {
            endpoint: BrokerEndpoint::UnixSocket(base.join("should-not-bind.sock")),
            secret_file: broker_dir.join("broker.secret"),
            signing_key_file: broker_dir.join("private").join("broker.cap.signing"),
            trusted_executable: std::env::current_exe().unwrap(),
            allowed_uids: vec![uid],
            socket_security: UnixSocketSecurity {
                owner_uid: uid,
                group_gid: 0,
                mode: 0o600,
            },
            addr_file: Some(base.join("ready.addr")),
        }),
    )
    .await
    .expect("run_broker returns promptly")
    .expect_err("must not serve");
    assert!(ready.contains("unsupported"), "{ready}");
    assert!(!base.join("ready.addr").exists());
    assert!(!base.join("should-not-bind.sock").exists());

    let _ = std::fs::remove_dir_all(&base);
}
