//! fix-4: Windows broker install/status must never claim installed=true without
//! safe Named Pipe peer PID/token/ACL enforcement.

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

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
use ownmesh_broker::install_broker;
use ownmesh_broker::{
    broker_status, endpoint_supports_peer_cred_enforcement, run_broker, BrokerServeConfig,
};
use ownmesh_broker_client::BrokerEndpoint;
use std::time::Duration;
use tempfile::tempdir;

#[test]
fn named_pipe_and_windows_install_never_returns_installed_true() {
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let dir = tempdir().unwrap();
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let base = dir.path();

    #[cfg(windows)]
    {
        let st = broker_status(base).unwrap();
        assert!(!st.installed, "installed must be false: {st:?}");
        assert_eq!(st.support, "unsupported");
        assert!(
            st.notes.iter().any(|n| {
                let l = n.to_ascii_lowercase();
                l.contains("unsupported")
                    || l.contains("fail-closed")
                    || l.contains("named")
                    || l.contains("custody")
            }),
            "notes must explain unsupported: {st:?}"
        );
    }

    // Generic Named Pipe endpoints remain forbidden: Windows only permits the
    // fixed SCM-owned broker pipe selected by the lifecycle module.
    let pipe = BrokerEndpoint::NamedPipe(r"\\.\pipe\ownmesh-fix4-test".into());
    assert!(!endpoint_supports_peer_cred_enforcement(&pipe));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let err = install_broker(base, Some(pipe)).expect_err("named pipe install");
        assert!(
            err.to_ascii_lowercase().contains("unsupported")
                || err.to_ascii_lowercase().contains("fixed"),
            "{err}"
        );
        let st = broker_status(base).unwrap();
        assert!(!st.installed);
        assert_eq!(st.support, "unsupported");
    }
}

#[test]
fn broker_status_clears_legacy_installed_true_without_peer_enforcement() {
    let dir = tempdir().unwrap();
    let base = dir.path();
    let broker = base.join("broker");
    std::fs::create_dir_all(&broker).unwrap();
    let fake = serde_json::json!({
        "installed": true,
        "installed_at_unix": 1,
        "endpoint": r"\\.\pipe\ownmesh",
        "endpoint_kind": "named_pipe",
        "unit_path": null,
        "secret_file": broker.join("broker.secret").display().to_string(),
        "signing_key_file": "",
        "verify_key_file": "",
        "notes": ["legacy success disguise"],
        "support": "supported"
    });
    std::fs::write(
        broker.join("broker-install.json"),
        serde_json::to_string_pretty(&fake).unwrap(),
    )
    .unwrap();

    let st = broker_status(base).unwrap();
    assert!(
        !st.installed,
        "legacy installed=true must not survive status: {st:?}"
    );
    assert_eq!(st.support, "unsupported");
}

#[tokio::test]
async fn run_broker_named_pipe_is_failed_not_success() {
    let dir = tempdir().unwrap();
    let cfg = BrokerServeConfig {
        endpoint: BrokerEndpoint::NamedPipe(r"\\.\pipe\ownmesh-fix4-run".into()),
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
        .expect("must return promptly")
        .expect_err("NamedPipe run must fail-closed");
    assert!(
        err.to_ascii_lowercase().contains("unsupported")
            || err.to_ascii_lowercase().contains("fail-closed")
            || err.to_ascii_lowercase().contains("named"),
        "{err}"
    );
}

#[test]
fn loopback_tcp_install_is_unsupported() {
    let ep = BrokerEndpoint::LoopbackTcp("127.0.0.1:0".parse().unwrap());
    assert!(!endpoint_supports_peer_cred_enforcement(&ep));
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let dir = tempdir().unwrap();
        let err = install_broker(dir.path(), Some(ep)).expect_err("tcp install");
        assert!(
            err.to_ascii_lowercase().contains("unsupported")
                || err.to_ascii_lowercase().contains("fixed"),
            "{err}"
        );
        let st = broker_status(dir.path()).unwrap();
        assert!(!st.installed);
    }
}

#[test]
#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn install_without_legacy_arguments_is_explicitly_unsupported_and_side_effect_free() {
    let dir = tempdir().unwrap();
    let err = install_broker(dir.path(), None).expect_err("production install is unsupported");
    assert!(err.to_ascii_lowercase().contains("unsupported"), "{err}");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
