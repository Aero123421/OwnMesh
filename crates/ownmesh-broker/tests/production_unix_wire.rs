#![cfg(target_os = "linux")]

use ownmesh_broker::{
    broker_status, install_broker_with_config, now_unix, run_broker, BrokerInstallConfig,
    BrokerServeConfig, UnixSocketSecurity,
};
use ownmesh_broker_client::{elevate, BrokerEndpoint, BrokerSecret, ElevatedCommand};
use std::path::{Path, PathBuf};
use std::time::Duration;

const HELPER_ENV: &str = "OWNMESH_BROKER_PRODUCTION_WIRE_HELPER";
const ENDPOINT_ENV: &str = "OWNMESH_BROKER_TEST_ENDPOINT";
const SECRET_ENV: &str = "OWNMESH_BROKER_TEST_SECRET";
const SIGNING_ENV: &str = "OWNMESH_BROKER_TEST_SIGNING";
const MARKER_ENV: &str = "OWNMESH_BROKER_TEST_MARKER";

fn secure_run_dir() -> PathBuf {
    PathBuf::from("/run").join(format!(
        "ownmesh-broker-wire-test-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ))
}

fn chmod(path: &Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

async fn copied_executable_helper() {
    let helper_mode = std::env::var(HELPER_ENV).expect("helper mode");
    let endpoint_path = PathBuf::from(std::env::var_os(ENDPOINT_ENV).expect("helper endpoint"));
    if helper_mode == "socket-denied" {
        let err = tokio::net::UnixStream::connect(&endpoint_path)
            .await
            .expect_err("non-owner UID must not physically connect to mode 0600 socket");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        return;
    }
    if helper_mode == "signing-denied" {
        let err = std::fs::read(std::env::var_os(SIGNING_ENV).expect("signing key path"))
            .expect_err("daemon UID must not physically read broker signing key");
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied, "{err}");
        return;
    }
    let endpoint = BrokerEndpoint::UnixSocket(endpoint_path);
    let secret_bytes =
        std::fs::read(std::env::var_os(SECRET_ENV).expect("helper request-MAC secret"))
            .expect("configured UID can physically read its 0600 MAC secret");
    let marker = PathBuf::from(std::env::var_os(MARKER_ENV).expect("helper marker"));
    let response = elevate(
        &endpoint,
        &BrokerSecret::from_bytes(secret_bytes),
        "ownmeshd-test-helper",
        "trusted-helper-operation",
        ElevatedCommand {
            program: "/usr/bin/touch".into(),
            args: vec![marker.display().to_string()],
            cwd: None,
            env: vec![],
        },
        now_unix(),
        30,
    )
    .await;
    if helper_mode == "untrusted" {
        assert!(response.is_err(), "different executable must be dropped");
        assert!(!marker.exists(), "denied helper command must not execute");
    } else {
        let response = response.expect("trusted copied executable receives a wire response");
        assert!(response.ok, "trusted helper must execute: {response:?}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn production_run_broker_enforces_executable_over_same_uid_mac_holder() {
    if std::env::var_os(HELPER_ENV).is_some() {
        copied_executable_helper().await;
        return;
    }

    let uid = rustix::process::geteuid().as_raw();
    if uid != 0 {
        let base = secure_run_dir();
        let err = run_broker(BrokerServeConfig {
            endpoint: BrokerEndpoint::UnixSocket(base.join("broker.sock")),
            secret_file: base.join("broker.secret"),
            signing_key_file: base.join("private").join("broker.cap.signing"),
            trusted_executable: std::env::current_exe().unwrap(),
            allowed_uids: vec![uid],
            socket_security: UnixSocketSecurity {
                owner_uid: uid,
                group_gid: uid,
                mode: 0o600,
            },
            addr_file: None,
        })
        .await
        .expect_err("non-root production custody must be explicitly unsupported");
        assert!(
            err.contains("unsupported") && err.contains("effective UID 0"),
            "expected explicit unsupported root custody, got: {err}"
        );
        return;
    }

    let base = secure_run_dir();
    std::fs::create_dir(&base).expect("create secure /run test directory");
    chmod(&base, 0o711);
    let daemon_uid = 65_534;
    let other_uid = 65_533;
    let copied_executable = base.join("trusted-ownmeshd-test");
    let untrusted_executable = base.join("untrusted-same-bytes-test");
    std::fs::copy(std::env::current_exe().unwrap(), &copied_executable)
        .expect("copy test executable into root-controlled ancestry");
    chmod(&copied_executable, 0o755);
    std::fs::copy(std::env::current_exe().unwrap(), &untrusted_executable)
        .expect("copy same test bytes under a different executable identity");
    chmod(&untrusted_executable, 0o755);

    let broker_dir = base.join("broker");
    let runtime_dir = broker_dir.join("runtime");
    let endpoint_path = runtime_dir.join("ownmesh-broker.sock");
    let secret_path = broker_dir.join("broker.secret");
    let signing_path = broker_dir.join("private").join("broker.cap.signing");
    let socket_security = UnixSocketSecurity {
        owner_uid: daemon_uid,
        group_gid: 4_242,
        mode: 0o600,
    };
    let install_err = install_broker_with_config(
        &base,
        BrokerInstallConfig {
            endpoint: Some(BrokerEndpoint::UnixSocket(endpoint_path.clone())),
            trusted_executable: copied_executable.clone(),
            socket_security,
            allowed_uids: vec![daemon_uid],
        },
    )
    .expect_err("template staging must not fake service installation success");
    assert!(
        install_err.contains("staged") && install_err.contains("installed=false"),
        "{install_err}"
    );
    assert!(
        !broker_status(&base).unwrap().installed,
        "a staged template without a live socket is not installed"
    );
    let staged: serde_json::Value =
        serde_json::from_slice(&std::fs::read(broker_dir.join("broker-install.json")).unwrap())
            .unwrap();
    assert_eq!(
        staged["installed"], false,
        "staged record must not fake success"
    );
    assert_eq!(staged["support"], "unsupported");
    assert_eq!(
        staged["endpoint"],
        endpoint_path.display().to_string(),
        "staged service and daemon discovery record must use the configured endpoint"
    );
    let addr_file = base.join("ready.addr");
    let denied_marker = base.join("denied-command-ran");
    let allowed_marker = base.join("trusted-command-ran");
    let config = BrokerServeConfig {
        endpoint: BrokerEndpoint::UnixSocket(endpoint_path.clone()),
        secret_file: secret_path.clone(),
        signing_key_file: signing_path,
        trusted_executable: copied_executable.clone(),
        allowed_uids: vec![daemon_uid],
        socket_security,
        addr_file: Some(addr_file.clone()),
    };

    // A root-owned regular leaf is still not a stale socket and must never be removed.
    std::fs::write(&endpoint_path, b"passwd-like protected leaf").unwrap();
    chmod(&endpoint_path, 0o600);
    let stale_err = run_broker(config.clone())
        .await
        .expect_err("regular stale endpoint must be rejected");
    assert!(stale_err.contains("Unix socket"), "{stale_err}");
    assert_eq!(
        std::fs::read(&endpoint_path).unwrap(),
        b"passwd-like protected leaf"
    );
    std::fs::remove_file(&endpoint_path).unwrap();

    let broker = tokio::spawn(run_broker(config.clone()));
    tokio::time::timeout(Duration::from_secs(10), async {
        while !addr_file.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("production broker became ready");

    let duplicate_err = run_broker(config)
        .await
        .expect_err("a second broker must not unlink an active matching socket");
    assert!(
        duplicate_err.contains("active Unix socket"),
        "{duplicate_err}"
    );

    let install_record = serde_json::json!({
        "installed": true,
        "installed_at_unix": now_unix(),
        "endpoint": endpoint_path.display().to_string(),
        "endpoint_kind": "unix_socket",
        "unit_path": null,
        "secret_file": secret_path.display().to_string(),
        "signing_key_file": broker_dir.join("private").join("broker.cap.signing").display().to_string(),
        "verify_key_file": broker_dir.join("broker.cap.verify").display().to_string(),
        "trusted_executable": copied_executable.display().to_string(),
        "socket_owner_uid": daemon_uid,
        "socket_group_gid": 4_242,
        "socket_mode": 0o600,
        "allowed_uids": [daemon_uid],
        "notes": ["root-only wire fixture with verified live broker"],
        "support": "supported"
    });
    let install_path = broker_dir.join("broker-install.json");
    std::fs::write(
        &install_path,
        serde_json::to_vec_pretty(&install_record).unwrap(),
    )
    .unwrap();
    chmod(&install_path, 0o644);
    let live_status = broker_status(&base).unwrap();
    assert!(
        live_status.installed,
        "live exact boundary must validate: {live_status:?}"
    );

    use std::os::unix::fs::MetadataExt;
    let secret_md = std::fs::symlink_metadata(&secret_path).unwrap();
    let socket_md = std::fs::symlink_metadata(&endpoint_path).unwrap();
    assert_eq!(
        (secret_md.uid(), secret_md.mode() & 0o777),
        (daemon_uid, 0o600)
    );
    assert_eq!(
        (socket_md.uid(), socket_md.gid(), socket_md.mode() & 0o777),
        (daemon_uid, 4_242, 0o600)
    );

    let denied_output = tokio::process::Command::new(&untrusted_executable)
        .args([
            "--exact",
            "production_run_broker_enforces_executable_over_same_uid_mac_holder",
            "--nocapture",
        ])
        .uid(daemon_uid)
        .env(HELPER_ENV, "untrusted")
        .env(ENDPOINT_ENV, &endpoint_path)
        .env(SECRET_ENV, &secret_path)
        .env(MARKER_ENV, &denied_marker)
        .output()
        .await
        .expect("launch same-UID different executable helper");
    assert!(
        denied_output.status.success(),
        "denied helper assertions failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&denied_output.stdout),
        String::from_utf8_lossy(&denied_output.stderr)
    );
    assert!(!denied_marker.exists(), "denied command must not execute");

    let socket_denied = tokio::process::Command::new(&untrusted_executable)
        .args([
            "--exact",
            "production_run_broker_enforces_executable_over_same_uid_mac_holder",
            "--nocapture",
        ])
        .uid(other_uid)
        .env(HELPER_ENV, "socket-denied")
        .env(ENDPOINT_ENV, &endpoint_path)
        .output()
        .await
        .expect("launch physical socket-DAC probe");
    assert!(
        socket_denied.status.success(),
        "other-UID socket denial assertion failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&socket_denied.stdout),
        String::from_utf8_lossy(&socket_denied.stderr)
    );

    let signing_denied = tokio::process::Command::new(&copied_executable)
        .args([
            "--exact",
            "production_run_broker_enforces_executable_over_same_uid_mac_holder",
            "--nocapture",
        ])
        .uid(daemon_uid)
        .env(HELPER_ENV, "signing-denied")
        .env(ENDPOINT_ENV, &endpoint_path)
        .env(
            SIGNING_ENV,
            broker_dir.join("private").join("broker.cap.signing"),
        )
        .output()
        .await
        .expect("launch daemon-UID signing-key custody probe");
    assert!(
        signing_denied.status.success(),
        "signing-key denial assertion failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&signing_denied.stdout),
        String::from_utf8_lossy(&signing_denied.stderr)
    );

    let helper_output = tokio::process::Command::new(&copied_executable)
        .args([
            "--exact",
            "production_run_broker_enforces_executable_over_same_uid_mac_holder",
            "--nocapture",
        ])
        .uid(daemon_uid)
        .env(HELPER_ENV, "trusted")
        .env(ENDPOINT_ENV, &endpoint_path)
        .env(SECRET_ENV, &secret_path)
        .env(MARKER_ENV, &allowed_marker)
        .output()
        .await
        .expect("launch copied trusted test helper");
    assert!(
        helper_output.status.success(),
        "trusted helper failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&helper_output.stdout),
        String::from_utf8_lossy(&helper_output.stderr)
    );
    assert!(
        allowed_marker.exists(),
        "trusted helper command must execute"
    );

    chmod(&endpoint_path, 0o660);
    assert!(
        !broker_status(&base).unwrap().installed,
        "socket mode drift must clear installed"
    );
    chmod(&endpoint_path, 0o600);
    broker.abort();
    let _ = broker.await;
    assert!(
        !broker_status(&base).unwrap().installed,
        "a stale socket inode without a listener is never installed"
    );
    std::fs::remove_file(&endpoint_path).unwrap();
    assert!(
        !broker_status(&base).unwrap().installed,
        "a missing socket is never trusted or installed"
    );
    std::fs::remove_dir_all(&base).unwrap();
}
