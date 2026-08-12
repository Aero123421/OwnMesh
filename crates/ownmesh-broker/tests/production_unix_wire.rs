//! Production broker must fail closed before bind when its root-controlled
//! custody prerequisites are absent.

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
#![cfg(target_os = "linux")]

use ownmesh_broker::{
    broker_status, install_broker_with_config, run_broker, BrokerInstallConfig, BrokerServeConfig,
    UnixSocketSecurity,
};
use ownmesh_broker_client::{
    compute_cancel_intent_mac_v2, compute_execute_intent_mac_v2, operation_facts_digest,
    BrokerEndpoint, BrokerResponse, BrokerSecret, BrokerWireIntentV2, CancelIntentV2,
    ExecutablePinV2, ExecuteIntentV2, OperationFactsV2, BROKER_PROTOCOL_V2,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

fn secure_run_dir() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ownmesh-broker-wire-unsup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

#[tokio::test]
async fn production_run_broker_requires_real_custody_before_bind() {
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
    .expect_err("temporary test path must not satisfy production custody");
    assert!(
        err.contains("fail-closed") || err.contains("root-owned"),
        "{err}"
    );
    assert!(!base.join("broker.sock").exists());
    let _ = std::fs::remove_dir_all(&base);
}

#[tokio::test]
async fn production_install_and_status_never_claim_success() {
    let base = secure_run_dir();
    let _ = std::fs::create_dir_all(&base);
    let endpoint_path = base.join("runtime").join("ownmesh-broker.sock");
    let uid = 1;
    let install_err = install_broker_with_config(
        &base,
        BrokerInstallConfig {
            endpoint: Some(BrokerEndpoint::UnixSocket(endpoint_path)),
            trusted_executable: std::env::current_exe().unwrap(),
            daemon_uid: 1,
            daemon_gid: 1,
            socket_security: UnixSocketSecurity {
                owner_uid: 1,
                group_gid: 1,
                mode: 0o600,
            },
            allowed_uids: vec![1],
        },
    )
    .expect_err("install must refuse success");
    assert!(!install_err.is_empty(), "{install_err}");
    assert!(
        !base.join("broker").exists(),
        "unsupported install must not create privileged state"
    );

    let st = broker_status(&base).unwrap();
    assert!(!st.installed, "{st:?}");
    assert_eq!(st.support, "unsupported");

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

    // A mutable temporary parent still cannot satisfy production custody.
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
    .expect_err("must fail closed");
    assert!(
        ready.contains("fail-closed")
            || ready.contains("root-owned")
            || ready.contains("addr_file"),
        "{ready}"
    );
    assert!(!base.join("ready.addr").exists());
    assert!(!base.join("should-not-bind.sock").exists());

    let _ = std::fs::remove_dir_all(&base);
}

/// Budget for the timeout/descendant-kill probe.
///
/// Must exceed cold Python interpreter startup (~200ms on a loaded runner) by a
/// wide margin: the fixture has to publish the grandchild pid *before* the
/// broker's deadline fires, or the test races its own setup. A 100ms budget
/// made the pid file frequently absent and the read panic with `NotFound`.
const TIMEOUT_TREE_BUDGET_MS: u64 = 5_000;

fn proof_root() -> PathBuf {
    PathBuf::from(format!(
        "/root/ownmesh-e8-proof-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ))
}

fn sha256_file(path: &std::path::Path) -> (String, u64) {
    let bytes = std::fs::read(path).unwrap();
    (hex::encode(Sha256::digest(&bytes)), bytes.len() as u64)
}

fn execute_intent(
    secret: &BrokerSecret,
    request_id: &str,
    operation_id: &str,
    nonce: &str,
    program: &std::path::Path,
    args: Vec<String>,
    timeout_ms: u64,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
) -> ExecuteIntentV2 {
    let (image_sha256, image_len) = sha256_file(program);
    let now = ownmesh_broker::now_unix();
    let mut intent = ExecuteIntentV2 {
        protocol_version: BROKER_PROTOCOL_V2,
        request_id: request_id.into(),
        operation_id: operation_id.into(),
        nonce: nonce.into(),
        issued_at_unix: now,
        expires_at_unix: now + 30,
        facts: OperationFactsV2 {
            operation: operation_id.into(),
            remote_payload_sha256: "a".repeat(64),
            principal_id: "root-proof-principal".into(),
            tenant_id: "root-proof-tenant".into(),
            principal_credential_generation: 1,
            timeout_ms,
            max_output_bytes: 64 * 1024,
            device_id: "root-proof-device".into(),
            workspace_id: "root-proof-workspace".into(),
            argv: std::iter::once(program.display().to_string())
                .chain(args)
                .collect(),
            canonical_cwd: cwd,
            sanitized_env: env,
            executable: ExecutablePinV2 {
                canonical_path: program.display().to_string(),
                image_sha256,
                image_len,
            },
        },
        mac: String::new(),
    };
    intent.mac = compute_execute_intent_mac_v2(secret, &intent);
    intent
}

async fn start_root_broker(
    base: &std::path::Path,
) -> (tokio::task::JoinHandle<()>, PathBuf, PathBuf) {
    let socket = base.join("runtime/broker.sock");
    let secret = base.join("daemon/request.secret");
    let signing = base.join("private/broker.cap.signing");
    for dir in [
        base.join("runtime"),
        base.join("daemon"),
        base.join("private"),
    ] {
        std::fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let trusted = std::env::current_exe().unwrap();
    let cfg = BrokerServeConfig {
        endpoint: BrokerEndpoint::UnixSocket(socket.clone()),
        secret_file: secret.clone(),
        signing_key_file: signing,
        trusted_executable: trusted,
        allowed_uids: vec![0],
        socket_security: UnixSocketSecurity {
            owner_uid: 0,
            group_gid: 0,
            mode: 0o600,
        },
        addr_file: None,
    };
    let handle = tokio::spawn(async move {
        let _ = run_broker(cfg).await;
    });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !socket.exists() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("phase broker socket ready");
    (handle, socket, secret)
}

async fn call_wire(
    socket: &std::path::Path,
    intent: BrokerWireIntentV2,
) -> (BrokerResponse, String) {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let wire = serde_json::to_string(&intent).unwrap();
    stream.write_all(wire.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    stream.flush().await.unwrap();
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    (serde_json::from_str(&line).unwrap(), line)
}

async fn begin_wire(
    socket: &std::path::Path,
    intent: BrokerWireIntentV2,
) -> tokio::net::UnixStream {
    let mut stream = tokio::net::UnixStream::connect(socket).await.unwrap();
    let wire = serde_json::to_string(&intent).unwrap();
    stream.write_all(wire.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    stream.flush().await.unwrap();
    stream
}

async fn read_response(stream: tokio::net::UnixStream) -> BrokerResponse {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    serde_json::from_str(&line).unwrap()
}

/// Manual WSL entrypoint: `cargo test -p ownmesh-broker --test production_unix_wire
/// wsl_root_production_broker_receipt -- --nocapture`.  It re-execs a
/// root-owned copy because `/mnt` custody cannot prove the peer image path.
#[tokio::test]
async fn wsl_root_production_broker_receipt() {
    if rustix::process::geteuid().as_raw() != 0 {
        return;
    }
    if std::env::var_os("OWNMESH_E8_ROOT_REEXEC").is_none() {
        let copied = proof_root().with_extension("client");
        std::fs::copy(std::env::current_exe().unwrap(), &copied).unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&copied, std::fs::Permissions::from_mode(0o500)).unwrap();
        let status = std::process::Command::new(&copied)
            .args([
                "wsl_root_production_broker_receipt",
                "--exact",
                "--nocapture",
            ])
            .env("OWNMESH_E8_ROOT_REEXEC", "1")
            .status()
            .unwrap();
        let _ = std::fs::remove_file(copied);
        assert!(status.success(), "root proof child failed: {status}");
        return;
    }
    let base = proof_root();
    std::fs::create_dir(&base).unwrap();
    std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("E8 phase=server-start base={}", base.display());
    let (broker, socket, secret_path) = start_root_broker(&base).await;
    let secret = BrokerSecret::from_bytes(std::fs::read(&secret_path).unwrap());
    let id = std::fs::canonicalize("/usr/bin/id").unwrap();
    let execute = execute_intent(
        &secret,
        "execute-1",
        "execute-1",
        "execute-nonce-1",
        &id,
        vec!["-u".into()],
        5_000,
        None,
        BTreeMap::new(),
    );
    eprintln!("E8 phase=staged-success");
    let (response, raw) = tokio::time::timeout(
        Duration::from_secs(8),
        call_wire(&socket, BrokerWireIntentV2::Execute(execute.clone())),
    )
    .await
    .expect("execute deadline");
    assert!(response.ok && response.stdout.trim() == "0", "{response:?}");
    assert!(
        !raw.contains("signature") && !raw.contains("capability"),
        "response leaked authority"
    );
    eprintln!("E8 phase=env-cwd-swap-deny");
    let env_denied = execute_intent(
        &secret,
        "env-denied",
        "env-denied",
        "env-denied-nonce",
        &id,
        vec!["-u".into()],
        5_000,
        None,
        BTreeMap::from([("PATH".into(), "/tmp".into())]),
    );
    assert!(
        !call_wire(&socket, BrokerWireIntentV2::Execute(env_denied))
            .await
            .0
            .ok
    );
    let cwd_denied = execute_intent(
        &secret,
        "cwd-denied",
        "cwd-denied",
        "cwd-denied-nonce",
        &id,
        vec!["-u".into()],
        5_000,
        Some(base.display().to_string()),
        BTreeMap::new(),
    );
    assert!(
        !call_wire(&socket, BrokerWireIntentV2::Execute(cwd_denied))
            .await
            .0
            .ok
    );
    let swap_source = base.join("swap-source");
    std::fs::copy(&id, &swap_source).unwrap();
    std::fs::set_permissions(&swap_source, std::fs::Permissions::from_mode(0o500)).unwrap();
    let swap_denied = execute_intent(
        &secret,
        "swap-denied",
        "swap-denied",
        "swap-denied-nonce",
        &swap_source,
        vec!["-u".into()],
        5_000,
        None,
        BTreeMap::new(),
    );
    std::fs::copy("/usr/bin/true", &swap_source).unwrap();
    assert!(
        !call_wire(&socket, BrokerWireIntentV2::Execute(swap_denied))
            .await
            .0
            .ok
    );
    eprintln!("E8 phase=timeout-descendant-kill");
    let python = std::fs::canonicalize("/usr/bin/python3").unwrap();
    let child_pid = base.join("child.pid");
    // Keep the child alive well past the deadline so the only thing under test
    // is the broker killing the process tree, not the child exiting on its own.
    let python_code = format!("import pathlib,subprocess,time;p=subprocess.Popen(['/usr/bin/sleep','120']);pathlib.Path({child_pid:?}).write_text(str(p.pid));time.sleep(120)");
    let timeout_tree = execute_intent(
        &secret,
        "timeout-tree",
        "timeout-tree",
        "timeout-tree-nonce",
        &python,
        vec!["-c".into(), python_code],
        TIMEOUT_TREE_BUDGET_MS,
        None,
        BTreeMap::new(),
    );
    let timeout_response = call_wire(&socket, BrokerWireIntentV2::Execute(timeout_tree))
        .await
        .0;
    assert!(
        !timeout_response.ok
            && timeout_response
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("timed out"),
        "{timeout_response:?}"
    );
    // The write happens milliseconds into a multi-second budget, so by the time
    // the timeout returns the file exists. Fail loudly if it does not: silently
    // skipping would turn the descendant-kill assertion below into a no-op.
    let recorded_pid = std::fs::read_to_string(&child_pid).unwrap_or_else(|err| {
        panic!(
            "fixture never published the grandchild pid at {} within the {TIMEOUT_TREE_BUDGET_MS}ms budget: {err}",
            child_pid.display()
        )
    });
    let pid: i32 = recorded_pid
        .trim()
        .parse()
        .unwrap_or_else(|err| panic!("unparseable grandchild pid {recorded_pid:?}: {err}"));
    tokio::time::sleep(Duration::from_millis(150)).await;
    let proc_status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    assert!(
        proc_status.is_empty() || proc_status.lines().any(|line| line == "State:\tZ (zombie)"),
        "timeout left descendant alive: {proc_status}"
    );
    let sleep = std::fs::canonicalize("/usr/bin/sleep").unwrap();
    eprintln!("E8 phase=explicit-cancel");
    let cancel_target = execute_intent(
        &secret,
        "execute-cancel",
        "execute-cancel",
        "execute-cancel-nonce",
        &sleep,
        vec!["30".into()],
        10_000,
        None,
        BTreeMap::new(),
    );
    let active_stream =
        begin_wire(&socket, BrokerWireIntentV2::Execute(cancel_target.clone())).await;
    tokio::time::sleep(Duration::from_millis(75)).await;
    let now = ownmesh_broker::now_unix();
    let mut cancel = CancelIntentV2 {
        protocol_version: BROKER_PROTOCOL_V2,
        request_id: "cancel-1".into(),
        operation_id: "operation.cancel".into(),
        nonce: "cancel-nonce-1".into(),
        issued_at_unix: now,
        expires_at_unix: now + 30,
        target_request_id: cancel_target.request_id.clone(),
        target_operation_id: cancel_target.operation_id.clone(),
        target_nonce: cancel_target.nonce.clone(),
        target_facts_digest: operation_facts_digest(&cancel_target.facts),
        mac: String::new(),
    };
    cancel.mac = compute_cancel_intent_mac_v2(&secret, &cancel);
    assert!(
        call_wire(&socket, BrokerWireIntentV2::Cancel(cancel))
            .await
            .0
            .ok
    );
    let cancelled = tokio::time::timeout(Duration::from_secs(5), read_response(active_stream))
        .await
        .expect("cancel deadline");
    assert!(
        !cancelled.ok
            && cancelled
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("cancelled"),
        "{cancelled:?}"
    );
    eprintln!("E8 phase=disconnect-kill");
    let disconnect_target = execute_intent(
        &secret,
        "execute-disconnect",
        "execute-disconnect",
        "execute-disconnect-nonce",
        &sleep,
        vec!["30".into()],
        10_000,
        None,
        BTreeMap::new(),
    );
    drop(
        begin_wire(
            &socket,
            BrokerWireIntentV2::Execute(disconnect_target.clone()),
        )
        .await,
    );
    tokio::time::sleep(Duration::from_millis(250)).await;
    let now = ownmesh_broker::now_unix();
    let mut after_disconnect = CancelIntentV2 {
        protocol_version: BROKER_PROTOCOL_V2,
        request_id: "cancel-after-disconnect".into(),
        operation_id: "operation.cancel".into(),
        nonce: "cancel-nonce-after-disconnect".into(),
        issued_at_unix: now,
        expires_at_unix: now + 30,
        target_request_id: disconnect_target.request_id.clone(),
        target_operation_id: disconnect_target.operation_id.clone(),
        target_nonce: disconnect_target.nonce.clone(),
        target_facts_digest: operation_facts_digest(&disconnect_target.facts),
        mac: String::new(),
    };
    after_disconnect.mac = compute_cancel_intent_mac_v2(&secret, &after_disconnect);
    let rejected = call_wire(&socket, BrokerWireIntentV2::Cancel(after_disconnect))
        .await
        .0;
    assert!(
        !rejected.ok
            && rejected
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("not an active"),
        "disconnect must remove active entry: {rejected:?}"
    );
    eprintln!("E8 phase=replay-before-restart");
    assert!(
        !call_wire(&socket, BrokerWireIntentV2::Execute(execute.clone()))
            .await
            .0
            .ok
    );
    broker.abort();
    let _ = broker.await;
    let _ = std::fs::remove_file(&socket);
    eprintln!("E8 phase=replay-after-restart");
    let (broker2, socket2, _) = start_root_broker(&base).await;
    assert!(
        !call_wire(&socket2, BrokerWireIntentV2::Execute(execute))
            .await
            .0
            .ok
    );
    broker2.abort();
    let _ = broker2.await;
    eprintln!("E8 phase=complete");
    let _ = std::fs::remove_dir_all(&base);
}
