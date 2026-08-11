#![cfg(unix)]

use ownmesh_broker_client::{
    build_cancel_intent_v2, compute_execute_intent_mac_v2, connect_and_cancel_v2,
    connect_and_execute_v2, connect_and_execute_v2_cancellable, BrokerEndpoint, BrokerSecret,
    BrokerV2ClientError, BrokerWireIntentV2, ExecutablePinV2, ExecuteIntentV2, OperationFactsV2,
    BROKER_PROTOCOL_V2, MAX_BROKER_RESPONSE_BYTES,
};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::watch;

static NEXT_SOCKET: AtomicU64 = AtomicU64::new(0);

fn socket_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "ownmesh-v2-client-{}-{}.sock",
        std::process::id(),
        NEXT_SOCKET.fetch_add(1, Ordering::Relaxed)
    ))
}

fn execute(secret: &BrokerSecret) -> ExecuteIntentV2 {
    let mut execute = ExecuteIntentV2 {
        protocol_version: BROKER_PROTOCOL_V2,
        request_id: "execute-request".into(),
        operation_id: "command.exec.elevated".into(),
        nonce: "execute-nonce".into(),
        issued_at_unix: 100,
        expires_at_unix: i64::MAX,
        facts: OperationFactsV2 {
            operation: "command.exec.elevated".into(),
            remote_payload_sha256: "a".repeat(64),
            principal_id: "principal-1".into(),
            tenant_id: "tenant-1".into(),
            principal_credential_generation: 1,
            timeout_ms: 1_000,
            max_output_bytes: 1_024,
            device_id: "device-1".into(),
            workspace_id: "workspace-1".into(),
            argv: vec!["/usr/bin/id".into()],
            canonical_cwd: Some("/tmp".into()),
            sanitized_env: BTreeMap::new(),
            executable: ExecutablePinV2 {
                canonical_path: "/usr/bin/id".into(),
                image_sha256: "b".repeat(64),
                image_len: 1,
            },
        },
        mac: String::new(),
    };
    execute.mac = compute_execute_intent_mac_v2(secret, &execute);
    execute
}

fn response(request_id: &str) -> String {
    serde_json::json!({
        "request_id": request_id,
        "ok": true,
        "exit_code": 0,
        "stdout": "ok",
        "stderr": "",
        "error": null,
        "timed_out": false,
        "cancelled": false,
        "truncated": false,
        "duration_ms": 3,
    })
    .to_string()
}

async fn read_line(stream: UnixStream) -> (UnixStream, String) {
    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    reader.read_line(&mut line).await.unwrap();
    (reader.into_inner(), line)
}

async fn write_line(stream: &mut UnixStream, line: &str) {
    stream.write_all(line.as_bytes()).await.unwrap();
    stream.write_all(b"\n").await.unwrap();
    stream.flush().await.unwrap();
}

#[tokio::test]
async fn execute_uses_one_live_uds_connection_and_parses_typed_response() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let secret = BrokerSecret::generate();
    let intent = execute(&secret);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let (mut stream, line) = read_line(stream).await;
        assert!(matches!(
            serde_json::from_str::<BrokerWireIntentV2>(&line).unwrap(),
            BrokerWireIntentV2::Execute(_)
        ));
        write_line(&mut stream, &response("execute-request")).await;
    });

    let actual = connect_and_execute_v2(&BrokerEndpoint::UnixSocket(path.clone()), &intent)
        .await
        .unwrap();
    assert_eq!(actual.stdout, "ok");
    server.await.unwrap();
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn rejects_malformed_mismatched_and_oversized_v2_responses() {
    for (line, matcher) in [
        ("not-json".to_string(), 0_u8),
        (response("other-request"), 1_u8),
        (
            format!("{}{}", "x".repeat(MAX_BROKER_RESPONSE_BYTES + 1), "\n"),
            2_u8,
        ),
    ] {
        let path = socket_path();
        let listener = UnixListener::bind(&path).unwrap();
        let secret = BrokerSecret::generate();
        let intent = execute(&secret);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut stream, _) = read_line(stream).await;
            stream.write_all(line.as_bytes()).await.unwrap();
            if !line.ends_with('\n') {
                stream.write_all(b"\n").await.unwrap();
            }
            stream.flush().await.unwrap();
        });
        let error = connect_and_execute_v2(&BrokerEndpoint::UnixSocket(path.clone()), &intent)
            .await
            .unwrap_err();
        match matcher {
            0 => assert!(matches!(error, BrokerV2ClientError::MalformedResponse(_))),
            1 => assert!(matches!(error, BrokerV2ClientError::RequestIdMismatch)),
            2 => assert!(matches!(error, BrokerV2ClientError::ResponseTooLarge)),
            _ => unreachable!(),
        }
        server.await.unwrap();
        let _ = std::fs::remove_file(path);
    }
}

#[tokio::test]
async fn cancellation_uses_fresh_exact_intent_and_keeps_waiting_for_execute_response() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let secret = BrokerSecret::generate();
    let intent = execute(&secret);
    let (cancel_tx, mut cancel_rx) = watch::channel(false);
    let server = tokio::spawn(async move {
        let (execute_stream, _) = listener.accept().await.unwrap();
        let (mut execute_stream, execute_line) = read_line(execute_stream).await;
        let BrokerWireIntentV2::Execute(execute) = serde_json::from_str(&execute_line).unwrap()
        else {
            panic!("expected Execute");
        };
        cancel_tx.send(true).unwrap();

        let (cancel_stream, _) = listener.accept().await.unwrap();
        let (mut cancel_stream, cancel_line) = read_line(cancel_stream).await;
        let BrokerWireIntentV2::Cancel(cancel) = serde_json::from_str(&cancel_line).unwrap() else {
            panic!("expected Cancel");
        };
        assert_ne!(cancel.nonce, execute.nonce);
        assert_eq!(cancel.target_request_id, execute.request_id);
        assert_eq!(cancel.target_operation_id, execute.operation_id);
        assert_eq!(cancel.target_nonce, execute.nonce);
        assert_eq!(
            cancel.target_facts_digest,
            ownmesh_broker_client::operation_facts_digest(&execute.facts)
        );
        write_line(&mut cancel_stream, &response(&cancel.request_id)).await;
        write_line(&mut execute_stream, &response(&execute.request_id)).await;
    });

    let actual = connect_and_execute_v2_cancellable(
        &BrokerEndpoint::UnixSocket(path.clone()),
        &secret,
        &intent,
        &mut cancel_rx,
    )
    .await
    .unwrap();
    assert_eq!(actual.request_id, intent.request_id);
    server.await.unwrap();
    let _ = std::fs::remove_file(path);
}

#[tokio::test]
async fn cancel_and_execute_connection_drop_are_never_retried() {
    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let secret = BrokerSecret::generate();
    let intent = execute(&secret);
    let cancel = build_cancel_intent_v2(&secret, &intent, 100);
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = read_line(stream).await;
    });
    let error = connect_and_execute_v2(&BrokerEndpoint::UnixSocket(path.clone()), &intent)
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerV2ClientError::ExecutionUncertain(_)));
    server.await.unwrap();
    let _ = std::fs::remove_file(path);

    let path = socket_path();
    let listener = UnixListener::bind(&path).unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = read_line(stream).await;
    });
    let error = connect_and_cancel_v2(&BrokerEndpoint::UnixSocket(path.clone()), &cancel)
        .await
        .unwrap_err();
    assert!(matches!(error, BrokerV2ClientError::ExecutionUncertain(_)));
    server.await.unwrap();
    let _ = std::fs::remove_file(path);
}
