//! Opt-in WSL receipt client.  The installer copies this root-owned image as
//! `ownmeshd`, then the test runs it under the dedicated daemon UID to prove
//! the broker accepts the real UDS v2 execution path.

use ownmesh_broker_client::{
    compute_execute_intent_mac_v2, connect_and_execute_v2, BrokerEndpoint, BrokerSecret,
    ExecutablePinV2, ExecuteIntentV2, OperationFactsV2, BROKER_PROTOCOL_V2,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

fn required(args: &mut impl Iterator<Item = String>, name: &str) -> Result<String, String> {
    args.next().ok_or_else(|| format!("missing {name}"))
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    let mut secret = None;
    let mut socket = None;
    let mut program = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--secret" => secret = Some(required(&mut args, "--secret value")?),
            "--socket" => socket = Some(required(&mut args, "--socket value")?),
            "--program" => program = Some(required(&mut args, "--program value")?),
            other => return Err(format!("unexpected argument {other}")),
        }
    }
    let secret_path = PathBuf::from(secret.ok_or_else(|| "--secret is required".to_string())?);
    let socket_path = PathBuf::from(socket.ok_or_else(|| "--socket is required".to_string())?);
    let program =
        std::fs::canonicalize(program.ok_or_else(|| "--program is required".to_string())?)
            .map_err(|e| format!("canonicalize test program: {e}"))?;
    let image = std::fs::read(&program).map_err(|e| format!("read test program: {e}"))?;
    let secret = BrokerSecret::from_bytes(
        std::fs::read(secret_path).map_err(|e| format!("read broker secret: {e}"))?,
    );
    let now = ownmesh_broker::now_unix();
    let mut intent = ExecuteIntentV2 {
        protocol_version: BROKER_PROTOCOL_V2,
        request_id: format!("e8-receipt-{}", uuid::Uuid::new_v4()),
        operation_id: "e8.lifecycle.receipt".into(),
        nonce: uuid::Uuid::new_v4().to_string(),
        issued_at_unix: now,
        expires_at_unix: now + 30,
        facts: OperationFactsV2 {
            operation: "e8.lifecycle.receipt".into(),
            remote_payload_sha256: hex::encode(Sha256::digest(b"e8-lifecycle-receipt")),
            principal_id: "e8-test-principal".into(),
            tenant_id: "e8-test-tenant".into(),
            principal_credential_generation: 1,
            timeout_ms: 5_000,
            max_output_bytes: 4_096,
            device_id: "e8-test-device".into(),
            workspace_id: "e8-test-workspace".into(),
            argv: vec![program.display().to_string()],
            canonical_cwd: None,
            sanitized_env: BTreeMap::new(),
            executable: ExecutablePinV2 {
                canonical_path: program.display().to_string(),
                image_sha256: hex::encode(Sha256::digest(&image)),
                image_len: u64::try_from(image.len()).map_err(|_| "image length overflow")?,
            },
        },
        mac: String::new(),
    };
    intent.mac = compute_execute_intent_mac_v2(&secret, &intent);
    let response = connect_and_execute_v2(&BrokerEndpoint::UnixSocket(socket_path), &intent)
        .await
        .map_err(|e| format!("execute via broker UDS: {e}"))?;
    if !response.ok || response.exit_code != Some(0) {
        return Err(format!("broker receipt execution failed: {response:?}"));
    }
    println!(
        "e8 lifecycle UDS execution receipt: request_id={}",
        response.request_id
    );
    Ok(())
}
