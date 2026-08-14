//! Authenticated control-plane WebSocket transport for the device Agent.
//!
//! E2 connects validated `operation.request` envelopes to the shared
//! policy-gated [`DaemonRuntime`]. Without a runtime handle the transport stays
//! fail-closed (`remote_routing_enabled: false`).

use crate::runtime::DaemonRuntime;
use crate::transfer_crypto::{canonical_ephemeral_proof, AgentTransferTicket, TransferEphemeral};
use futures_util::{SinkExt, StreamExt};
use ownmesh_config::{atomic_write, OwnMeshConfig, OwnMeshPaths};
use ownmesh_domain::{DeviceId, ErrorCode, MessageId, Timestamp};
use ownmesh_identity::{
    load_device_credential, load_or_create_device_key, DeviceKeyPair, PreferredSecretStore,
    SecretString, DEFAULT_KEYCHAIN_SERVICE,
};
use ownmesh_ipc::{methods, ClientIdentity};
use ownmesh_protocol::{
    Envelope, OperationEnvelope, OperationPayload, OperationRequestPayload, OPERATION_CONTRACT_V1,
    PROTOCOL_DEVICE_V1,
};
use ownmesh_transfer::TransferChunk;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch, Mutex, OwnedSemaphorePermit, Semaphore};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, ORIGIN, USER_AGENT};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{connect_async_with_config, MaybeTlsStream, WebSocketStream};
use url::Url;
use uuid::Uuid;

const TRANSPORT_STATE_VERSION: u32 = 1;
const TRANSPORT_STATE_FILE: &str = "agent-transport-state.json";
const LOOPBACK_TEST_KEYCHAIN_SERVICE_ENV: &str = "OWNMESH_LOOPBACK_TEST_KEYCHAIN_SERVICE";
const MAX_REPLAY_ENTRIES: usize = 4096;
const MAX_COMPLETED_REPLIES: usize = 1024;
/// Aggregate UTF-8 budget for durable completed_replies payloads (not per-entry).
const MAX_COMPLETED_REPLIES_BYTES: usize = 4 * 1024 * 1024;
/// Per-entry compact receipt when a full result would blow the aggregate budget.
const MAX_COMPLETED_REPLY_PAYLOAD_BYTES: usize = 64 * 1024;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PAYLOAD_BYTES: usize = 1_000_000;
/// Reject transport state files larger than this before deserialize.
const MAX_TRANSPORT_STATE_FILE_BYTES: usize = 8 * 1024 * 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(30);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);
/// Bounded completion queue between worker tasks and the live WebSocket loop.
/// Prevents unbounded memory growth when the WSS consumer is slow.
const MAX_COMPLETION_QUEUE: usize = 8;
/// Cap concurrent remote dispatches (running + waiting to send a result).
const MAX_IN_FLIGHT_REMOTE_OPS: usize = 32;
/// Durable accepted-but-not-completed operation.request envelopes (crash outbox).
const MAX_PENDING_DISPATCHES: usize = 64;
/// Bound raw envelope retention so the transport state file stays inside budget.
const MAX_PENDING_RAW_BYTES: usize = MAX_PAYLOAD_BYTES.saturating_add(64 * 1024);
/// Transfer data is a distinct, bounded WSS connection. It never shares the
/// control Agent socket or its persisted operation queue.
const MAX_TRANSFER_SOCKET_BYTES: usize = 96 * 1024;
/// Opaque Worker-signed transfer bearer accepted on the live-only start path.
const MAX_TRANSFER_TICKET_WIRE_BYTES: usize = 16 * 1024;

type AgentSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Tracks consecutive Agent connection failures. A session that completes the
/// authenticated ready handshake starts a fresh reconnect history, even if the
/// peer later closes the live socket.
#[derive(Default)]
struct ReconnectBackoff {
    attempt: u32,
}

impl ReconnectBackoff {
    fn reset_after_ready(&mut self) {
        self.attempt = 0;
    }

    fn next_delay(&mut self) -> Duration {
        self.attempt = self.attempt.saturating_add(1).min(10);
        let shift = self.attempt.min(5);
        Duration::from_secs(1_u64 << shift).min(MAX_RECONNECT_DELAY)
    }
}

fn reconnect_failure_category(error: &str) -> &'static str {
    if error.contains("control plane rejected") || error.contains("unsupported device protocol") {
        "protocol_rejection"
    } else if error.contains("socket closed")
        || error.contains("control plane closed")
        || error.contains("WebSocket stream ended")
        || error.contains("ConnectionClosed")
    {
        "peer_closed"
    } else {
        "transport_error"
    }
}

/// Fully bound transport inputs. Secret-bearing fields intentionally have no
/// `Debug` implementation.
#[derive(Clone)]
pub struct AgentTransportConfig {
    issuer: String,
    ws_url: Url,
    origin: String,
    device_id: DeviceId,
    credential: SecretString,
    key: Arc<DeviceKeyPair>,
    /// Ephemeral X25519 private halves are scoped to a short-lived transfer
    /// preflight and deliberately never enter AgentTransportState or logs.
    preflight_ephemerals: Arc<Mutex<HashMap<String, PreflightEphemeral>>>,
    state_path: PathBuf,
}

struct PreflightEphemeral {
    role: String,
    transfer_id: String,
    epoch: u32,
    fence: u64,
    session_nonce: String,
    expires_at_ms: u64,
    key: TransferEphemeral,
}

/// Parse only the signed-ticket body.  HMAC validation happens at the Worker
/// upgrade boundary; the Agent independently validates role/device/expiry and
/// both Ed25519 ephemeral proofs before deriving a cipher.  The wire bearer is
/// never retained in transport state or an operation result.
fn parse_transfer_ticket_wire(raw: &str) -> Result<AgentTransferTicket, String> {
    let (body, signature) = match raw.split_once('.') {
        Some((body, rest)) => match rest.split_once('.') {
            Some((_, _)) => return Err("invalid transfer ticket segments".into()),
            None => (body, rest),
        },
        None => return Err("invalid transfer ticket segments".into()),
    };
    if body.is_empty() || signature.is_empty() || raw.len() > MAX_TRANSFER_TICKET_WIRE_BYTES {
        return Err("invalid transfer ticket wire".into());
    }
    let bytes = base64url_decode(body)?;
    serde_json::from_slice(&bytes).map_err(|_| "invalid transfer ticket body".into())
}

/// The bearer itself is intentionally excluded from the auditable action hash,
/// but every authority fact inside it must equal the already verified
/// `transfer.start` action. This prevents a stolen valid ticket from attaching a
/// different Room/proof generation to an otherwise exact-bound request.
fn validate_ticket_for_start(
    ticket: &AgentTransferTicket,
    request: &OperationRequestPayload,
    args: &Value,
    device_id: &DeviceId,
) -> Result<(), String> {
    let object = args.as_object().ok_or("invalid transfer start arguments")?;
    let text = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("transfer start argument '{name}' is missing"))
    };
    let number = |name: &str| {
        object
            .get(name)
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("transfer start argument '{name}' is missing"))
    };
    let bound = request
        .authorization
        .as_ref()
        .and_then(|authorization| authorization.bound_action.as_object())
        .ok_or("verified transfer start binding is missing")?;
    let principal = bound
        .get("principal_id")
        .and_then(Value::as_str)
        .ok_or("verified transfer start principal is missing")?;
    let tenant = bound
        .get("tenant_id")
        .and_then(Value::as_str)
        .ok_or("verified transfer start tenant is missing")?;
    let role = text("role")?;
    let expected_local = if role == "source" {
        text("source_device_id")?
    } else if role == "destination" {
        text("destination_device_id")?
    } else {
        return Err("invalid transfer start role".into());
    };
    let grant_expiry = number("grant_expires_at_unix")?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock before unix epoch")?
        .as_millis() as u64;
    ticket.validate_for(device_id.as_str(), role, now_ms)?;
    if ticket.transfer_id != text("transfer_id")?
        || ticket.tenant_id != tenant
        || ticket.principal_id != principal
        || ticket.device_id != device_id.as_str()
        || ticket.role != role
        || ticket.source_device_id != text("source_device_id")?
        || ticket.destination_device_id != text("destination_device_id")?
        || ticket.source_workspace_id != text("source_workspace_id")?
        || ticket.destination_workspace_id != text("destination_workspace_id")?
        || ticket.plan_sha256 != text("plan_sha256")?
        || ticket.epoch != u32::try_from(number("epoch")?).map_err(|_| "transfer epoch overflow")?
        || ticket.fence != number("fence")?
        || ticket.max_bytes != number("size_bytes")?
        || ticket.transfer_expires_at / 1_000 != grant_expiry
        || expected_local != device_id.as_str()
    {
        return Err("transfer ticket does not match exact start binding".into());
    }
    Ok(())
}

fn transfer_start_result(
    admitted: &Value,
    ticket: &AgentTransferTicket,
    completed: bool,
    destination_publish: Option<&Value>,
    expected_artifact_sha256: Option<&str>,
) -> Result<Value, String> {
    let object = admitted
        .as_object()
        .ok_or("transfer start admission is invalid")?;
    let allowed = [
        "transfer_id",
        "plan_id",
        "role",
        "plan_sha256",
        "epoch",
        "fence",
        "admitted",
    ];
    if object.keys().any(|key| !allowed.contains(&key.as_str()))
        || object.get("transfer_id").and_then(Value::as_str) != Some(ticket.transfer_id.as_str())
        || object.get("role").and_then(Value::as_str) != Some(ticket.role.as_str())
        || object.get("plan_sha256").and_then(Value::as_str) != Some(ticket.plan_sha256.as_str())
        || object.get("epoch").and_then(Value::as_u64) != Some(u64::from(ticket.epoch))
        || object.get("fence").and_then(Value::as_u64) != Some(ticket.fence)
        || object.get("admitted") != Some(&Value::Bool(true))
        || object
            .get("plan_id")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err("transfer start admission binding mismatch".into());
    }
    let mut result = json!({
        "transfer_id": ticket.transfer_id,
        "plan_id": object.get("plan_id").cloned().unwrap_or(Value::Null),
        "role": ticket.role,
        "plan_sha256": ticket.plan_sha256,
        "epoch": ticket.epoch,
        "fence": ticket.fence,
        "admitted": true,
        "completed": completed,
    });
    if ticket.role == "destination" {
        let published = destination_publish
            .and_then(Value::as_object)
            .ok_or("destination publication receipt missing")?;
        let sha256 = published
            .get("sha256")
            .and_then(Value::as_str)
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or("destination publication digest missing")?;
        let expected_artifact_sha256 = expected_artifact_sha256
            .filter(|value| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .ok_or("destination canonical artifact digest missing")?;
        if published.get("published") != Some(&Value::Bool(true))
            || published.get("plan_id").and_then(Value::as_str)
                != object.get("plan_id").and_then(Value::as_str)
            || published.get("size_bytes").and_then(Value::as_u64) != Some(ticket.max_bytes)
            || sha256 != expected_artifact_sha256
        {
            return Err("destination publication receipt is invalid".into());
        }
        result["published"] = Value::Bool(true);
        result["artifact_sha256"] = Value::String(sha256.to_owned());
    }
    Ok(result)
}

fn base64url_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || value.len() % 4 == 1 {
        return Err("invalid base64url".into());
    }
    let decode = |byte: u8| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    };
    let mut bits = 0_u32;
    let mut count = 0_u8;
    let mut out = Vec::with_capacity(value.len() * 3 / 4);
    for byte in value.bytes() {
        let sextet = u32::from(decode(byte).ok_or("invalid base64url")?);
        bits = (bits << 6) | sextet;
        count += 6;
        while count >= 8 {
            count -= 8;
            out.push(((bits >> count) & 0xff) as u8);
        }
    }
    if count > 0 && (bits & ((1_u32 << count) - 1)) != 0 {
        return Err("non-canonical base64url".into());
    }
    Ok(out)
}

async fn consume_preflight_cipher(
    cache: &Arc<Mutex<HashMap<String, PreflightEphemeral>>>,
    device_id: &str,
    ticket: &AgentTransferTicket,
) -> Result<crate::transfer_crypto::TransferCipher, String> {
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock before unix epoch")?
        .as_millis() as u64;
    ticket.validate_for(device_id, &ticket.role, now_ms)?;
    let workspace = if ticket.role == "source" {
        &ticket.source_workspace_id
    } else {
        &ticket.destination_workspace_id
    };
    let key = preflight_cache_key(&[
        &ticket.role,
        &ticket.transfer_id,
        device_id,
        workspace,
        &ticket.plan_sha256,
        &ticket.session_nonce,
        &ticket.epoch.to_string(),
        &ticket.fence.to_string(),
        &ticket.transfer_expires_at.to_string(),
    ]);
    let entry = {
        let mut guard = cache.lock().await;
        guard.retain(|_, item| item.expires_at_ms > now_ms);
        guard
            .remove(&key)
            .ok_or("transfer ephemeral key is unavailable or already consumed")?
    };
    if entry.role != ticket.role
        || entry.transfer_id != ticket.transfer_id
        || entry.epoch != ticket.epoch
        || entry.fence != ticket.fence
        || entry.session_nonce != ticket.session_nonce
        || entry.expires_at_ms != ticket.transfer_expires_at
    {
        return Err("transfer ephemeral cache binding mismatch".into());
    }
    entry.key.derive(
        &ticket.peer_ephemeral_public_key(&ticket.role)?,
        &ticket.binding(),
    )
}

#[derive(Clone)]
struct TransferSessionAuthority {
    client: ClientIdentity,
    operation_id: String,
    expires_at_unix: i64,
    payload_hash: String,
    device_id: String,
}

async fn transfer_runtime_call(
    runtime: &Arc<Mutex<DaemonRuntime>>,
    authority: &TransferSessionAuthority,
    method: &str,
    params: Value,
    cancel: Option<watch::Receiver<bool>>,
) -> Result<Value, String> {
    let mut guard = runtime.lock().await;
    guard
        .dispatch_cancellable_bound(
            method,
            Some(params),
            &authority.client,
            cancel,
            Some(authority.operation_id.clone()),
            Some(authority.expires_at_unix),
            Some(authority.payload_hash.clone()),
            Some(authority.device_id.clone()),
        )
        .await
        .map_err(|error| error.to_string())
}

fn b64_standard_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for raw in bytes.chunks(3) {
        let a = raw[0];
        let b = *raw.get(1).unwrap_or(&0);
        let c = *raw.get(2).unwrap_or(&0);
        out.push(TABLE[(a >> 2) as usize] as char);
        out.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
        out.push(if raw.len() > 1 {
            TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if raw.len() > 2 {
            TABLE[(c & 63) as usize] as char
        } else {
            '='
        });
    }
    out
}

fn b64_standard_decode(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() || !value.len().is_multiple_of(4) {
        return Err("invalid base64".into());
    }
    let pad = value.bytes().rev().take_while(|byte| *byte == b'=').count();
    if pad > 2 || value[..value.len() - pad].contains('=') {
        return Err("invalid base64".into());
    }
    let decode = |byte| match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    };
    let mut out = Vec::with_capacity(value.len() / 4 * 3 - pad);
    for (index, raw) in value.as_bytes().chunks_exact(4).enumerate() {
        let last = index + 1 == value.len() / 4;
        let a = decode(raw[0]).ok_or("invalid base64")?;
        let b = decode(raw[1]).ok_or("invalid base64")?;
        let c = if raw[2] == b'=' {
            0
        } else {
            decode(raw[2]).ok_or("invalid base64")?
        };
        let d = if raw[3] == b'=' {
            0
        } else {
            decode(raw[3]).ok_or("invalid base64")?
        };
        if (raw[3] == b'=' || raw[2] == b'=') && (raw[3] != b'=' || !last) {
            return Err("invalid base64".into());
        }
        out.push((a << 2) | (b >> 4));
        if raw[2] != b'=' {
            out.push((b << 4) | (c >> 2));
        }
        if raw[3] != b'=' {
            out.push((c << 6) | d);
        }
    }
    Ok(out)
}

fn transfer_frame_binding(
    value: &serde_json::Map<String, Value>,
    ticket: &AgentTransferTicket,
) -> bool {
    value.get("protocol").and_then(Value::as_str) == Some("ownmesh.transfer/1.0")
        && value.get("transfer_id").and_then(Value::as_str) == Some(ticket.transfer_id.as_str())
        && value.get("epoch").and_then(Value::as_u64) == Some(u64::from(ticket.epoch))
        && value.get("fence").and_then(Value::as_u64) == Some(ticket.fence)
        && value.get("plan_sha256").and_then(Value::as_str) == Some(ticket.plan_sha256.as_str())
}

async fn transfer_next_text(
    socket: &mut AgentSocket,
    cancel: &mut watch::Receiver<bool>,
) -> Result<String, String> {
    tokio::select! {
        changed = cancel.changed() => {
            if changed.is_ok() && *cancel.borrow() { Err("transfer cancelled".into()) } else { Err("transfer cancellation channel closed".into()) }
        }
        frame = tokio::time::timeout(Duration::from_secs(30), socket.next()) => match frame {
            Ok(Some(Ok(Message::Text(text)))) => Ok(text.to_string()),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => Err("transfer socket closed; fresh ticket required for reconnect".into()),
            Ok(Some(Ok(_))) => Err("transfer socket binary/control frame rejected".into()),
            Ok(Some(Err(_))) => Err("transfer socket failed; fresh ticket required for reconnect".into()),
            Err(_) => Err("transfer socket ACK timeout".into()),
        }
    }
}

/// Transport loss and a local generation-staging conflict are safe for the
/// coordinator to resume with a fresh fence. Integrity, custody and binding
/// failures deliberately remain terminal and never cause an automatic retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferSessionFailure {
    Reconnect,
    Cancelled,
    Terminal,
}

fn classify_transfer_failure(error: &str) -> TransferSessionFailure {
    // A newly fenced destination may race an old process that still owns the
    // retired part handle. Generation staging then fails without mutating the
    // active part; only another fresh ticket/fence can safely retry it.
    if error.contains("transfer lease is held by another owner")
        || error.contains("journal lease or fence is stale")
    {
        return TransferSessionFailure::Reconnect;
    }
    match error {
        "transfer cancelled" => TransferSessionFailure::Cancelled,
        "transfer socket closed; fresh ticket required for reconnect"
        | "transfer socket failed; fresh ticket required for reconnect"
        | "transfer socket ACK timeout"
        | "transfer send failed"
        | "transfer ACK send failed"
        | "transfer finish send failed"
        | "transfer finish acknowledgement send failed"
        | "transfer peer unavailable; fresh ticket required for reconnect"
        | "source cleanup pending" => TransferSessionFailure::Reconnect,
        _ => TransferSessionFailure::Terminal,
    }
}

fn transfer_room_reconnect_signal(frame: &serde_json::Map<String, Value>) -> bool {
    frame.len() == 3
        && frame.get("protocol").and_then(Value::as_str) == Some("ownmesh.transfer/1.0")
        && frame.get("type").and_then(Value::as_str) == Some("error")
        && matches!(
            frame.get("code").and_then(Value::as_str),
            Some("destination_offline" | "peer_unavailable")
        )
}

fn reject_transfer_room_reconnect_signal(
    frame: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    if transfer_room_reconnect_signal(frame) {
        Err("transfer peer unavailable; fresh ticket required for reconnect".into())
    } else {
        Ok(())
    }
}

async fn transfer_ready_cursor(
    socket: &mut AgentSocket,
    ticket: &AgentTransferTicket,
    cancel: &mut watch::Receiver<bool>,
) -> Result<(u64, u64), String> {
    let raw = transfer_next_text(socket, cancel).await?;
    let frame: Value = serde_json::from_str(&raw).map_err(|_| "invalid transfer ready frame")?;
    let object = frame.as_object().ok_or("invalid transfer ready frame")?;
    reject_transfer_room_reconnect_signal(object)?;
    if object.get("type").and_then(Value::as_str) != Some("ready")
        || !transfer_frame_binding(object, ticket)
    {
        return Err("transfer ready binding mismatch".into());
    }
    let sequence = object
        .get("next_sequence")
        .and_then(Value::as_u64)
        .ok_or("transfer ready cursor missing")?;
    let offset = object
        .get("next_offset")
        .and_then(Value::as_u64)
        .ok_or("transfer ready cursor missing")?;
    if offset > ticket.max_bytes {
        return Err("transfer ready cursor exceeds plan".into());
    }
    Ok((sequence, offset))
}

async fn run_source_transfer_pump(
    socket: &mut AgentSocket,
    runtime: &Arc<Mutex<DaemonRuntime>>,
    authority: &TransferSessionAuthority,
    ticket: &AgentTransferTicket,
    cipher: crate::transfer_crypto::TransferCipher,
    plan_id: &str,
    cursor: (u64, u64),
    cancel: &mut watch::Receiver<bool>,
) -> Result<Value, String> {
    let opened = transfer_runtime_call(runtime, authority, methods::TRANSFER_SOURCE_OPEN,
        json!({"plan_id":plan_id,"sequence":cursor.0,"offset":cursor.1,"workspace_id":ticket.source_workspace_id}), None).await?;
    let mut sequence = opened
        .get("next_sequence")
        .and_then(Value::as_u64)
        .ok_or("source cursor missing")?;
    let mut offset = opened
        .get("next_offset")
        .and_then(Value::as_u64)
        .ok_or("source cursor missing")?;
    if (sequence, offset) != cursor {
        return Err("source durable cursor differs from transfer room".into());
    }
    loop {
        let next = transfer_runtime_call(
            runtime,
            authority,
            methods::TRANSFER_SOURCE_CHUNK,
            json!({"plan_id":plan_id,"sequence":sequence}),
            None,
        )
        .await;
        let chunk_reply = next?;
        if chunk_reply.get("eof") == Some(&Value::Bool(true)) {
            if offset != ticket.max_bytes {
                return Err("source ended before immutable transfer size".into());
            }
            socket
                .send(Message::Text(
                    json!({"protocol":"ownmesh.transfer/1.0","type":"finish","transfer_id":ticket.transfer_id,"epoch":ticket.epoch,"fence":ticket.fence,"plan_sha256":ticket.plan_sha256})
                        .to_string()
                        .into(),
                ))
                .await
                .map_err(|_| "transfer finish send failed")?;
            let finish = transfer_next_text(socket, cancel).await?;
            let finish: Value = serde_json::from_str(&finish)
                .map_err(|_| "invalid transfer finish acknowledgement")?;
            let finish = finish
                .as_object()
                .ok_or("invalid transfer finish acknowledgement")?;
            reject_transfer_room_reconnect_signal(finish)?;
            if finish.get("type").and_then(Value::as_str) != Some("finish_ack")
                || !transfer_frame_binding(finish, ticket)
            {
                return Err("transfer finish acknowledgement binding mismatch".into());
            }
            // Only the authenticated Room finish_ack makes source custody
            // terminal. Before it, the retained snapshot is the sole safe
            // resume source if the original pathname changes or disappears.
            cleanup_source_transfer_state(runtime, authority, ticket, plan_id).await?;
            return Ok(
                json!({"transfer_id":ticket.transfer_id,"state":"source_finished","plan_sha256":ticket.plan_sha256}),
            );
        }
        let raw = chunk_reply
            .get("frame_base64")
            .and_then(Value::as_str)
            .ok_or("source chunk frame missing")?;
        let chunk =
            TransferChunk::decode(&b64_standard_decode(raw)?).map_err(|error| error.to_string())?;
        if chunk.sequence != sequence || chunk.offset != offset {
            return Err("source emitted non-contiguous chunk".into());
        }
        let ciphertext = cipher.seal(chunk.sequence, chunk.offset, &chunk.sha256, &chunk.bytes)?;
        let frame = json!({"protocol":"ownmesh.transfer/1.0","type":"chunk","transfer_id":ticket.transfer_id,"epoch":ticket.epoch,"fence":ticket.fence,"plan_sha256":ticket.plan_sha256,"sequence":chunk.sequence,"offset":chunk.offset,"length":chunk.bytes.len(),"ciphertext_base64":b64_standard_encode(&ciphertext),"chunk_sha256":chunk.sha256});
        socket
            .send(Message::Text(frame.to_string().into()))
            .await
            .map_err(|_| "transfer send failed")?;
        let raw_ack = transfer_next_text(socket, cancel).await?;
        let ack: Value = serde_json::from_str(&raw_ack).map_err(|_| "invalid transfer ACK")?;
        let object = ack.as_object().ok_or("invalid transfer ACK")?;
        reject_transfer_room_reconnect_signal(object)?;
        if object.get("type").and_then(Value::as_str) != Some("ack")
            || !transfer_frame_binding(object, ticket)
            || object.get("sequence").and_then(Value::as_u64) != Some(sequence)
            || object.get("next_offset").and_then(Value::as_u64)
                != Some(offset + chunk.bytes.len() as u64)
        {
            return Err("transfer ACK binding mismatch".into());
        }
        sequence += 1;
        offset += chunk.bytes.len() as u64;
    }
}

async fn cleanup_source_transfer_state(
    runtime: &Arc<Mutex<DaemonRuntime>>,
    authority: &TransferSessionAuthority,
    ticket: &AgentTransferTicket,
    plan_id: &str,
) -> Result<(), String> {
    // Owner-only file removal can briefly contend with an antivirus/indexer or
    // an older process handle on Windows. Keep the Agent retry bounded; after
    // that the coordinator receives a fixed cleanup-pending code and routes an
    // exact source cleanup operation instead of manufacturing success.
    for attempt in 0..4 {
        if transfer_runtime_call(
            runtime,
            authority,
            methods::TRANSFER_CANCEL,
            json!({"plan_id":plan_id,"epoch":ticket.epoch,"fence":ticket.fence}),
            None,
        )
        .await
        .is_ok()
        {
            return Ok(());
        }
        if attempt < 3 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
    Err("source cleanup pending".into())
}

async fn run_destination_transfer_pump(
    socket: &mut AgentSocket,
    runtime: &Arc<Mutex<DaemonRuntime>>,
    authority: &TransferSessionAuthority,
    ticket: &AgentTransferTicket,
    cipher: crate::transfer_crypto::TransferCipher,
    plan_id: &str,
    cursor: (u64, u64),
    cancel: &mut watch::Receiver<bool>,
) -> Result<Value, String> {
    let prepared = transfer_runtime_call(runtime, authority, methods::TRANSFER_DESTINATION_PREPARE,
        json!({"plan_id":plan_id,"epoch":ticket.epoch,"fence":ticket.fence,"next_sequence":cursor.0,"next_offset":cursor.1,"workspace_id":ticket.destination_workspace_id}), None).await?;
    let mut expected_sequence = prepared
        .get("next_sequence")
        .and_then(Value::as_u64)
        .ok_or("destination cursor missing")?;
    let mut expected_offset = prepared
        .get("next_offset")
        .and_then(Value::as_u64)
        .ok_or("destination cursor missing")?;
    if (expected_sequence, expected_offset) != cursor {
        return Err("destination durable cursor differs from transfer room".into());
    }
    loop {
        let raw = transfer_next_text(socket, cancel).await?;
        let frame: Value = serde_json::from_str(&raw).map_err(|_| "invalid transfer frame")?;
        let object = frame.as_object().ok_or("invalid transfer frame")?;
        reject_transfer_room_reconnect_signal(object)?;
        if object.get("type").and_then(Value::as_str) == Some("cancel") {
            if transfer_frame_binding(object, ticket) {
                return Err("transfer cancelled".into());
            }
            return Err("transfer cancel binding mismatch".into());
        }
        if object.get("type").and_then(Value::as_str) == Some("finish") {
            if !transfer_frame_binding(object, ticket) {
                return Err("transfer finish binding mismatch".into());
            }
            if expected_offset != ticket.max_bytes {
                return Err("transfer finish before durable destination completion".into());
            }
            let finalized = transfer_runtime_call(runtime, authority, methods::TRANSFER_FINALIZE, json!({"plan_id":plan_id,"epoch":ticket.epoch,"fence":ticket.fence,"workspace_id":ticket.destination_workspace_id}), None).await?;
            // Publication is already atomic and authenticated locally. Preserve
            // that authoritative receipt even when the reply socket disappears;
            // the coordinator will stop and clean the source before completing.
            let _ = socket.send(Message::Text(json!({"protocol":"ownmesh.transfer/1.0","type":"finish_ack","transfer_id":ticket.transfer_id,"epoch":ticket.epoch,"fence":ticket.fence,"plan_sha256":ticket.plan_sha256}).to_string().into())).await;
            return Ok(finalized);
        }
        if object.get("type").and_then(Value::as_str) != Some("chunk")
            || !transfer_frame_binding(object, ticket)
        {
            return Err("transfer frame binding mismatch".into());
        }
        let sequence = object
            .get("sequence")
            .and_then(Value::as_u64)
            .ok_or("chunk sequence missing")?;
        let offset = object
            .get("offset")
            .and_then(Value::as_u64)
            .ok_or("chunk offset missing")?;
        let length = object
            .get("length")
            .and_then(Value::as_u64)
            .and_then(|n| usize::try_from(n).ok())
            .filter(|n| *n > 0 && *n <= 64 * 1024)
            .ok_or("chunk length invalid")?;
        let sha = object
            .get("chunk_sha256")
            .and_then(Value::as_str)
            .ok_or("chunk hash missing")?;
        let mut encrypted = b64_standard_decode(
            object
                .get("ciphertext_base64")
                .and_then(Value::as_str)
                .ok_or("ciphertext missing")?,
        )?;
        if sequence != expected_sequence || offset != expected_offset {
            return Err("destination chunk is not contiguous".into());
        }
        let plaintext = cipher.open(sequence, offset, length, sha, &mut encrypted)?;
        let chunk =
            TransferChunk::new(sequence, offset, plaintext).map_err(|error| error.to_string())?;
        let saved = transfer_runtime_call(runtime, authority, methods::TRANSFER_DESTINATION_CHUNK,
            json!({"plan_id":plan_id,"epoch":ticket.epoch,"fence":ticket.fence,"workspace_id":ticket.destination_workspace_id,"frame_base64":b64_standard_encode(&chunk.encode().map_err(|error| error.to_string())?)}), None).await?;
        // Durable destination_chunk completed before this ACK is emitted.
        let next_offset = offset + length as u64;
        socket.send(Message::Text(json!({"protocol":"ownmesh.transfer/1.0","type":"ack","transfer_id":ticket.transfer_id,"epoch":ticket.epoch,"fence":ticket.fence,"plan_sha256":ticket.plan_sha256,"sequence":sequence,"next_offset":next_offset}).to_string().into())).await.map_err(|_| "transfer ACK send failed")?;
        if saved.get("completed") == Some(&Value::Bool(true)) && next_offset != ticket.max_bytes {
            return Err("destination reported completed before immutable transfer size".into());
        }
        expected_sequence += 1;
        expected_offset = next_offset;
    }
}

/// Resolve the single active instance and its issuer/device-bound credential.
/// Missing enrollment leaves the remote transport disabled without weakening
/// the local IPC daemon.
pub fn configured_transport(
    paths: &OwnMeshPaths,
    cfg: &OwnMeshConfig,
) -> Result<Option<AgentTransportConfig>, String> {
    let Some(active_id) = cfg.active_instance.as_deref() else {
        return Ok(None);
    };
    let instance = cfg
        .instances
        .iter()
        .find(|candidate| candidate.id == active_id)
        .ok_or_else(|| format!("active instance '{active_id}' is not configured"))?;
    let issuer = ownmesh_config::validate_control_plane_base_url(&instance.base_url)
        .map_err(|error| error.to_string())?;
    let base = Url::parse(&issuer).map_err(|error| format!("invalid active issuer: {error}"))?;

    let service = keychain_service(cfg);
    if service != DEFAULT_KEYCHAIN_SERVICE {
        tracing::info!("debug loopback keychain isolation enabled");
    }
    let store = PreferredSecretStore::open(service, paths.keystore_dir())
        .map_err(|error| format!("open device secret store: {error}"))?;
    let Some(envelope) = load_device_credential(&store)
        .map_err(|error| format!("load device credential: {error}"))?
    else {
        return Ok(None);
    };
    if !envelope.matches(&issuer, &envelope.device_id) {
        return Err("stored device credential is not bound to the active issuer".into());
    }
    let device_id = DeviceId::parse(&envelope.device_id)
        .map_err(|error| format!("stored device id is invalid: {error}"))?;
    let key = load_or_create_device_key(&store)
        .map_err(|error| format!("load device signing key: {error}"))?;
    let ws_url = agent_connect_url(&issuer, device_id.as_str())?;
    let origin = base.origin().ascii_serialization();

    Ok(Some(AgentTransportConfig {
        issuer,
        ws_url,
        origin,
        device_id,
        credential: envelope.credential().clone(),
        key: Arc::new(key),
        preflight_ephemerals: Arc::new(Mutex::new(HashMap::new())),
        state_path: paths.state_dir.join(TRANSPORT_STATE_FILE),
    }))
}

/// Production uses the fixed service name. Debug binaries may select an
/// isolated service only for a loopback active issuer, enabling a real-binary
/// workerd test without touching a developer's normal OwnMesh keychain entry.
pub fn keychain_service(cfg: &OwnMeshConfig) -> String {
    #[cfg(debug_assertions)]
    {
        let loopback_active = cfg
            .active_instance
            .as_deref()
            .and_then(|id| cfg.instances.iter().find(|instance| instance.id == id))
            .and_then(|instance| Url::parse(&instance.base_url).ok())
            .is_some_and(|url| {
                matches!(
                    url.host_str().unwrap_or("").to_ascii_lowercase().as_str(),
                    "127.0.0.1" | "localhost" | "::1"
                )
            });
        if loopback_active {
            if let Ok(service) = std::env::var(LOOPBACK_TEST_KEYCHAIN_SERVICE_ENV) {
                if service.starts_with("dev.ownmesh.loopback-test.")
                    && service.len() <= 128
                    && service.chars().all(|character| {
                        character.is_ascii_alphanumeric() || ".-_".contains(character)
                    })
                {
                    return service;
                }
            }
        }
    }
    DEFAULT_KEYCHAIN_SERVICE.to_owned()
}

fn agent_connect_url(issuer: &str, device_id: &str) -> Result<Url, String> {
    let raw = format!("{}/agent/connect", issuer.trim_end_matches('/'));
    let mut url = Url::parse(&raw).map_err(|error| format!("build agent connect URL: {error}"))?;
    let websocket_scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err("control-plane URL must use https or loopback http".into()),
    };
    url.set_scheme(websocket_scheme)
        .map_err(|()| "failed to set WebSocket URL scheme".to_owned())?;
    url.query_pairs_mut()
        .clear()
        .append_pair("device_id", device_id)
        .append_pair("role", "agent");
    url.set_fragment(None);
    Ok(url)
}

fn transfer_connect_url(issuer: &str) -> Result<Url, String> {
    let raw = format!("{}/transfer/connect", issuer.trim_end_matches('/'));
    let mut url =
        Url::parse(&raw).map_err(|error| format!("build transfer connect URL: {error}"))?;
    let websocket_scheme = match url.scheme() {
        "https" => "wss",
        "http" => "ws",
        _ => return Err("control-plane URL must use https or loopback http".into()),
    };
    url.set_scheme(websocket_scheme)
        .map_err(|()| "failed to set transfer WebSocket URL scheme".to_owned())?;
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

/// Open the short-lived transfer WebSocket using the already enrolled device
/// credential. Ticket authority is carried only in a header, never a URL.
/// The caller supplies the ticket decoded from the exact signed Worker value;
/// this method checks its device/role/expiry/key proofs before the upgrade.
pub async fn connect_transfer_socket(
    config: &AgentTransportConfig,
    ticket_wire: &str,
    ticket: &AgentTransferTicket,
) -> Result<AgentSocket, String> {
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "system time is before UNIX epoch")?
        .as_millis()
        .try_into()
        .map_err(|_| "system time exceeds transfer ticket range")?;
    ticket.validate_for(config.device_id.as_str(), &ticket.role, now_ms)?;
    if ticket_wire.is_empty()
        || ticket_wire.len() > 16 * 1024
        || ticket_wire.chars().any(char::is_whitespace)
    {
        return Err("invalid transfer ticket wire value".into());
    }
    let mut request = transfer_connect_url(&config.issuer)?
        .as_str()
        .into_client_request()
        .map_err(|error| format!("build transfer WebSocket request: {error}"))?;
    let bearer = format!("Bearer {}", config.credential.expose());
    request.headers_mut().insert(
        AUTHORIZATION,
        bearer
            .parse()
            .map_err(|_| "device credential cannot be encoded as an HTTP header")?,
    );
    request.headers_mut().insert(
        ORIGIN,
        config
            .origin
            .parse()
            .map_err(|_| "control-plane origin cannot be encoded as an HTTP header")?,
    );
    request.headers_mut().insert(
        "x-ownmesh-transfer-ticket",
        ticket_wire
            .parse()
            .map_err(|_| "transfer ticket cannot be encoded as an HTTP header")?,
    );
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_TRANSFER_SOCKET_BYTES))
        .max_frame_size(Some(MAX_TRANSFER_SOCKET_BYTES));
    let (socket, _) = connect_async_with_config(request, Some(ws_config), true)
        .await
        .map_err(|error| format!("transfer WebSocket connect failed: {error}"))?;
    Ok(socket)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompletedReply {
    correlation_id: String,
    operation_id: String,
    payload: Value,
}

/// Immutable accepted operation.request kept until a durable completion exists.
/// Survives crash between "seen" acknowledgment and side-effect finish so
/// control-plane replay can resume dispatch or resend a terminal result.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingDispatch {
    message_id: String,
    correlation_id: String,
    operation_id: String,
    raw: String,
    accepted_at: String,
    /// transfer.start tickets and ephemeral proof material are single-use and
    /// must never enter the device crash outbox. These receipts deliberately
    /// cannot be redelivered after a restart; the coordinator must mint a
    /// fresh epoch/fence/ticket after new preflight evidence.
    #[serde(default)]
    transfer_session_lost: bool,
    #[serde(default)]
    expires_at: Option<String>,
    /// `Some(true)` is durably saved immediately before runtime dispatch;
    /// `Some(false)` is known not to have crossed the side-effect boundary.
    /// Legacy state has `None`, whose outcome must not be guessed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    dispatch_started: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AgentTransportState {
    version: u32,
    issuer: String,
    device_id: String,
    next_outbound_seq: u64,
    last_server_seq: u64,
    #[serde(default)]
    seen_message_ids: VecDeque<String>,
    #[serde(default)]
    completed_replies: VecDeque<CompletedReply>,
    /// Crash outbox: raw envelopes accepted but not yet completed.
    #[serde(default)]
    pending_dispatches: VecDeque<PendingDispatch>,
}

impl AgentTransportState {
    fn fresh(issuer: &str, device_id: &DeviceId) -> Self {
        Self {
            version: TRANSPORT_STATE_VERSION,
            issuer: issuer.to_owned(),
            device_id: device_id.to_string(),
            next_outbound_seq: 0,
            last_server_seq: 0,
            seen_message_ids: VecDeque::new(),
            completed_replies: VecDeque::new(),
            pending_dispatches: VecDeque::new(),
        }
    }

    fn load(path: &Path, issuer: &str, device_id: &DeviceId) -> Result<Self, String> {
        // Ceiling BEFORE allocation: never `read()` an attacker-grown state file
        // into memory and only then discover it exceeds the budget.
        let meta = match std::fs::metadata(path) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::fresh(issuer, device_id));
            }
            Err(error) => return Err(format!("stat transport state: {error}")),
        };
        if meta.len() as usize > MAX_TRANSPORT_STATE_FILE_BYTES {
            return Err(format!(
                "transport state exceeds {MAX_TRANSPORT_STATE_FILE_BYTES} byte budget"
            ));
        }
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::fresh(issuer, device_id));
            }
            Err(error) => return Err(format!("read transport state: {error}")),
        };
        if bytes.len() > MAX_TRANSPORT_STATE_FILE_BYTES {
            return Err(format!(
                "transport state exceeds {MAX_TRANSPORT_STATE_FILE_BYTES} byte budget"
            ));
        }
        let mut state: Self = serde_json::from_slice(&bytes)
            .map_err(|error| format!("transport state is corrupt: {error}"))?;
        if state.version != TRANSPORT_STATE_VERSION {
            return Err(format!(
                "unsupported transport state version {}",
                state.version
            ));
        }
        if state.issuer != issuer || state.device_id != device_id.as_str() {
            return Ok(Self::fresh(issuer, device_id));
        }
        if state.next_outbound_seq > MAX_SAFE_JSON_INTEGER
            || state.last_server_seq > MAX_SAFE_JSON_INTEGER
        {
            return Err("transport state sequence exceeds JSON safe-integer range".into());
        }
        trim_front(&mut state.seen_message_ids, MAX_REPLAY_ENTRIES);
        trim_front(&mut state.completed_replies, MAX_COMPLETED_REPLIES);
        state.enforce_completed_reply_budgets();
        state.enforce_pending_dispatch_budgets();
        Ok(state)
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("serialize transport state: {error}"))?;
        if bytes.len() > MAX_TRANSPORT_STATE_FILE_BYTES {
            return Err(format!(
                "transport state serialize exceeds {MAX_TRANSPORT_STATE_FILE_BYTES} byte budget"
            ));
        }
        bytes.push(b'\n');
        atomic_write(path, &bytes).map_err(|error| format!("persist transport state: {error}"))
    }

    fn next_seq(&mut self) -> Result<u64, String> {
        if self.next_outbound_seq >= MAX_SAFE_JSON_INTEGER {
            return Err("outbound sequence exhausted JSON safe-integer range".into());
        }
        self.next_outbound_seq += 1;
        Ok(self.next_outbound_seq)
    }

    fn has_seen_message(&self, message_id: &str) -> bool {
        self.seen_message_ids
            .iter()
            .any(|candidate| candidate == message_id)
    }

    fn remember_message(&mut self, message_id: String) {
        self.seen_message_ids.push_back(message_id);
        trim_front(&mut self.seen_message_ids, MAX_REPLAY_ENTRIES);
    }

    fn completed(&self, correlation_id: &str) -> Option<&CompletedReply> {
        self.completed_replies
            .iter()
            .find(|reply| reply.correlation_id == correlation_id)
    }

    fn remember_completed(&mut self, reply: CompletedReply) {
        // Terminal result supersedes any crash-outbox entry for this correlation.
        self.clear_pending_by_correlation(&reply.correlation_id);
        let compact = compact_completed_reply(reply);
        self.completed_replies
            .retain(|candidate| candidate.correlation_id != compact.correlation_id);
        self.completed_replies.push_back(compact);
        trim_front(&mut self.completed_replies, MAX_COMPLETED_REPLIES);
        self.enforce_completed_reply_budgets();
    }

    fn pending_by_correlation(&self, correlation_id: &str) -> Option<&PendingDispatch> {
        self.pending_dispatches
            .iter()
            .find(|pending| pending.correlation_id == correlation_id)
    }

    fn remember_pending(&mut self, pending: PendingDispatch) -> Result<(), String> {
        if pending.raw.len() > MAX_PENDING_RAW_BYTES {
            return Err(format!(
                "pending operation envelope exceeds {MAX_PENDING_RAW_BYTES} byte budget"
            ));
        }
        if pending.correlation_id.is_empty() || pending.message_id.is_empty() {
            return Err("pending dispatch requires message_id and correlation_id".into());
        }
        // Replace any prior accept for the same correlation (should be rare).
        self.pending_dispatches
            .retain(|candidate| candidate.correlation_id != pending.correlation_id);
        // Capacity reject WITHOUT live-entry eviction (matches nonce map policy).
        if self.pending_dispatches.len() >= MAX_PENDING_DISPATCHES {
            return Err(format!(
                "pending dispatch outbox full (max {MAX_PENDING_DISPATCHES}); no live eviction"
            ));
        }
        let total_raw = self
            .pending_dispatches
            .iter()
            .map(|p| p.raw.len())
            .sum::<usize>()
            .saturating_add(pending.raw.len());
        if total_raw > MAX_COMPLETED_REPLIES_BYTES / 2 {
            return Err("pending dispatch outbox byte budget exhausted; no live eviction".into());
        }
        self.pending_dispatches.push_back(pending);
        Ok(())
    }

    fn clear_pending_by_correlation(&mut self, correlation_id: &str) {
        self.pending_dispatches
            .retain(|pending| pending.correlation_id != correlation_id);
    }

    fn mark_dispatch_started(&mut self, correlation_id: &str) -> Result<(), String> {
        let pending = self
            .pending_dispatches
            .iter_mut()
            .find(|pending| pending.correlation_id == correlation_id)
            .ok_or_else(|| "cannot mark a missing pending dispatch as started".to_owned())?;
        pending.dispatch_started = Some(true);
        Ok(())
    }

    fn enforce_pending_dispatch_budgets(&mut self) {
        // Load-time hard bound only (corrupt/oversize files). Runtime admits never
        // grow past the cap without an explicit capacity error.
        while self.pending_dispatches.len() > MAX_PENDING_DISPATCHES {
            let _ = self.pending_dispatches.pop_front();
        }
        let mut total_raw = self
            .pending_dispatches
            .iter()
            .map(|p| p.raw.len())
            .sum::<usize>();
        while total_raw > MAX_COMPLETED_REPLIES_BYTES / 2 {
            let Some(oldest) = self.pending_dispatches.pop_front() else {
                break;
            };
            total_raw = total_raw.saturating_sub(oldest.raw.len());
        }
    }

    /// Compact oversize entries, then drop oldest until aggregate bytes fit.
    /// Compact receipts retain status/operation_id for exact-once replay.
    fn enforce_completed_reply_budgets(&mut self) {
        let mut compacted = VecDeque::with_capacity(self.completed_replies.len());
        while let Some(reply) = self.completed_replies.pop_front() {
            compacted.push_back(compact_completed_reply(reply));
        }
        self.completed_replies = compacted;
        while completed_replies_bytes(&self.completed_replies) > MAX_COMPLETED_REPLIES_BYTES {
            let Some(oldest) = self.completed_replies.pop_front() else {
                break;
            };
            let receipt = completion_receipt(&oldest);
            let already_receipt = oldest.payload.get("durable_receipt") == Some(&Value::Bool(true));
            if already_receipt {
                // Oldest is already minimal; drop it to free budget.
                continue;
            }
            // Re-queue compacted receipt at the front and re-check; if still over,
            // next iteration drops it.
            self.completed_replies.push_front(receipt);
            if completed_replies_bytes(&self.completed_replies) > MAX_COMPLETED_REPLIES_BYTES {
                let _ = self.completed_replies.pop_front();
            }
        }
        trim_front(&mut self.completed_replies, MAX_COMPLETED_REPLIES);
    }
}

fn completed_replies_bytes(replies: &VecDeque<CompletedReply>) -> usize {
    replies
        .iter()
        .map(|reply| {
            serde_json::to_vec(&reply.payload)
                .map(|b| b.len())
                .unwrap_or(0)
                + reply.correlation_id.len()
                + reply.operation_id.len()
        })
        .sum()
}

fn compact_completed_reply(reply: CompletedReply) -> CompletedReply {
    let payload_bytes = serde_json::to_vec(&reply.payload)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);
    if payload_bytes <= MAX_COMPLETED_REPLY_PAYLOAD_BYTES {
        return reply;
    }
    completion_receipt(&reply)
}

fn completion_receipt(reply: &CompletedReply) -> CompletedReply {
    let status = reply
        .payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("completed")
        .to_owned();
    let error = reply.payload.get("error").cloned();
    let mut payload = json!({
        "operation_contract": OPERATION_CONTRACT_V1,
        "operation_id": reply.operation_id,
        "status": status,
        "durable_receipt": true,
        "truncated": true,
        "note": "full result exceeded durable Agent reply budget; completion retained for exact-once replay"
    });
    if let Some(err) = error {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("error".into(), err);
        }
    }
    CompletedReply {
        correlation_id: reply.correlation_id.clone(),
        operation_id: reply.operation_id.clone(),
        payload,
    }
}

fn trim_front<T>(values: &mut VecDeque<T>, maximum: usize) {
    while values.len() > maximum {
        values.pop_front();
    }
}

enum InboundFrame {
    New { raw: String, envelope: Envelope },
    Duplicate(Envelope),
}

/// Maintain an authenticated Agent connection until shutdown, reconnecting with
/// bounded exponential backoff. Errors never include credential material.
///
/// When `runtime` is `Some`, the Agent advertises remote routing and dispatches
/// validated operation requests through the shared local policy runtime.
pub async fn run(
    config: AgentTransportConfig,
    runtime: Option<Arc<Mutex<DaemonRuntime>>>,
    mut shutdown: watch::Receiver<bool>,
) {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut state = match AgentTransportState::load(
        &config.state_path,
        &config.issuer,
        &config.device_id,
    ) {
        Ok(state) => state,
        Err(error) => {
            tracing::error!(error = %error, "remote Agent transport state rejected; transport disabled");
            return;
        }
    };
    let mut backoff = ReconnectBackoff::default();
    loop {
        if *shutdown.borrow() {
            return;
        }
        let mut reached_ready = false;
        match connect_and_run(
            &config,
            runtime.as_ref(),
            &mut state,
            &mut shutdown,
            &mut reached_ready,
        )
        .await
        {
            Ok(()) => return,
            Err(error) => {
                tracing::warn!(
                    issuer = %ownmesh_config::redact_control_plane_url(&config.issuer),
                    phase = if reached_ready { "authenticated_ready" } else { "pre_ready" },
                    category = reconnect_failure_category(&error),
                    "Agent WebSocket disconnected; reconnecting"
                );
            }
        }
        if reached_ready {
            backoff.reset_after_ready();
        }
        let delay = backoff.next_delay();
        tracing::info!(
            phase = if reached_ready {
                "authenticated_ready"
            } else {
                "pre_ready"
            },
            reconnect_delay_ms = delay.as_millis(),
            "Agent reconnect delay selected"
        );
        tokio::select! {
            () = tokio::time::sleep(delay) => {}
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return;
                }
            }
        }
    }
}

async fn connect_and_run(
    config: &AgentTransportConfig,
    runtime: Option<&Arc<Mutex<DaemonRuntime>>>,
    state: &mut AgentTransportState,
    shutdown: &mut watch::Receiver<bool>,
    reached_ready: &mut bool,
) -> Result<(), String> {
    let mut request = config
        .ws_url
        .as_str()
        .into_client_request()
        .map_err(|error| format!("build WebSocket request: {error}"))?;
    let bearer = format!("Bearer {}", config.credential.expose());
    request.headers_mut().insert(
        AUTHORIZATION,
        bearer
            .parse()
            .map_err(|_| "device credential cannot be encoded as an HTTP header".to_owned())?,
    );
    request.headers_mut().insert(
        ORIGIN,
        config
            .origin
            .parse()
            .map_err(|_| "control-plane origin cannot be encoded as an HTTP header".to_owned())?,
    );
    request.headers_mut().insert(
        USER_AGENT,
        format!("ownmeshd/{}", env!("CARGO_PKG_VERSION"))
            .parse()
            .map_err(|_| "Agent version cannot be encoded as an HTTP header".to_owned())?,
    );
    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_PAYLOAD_BYTES))
        .max_frame_size(Some(MAX_PAYLOAD_BYTES));
    let connect = connect_async_with_config(request, Some(ws_config), true);
    let (mut socket, _) = tokio::select! {
        result = connect => result.map_err(|error| format!("WebSocket connect failed: {error}"))?,
        changed = shutdown.changed() => {
            if changed.is_err() || *shutdown.borrow() {
                return Ok(());
            }
            return Err("shutdown watch changed without shutdown".into());
        }
    };

    let workspace_registry = if let Some(runtime) = runtime {
        Some(runtime.lock().await.remote_workspace_registry())
    } else {
        None
    };
    perform_handshake(&mut socket, config, state, workspace_registry.as_ref()).await?;
    *reached_ready = true;
    tracing::info!(
        issuer = %ownmesh_config::redact_control_plane_url(&config.issuer),
        device_id = %config.device_id,
        remote_routing_enabled = runtime.is_some(),
        "Agent WebSocket authenticated and ready"
    );
    live_loop(&mut socket, config, runtime, state, shutdown).await
}

async fn perform_handshake(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    workspace_registry: Option<&(bool, Vec<String>)>,
) -> Result<(), String> {
    let remote_routing_enabled = workspace_registry.is_some();
    let resume = json!({
        "last_server_seq": state.last_server_seq,
        "next_outbound_seq": state.next_outbound_seq,
        "completed_correlations": state.completed_replies.iter().rev().take(64).map(|reply| reply.correlation_id.clone()).collect::<Vec<_>>(),
    });
    send_envelope(
        socket,
        config,
        state,
        "hello",
        json!({
            "protocols": [PROTOCOL_DEVICE_V1],
            "operation_contracts": [OPERATION_CONTRACT_V1],
            "agent_version": env!("CARGO_PKG_VERSION"),
            "resume": resume,
        }),
        None,
    )
    .await?;

    let challenge = wait_for_type(socket, config, state, "challenge").await?;
    let challenge_message = challenge
        .payload
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.is_empty())
        .ok_or_else(|| "challenge omitted its signed message".to_owned())?;
    let signature = hex_encode(config.key.sign(challenge_message.as_bytes()).expose());
    let connection_id = challenge.payload.get("connection_id").cloned();
    let mut proof = json!({ "signature": signature });
    if let (Some(connection_id), Some(object)) = (connection_id, proof.as_object_mut()) {
        object.insert("connection_id".into(), connection_id);
    }
    send_envelope(socket, config, state, "proof", proof, None).await?;

    let accepted = wait_for_type(socket, config, state, "accepted").await?;
    if accepted
        .payload
        .get("selected_protocol")
        .and_then(Value::as_str)
        != Some(PROTOCOL_DEVICE_V1)
    {
        return Err("control plane selected an unsupported device protocol".into());
    }
    let capabilities = if remote_routing_enabled {
        json!([
            "filesystem.read",
            "filesystem.write",
            "command.run",
            "operation.cancel"
        ])
    } else {
        json!([])
    };
    let mut ready_payload = json!({
        "capabilities": capabilities,
        "operation_contracts": [OPERATION_CONTRACT_V1],
        // DeviceRoom records display/security metadata only after proof+ready,
        // not from the unauthenticated hello envelope.
        "agent_version": env!("CARGO_PKG_VERSION"),
        "protocol_version": PROTOCOL_DEVICE_V1,
        "remote_routing_enabled": remote_routing_enabled,
    });
    if let (Some((enforce_workspace, workspace_ids)), Some(object)) =
        (workspace_registry, ready_payload.as_object_mut())
    {
        object.insert(
            "workspace_registry".into(),
            json!({
                "enforce_workspace": enforce_workspace,
                "ids": workspace_ids,
            }),
        );
    }
    send_envelope(socket, config, state, "ready", ready_payload, None).await?;
    let _ = wait_for_type(socket, config, state, "ready.ack").await?;
    Ok(())
}

async fn wait_for_type(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    expected: &str,
) -> Result<Envelope, String> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            match receive_frame(socket, config, state).await? {
                InboundFrame::Duplicate(_) => {}
                InboundFrame::New { envelope, .. } if envelope.message_type == expected => {
                    return Ok(envelope);
                }
                InboundFrame::New { envelope, .. } if envelope.message_type == "error" => {
                    return Err("control plane rejected Agent handshake".into());
                }
                InboundFrame::New { envelope, .. } => {
                    return Err(format!(
                        "expected handshake message '{expected}', got '{}'",
                        envelope.message_type
                    ));
                }
            }
        }
    })
    .await
    .map_err(|_| format!("timed out waiting for handshake message '{expected}'"))?
}

/// In-flight remote operation cancellation handles live outside the runtime mutex
/// so cancel can interrupt a long command without waiting for dispatch to finish.
#[derive(Default)]
struct CancelRegistry {
    inner: Mutex<HashMap<String, watch::Sender<bool>>>,
}

impl CancelRegistry {
    async fn register(&self, operation_id: &str) -> watch::Receiver<bool> {
        let (tx, rx) = watch::channel(false);
        let mut guard = self.inner.lock().await;
        if let Some(prev) = guard.insert(operation_id.to_owned(), tx) {
            let _ = prev.send(true);
        }
        rx
    }

    async fn cancel(&self, operation_id: &str) -> bool {
        let guard = self.inner.lock().await;
        if let Some(tx) = guard.get(operation_id) {
            let _ = tx.send(true);
            true
        } else {
            false
        }
    }

    async fn forget(&self, operation_id: &str) {
        let mut guard = self.inner.lock().await;
        guard.remove(operation_id);
    }
}

struct FinishedRemoteOp {
    completed: CompletedReply,
}

fn transfer_session_lost_reply(operation_id: &str) -> Value {
    json!({
        "operation_contract": OPERATION_CONTRACT_V1,
        "operation_id": operation_id,
        "status": "failed",
        "error": {
            "code": "OWNMESH_E_TRANSFER_SESSION_LOST",
            "message": "transfer session was interrupted; obtain fresh preflight and ticket",
            "retryable": true
        }
    })
}

fn operation_expired_reply(operation_id: &ownmesh_domain::OperationId) -> Value {
    json!({
        "operation_contract": OPERATION_CONTRACT_V1,
        "operation_id": operation_id,
        "status": "failed",
        "error": {
            "code": "OWNMESH_E_OPERATION_EXPIRED",
            "message": "operation request expired before device execution",
            "retryable": false
        }
    })
}

fn dispatch_outcome_unknown_reply(operation_id: &ownmesh_domain::OperationId) -> Value {
    json!({
        "operation_contract": OPERATION_CONTRACT_V1,
        "operation_id": operation_id,
        "status": "failed",
        "error": {
            "code": "OWNMESH_E_DISPATCH_OUTCOME_UNKNOWN",
            "message": "legacy dispatch outcome is unknown; the operation was not replayed",
            "retryable": false,
            "details": { "category": "dispatch_outcome_unknown" }
        }
    })
}

/// Commit the terminal receipt and remove its pending dispatch in one durable
/// state write before attempting the network send. A failed send is therefore
/// replayable after reconnect and can never resurrect the accepted request.
async fn persist_and_send_completed(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    completed: CompletedReply,
) -> Result<(), String> {
    state.remember_completed(completed.clone());
    state.save(&config.state_path)?;
    send_cached_result(socket, config, state, &completed).await
}

async fn live_loop(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    runtime: Option<&Arc<Mutex<DaemonRuntime>>>,
    state: &mut AgentTransportState,
    shutdown: &mut watch::Receiver<bool>,
) -> Result<(), String> {
    let mut heartbeat = tokio::time::interval(DEFAULT_HEARTBEAT);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    heartbeat.tick().await;
    let mut last_receive = Instant::now();
    let cancel_registry = Arc::new(CancelRegistry::default());
    // Bounded queue + semaphore: slow WSS consumers must not grow RSS without limit.
    let (finish_tx, mut finish_rx) = mpsc::channel::<FinishedRemoteOp>(MAX_COMPLETION_QUEUE);
    let in_flight = Arc::new(Semaphore::new(MAX_IN_FLIGHT_REMOTE_OPS));
    let active_dispatches = Arc::new(Mutex::new(HashSet::<String>::new()));

    // Crash resume: redispatch any accepted-but-incomplete operation.request entries
    // from the durable outbox. Runtime idempotency keys prevent duplicate side effects.
    let pending_resume: Vec<PendingDispatch> = state.pending_dispatches.iter().cloned().collect();
    for pending in pending_resume {
        if state.completed(&pending.correlation_id).is_some() {
            state.clear_pending_by_correlation(&pending.correlation_id);
            continue;
        }
        if pending.transfer_session_lost {
            let completed = CompletedReply {
                correlation_id: pending.correlation_id.clone(),
                operation_id: pending.operation_id.clone(),
                payload: transfer_session_lost_reply(&pending.operation_id),
            };
            state.remember_completed(completed.clone());
            state.save(&config.state_path)?;
            send_cached_result(socket, config, state, &completed).await?;
            continue;
        }
        let Ok(envelope) = Envelope::parse_str(&pending.raw) else {
            // Corrupt outbox entry: fail closed with a terminal receipt.
            let payload = json!({
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": pending.operation_id,
                "status": "failed",
                "error": {
                    "code": "OWNMESH_E_DISPATCH_LOST",
                    "message": "pending dispatch envelope is corrupt and cannot be resumed",
                    "retryable": false
                }
            });
            let completed = CompletedReply {
                correlation_id: pending.correlation_id.clone(),
                operation_id: pending.operation_id.clone(),
                payload,
            };
            state.remember_completed(completed.clone());
            state.save(&config.state_path)?;
            send_cached_result(socket, config, state, &completed).await?;
            continue;
        };
        handle_live_frame(
            socket,
            config,
            runtime,
            state,
            InboundFrame::New {
                raw: pending.raw.clone(),
                envelope,
            },
            &cancel_registry,
            &finish_tx,
            &in_flight,
            &active_dispatches,
        )
        .await?;
    }
    state.save(&config.state_path)?;

    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    let _ = socket.send(Message::Close(None)).await;
                    return Ok(());
                }
            }
            _ = heartbeat.tick() => {
                if last_receive.elapsed() > DEFAULT_HEARTBEAT.saturating_mul(3) {
                    return Err("Agent heartbeat timed out".into());
                }
                send_envelope(
                    socket,
                    config,
                    state,
                    "ping",
                    json!({ "agent_time": Timestamp::now() }),
                    None,
                ).await?;
            }
            Some(finished) = finish_rx.recv() => {
                // Durable completion before network send (same as sync path).
                // remember_completed also clears the crash-outbox entry.
                state.remember_completed(finished.completed.clone());
                state.save(&config.state_path)?;
                send_cached_result(socket, config, state, &finished.completed).await?;
            }
            message = socket.next() => {
                let message = message
                    .ok_or_else(|| "WebSocket stream ended".to_owned())?
                    .map_err(|error| format!("WebSocket receive failed: {error}"))?;
                last_receive = Instant::now();
                if let Some(frame) = handle_wire_message(socket, config, state, message).await? {
                    handle_live_frame(
                        socket,
                        config,
                        runtime,
                        state,
                        frame,
                        &cancel_registry,
                        &finish_tx,
                        &in_flight,
                        &active_dispatches,
                    ).await?;
                }
            }
        }
    }
}

async fn receive_frame(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
) -> Result<InboundFrame, String> {
    loop {
        let message = socket
            .next()
            .await
            .ok_or_else(|| "WebSocket stream ended".to_owned())?
            .map_err(|error| format!("WebSocket receive failed: {error}"))?;
        if let Some(frame) = handle_wire_message(socket, config, state, message).await? {
            return Ok(frame);
        }
    }
}

async fn handle_wire_message(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    message: Message,
) -> Result<Option<InboundFrame>, String> {
    match message {
        Message::Text(text) => parse_and_record_inbound(text.as_str(), config, state).map(Some),
        Message::Ping(payload) => {
            socket
                .send(Message::Pong(payload))
                .await
                .map_err(|error| format!("send WebSocket pong: {error}"))?;
            Ok(None)
        }
        Message::Pong(_) | Message::Frame(_) => Ok(None),
        Message::Close(frame) => {
            let detail = frame
                .as_ref()
                .map(|f| format!("code={} reason={}", f.code, f.reason))
                .unwrap_or_else(|| "no close frame".into());
            Err(format!("control plane closed the WebSocket ({detail})"))
        }
        Message::Binary(_) => Err("binary WebSocket messages are unsupported".into()),
    }
}

fn parse_and_record_inbound(
    raw: &str,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
) -> Result<InboundFrame, String> {
    let original: Value = serde_json::from_str(raw)
        .map_err(|error| format!("invalid control-plane envelope JSON: {error}"))?;
    let object = original
        .as_object()
        .ok_or_else(|| "control-plane envelope must be an object".to_owned())?;
    const ALLOWED_KEYS: &[&str] = &[
        "protocol",
        "message_id",
        "type",
        "device_id",
        "correlation_id",
        "seq",
        "sent_at",
        "expires_at",
        "payload",
    ];
    if let Some(unknown) = object
        .keys()
        .find(|key| !ALLOWED_KEYS.contains(&key.as_str()))
    {
        return Err(format!(
            "control-plane envelope contains unknown field '{unknown}'"
        ));
    }
    if object.get("expires_at").is_some_and(Value::is_null) {
        return Err("control-plane envelope expires_at must not be null".into());
    }
    let envelope = Envelope::parse_str(raw).map_err(|error| error.to_string())?;
    if envelope.device_id != config.device_id {
        return Err("control-plane envelope device_id mismatch".into());
    }
    if envelope.seq > MAX_SAFE_JSON_INTEGER {
        return Err("control-plane envelope seq exceeds JSON safe-integer range".into());
    }
    let message_id = envelope.message_id.as_str();
    if state.has_seen_message(message_id) {
        return Ok(InboundFrame::Duplicate(envelope));
    }
    if envelope.seq <= state.last_server_seq {
        return Err(format!(
            "control-plane envelope seq {} did not advance past {}",
            envelope.seq, state.last_server_seq
        ));
    }
    state.last_server_seq = envelope.seq;
    state.remember_message(message_id.to_owned());
    // Crash outbox: persist the immutable operation.request envelope BEFORE the
    // seen-ack is durable so a daemon crash cannot strand D1 in pending forever.
    if envelope.message_type == "operation.request" {
        let correlation_id = envelope
            .correlation_id
            .clone()
            .unwrap_or_else(|| message_id.to_owned());
        let operation_id = envelope
            .payload
            .get("operation_id")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();
        // Skip outbox when a terminal result already exists (replay after complete).
        if state.completed(&correlation_id).is_none() {
            let transfer_session_lost = envelope.payload.get("capability").and_then(Value::as_str)
                == Some("transfer.start");
            state.remember_pending(PendingDispatch {
                message_id: message_id.to_owned(),
                correlation_id,
                operation_id,
                raw: if transfer_session_lost {
                    String::new()
                } else {
                    raw.to_owned()
                },
                accepted_at: Timestamp::now().to_rfc3339(),
                transfer_session_lost,
                expires_at: envelope.expires_at.as_ref().map(ToString::to_string),
                dispatch_started: Some(false),
            })?;
        }
    }
    state.save(&config.state_path)?;
    Ok(InboundFrame::New {
        raw: raw.to_owned(),
        envelope,
    })
}

async fn handle_live_frame(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    runtime: Option<&Arc<Mutex<DaemonRuntime>>>,
    state: &mut AgentTransportState,
    frame: InboundFrame,
    cancel_registry: &Arc<CancelRegistry>,
    finish_tx: &mpsc::Sender<FinishedRemoteOp>,
    in_flight: &Arc<Semaphore>,
    active_dispatches: &Arc<Mutex<HashSet<String>>>,
) -> Result<(), String> {
    let (raw, envelope) = match frame {
        InboundFrame::New { raw, envelope } => (Some(raw), envelope),
        InboundFrame::Duplicate(envelope) => (None, envelope),
    };
    match envelope.message_type.as_str() {
        "pong" => Ok(()),
        "ping" => {
            send_envelope(
                socket,
                config,
                state,
                "pong",
                json!({ "agent_time": Timestamp::now() }),
                envelope.correlation_id.as_deref(),
            )
            .await
        }
        "operation.request" => {
            let correlation = envelope
                .correlation_id
                .as_deref()
                .ok_or_else(|| "operation.request requires correlation_id".to_owned())?;
            if let Some(completed) = state.completed(correlation).cloned() {
                return send_cached_result(socket, config, state, &completed).await;
            }
            // Duplicate / crash-resume: recover the immutable envelope from the outbox.
            let raw = match raw {
                Some(raw) => raw,
                None => match state.pending_by_correlation(correlation) {
                    Some(pending) if pending.transfer_session_lost => {
                        let completed = CompletedReply {
                            correlation_id: correlation.to_owned(),
                            operation_id: pending.operation_id.clone(),
                            payload: transfer_session_lost_reply(&pending.operation_id),
                        };
                        state.remember_completed(completed.clone());
                        state.save(&config.state_path)?;
                        return send_cached_result(socket, config, state, &completed).await;
                    }
                    Some(pending) => pending.raw.clone(),
                    None => {
                        // Seen without pending or completion: fail closed so D1 cannot
                        // remain pending forever after an outbox eviction/corruption.
                        let operation_id = envelope
                            .payload
                            .get("operation_id")
                            .and_then(Value::as_str)
                            .unwrap_or(correlation)
                            .to_owned();
                        let payload = json!({
                            "operation_contract": OPERATION_CONTRACT_V1,
                            "operation_id": operation_id,
                            "status": "failed",
                            "error": {
                                "code": "OWNMESH_E_DISPATCH_LOST",
                                "message": "operation was accepted but the durable dispatch outbox entry is gone; retry with a new operation id",
                                "retryable": false
                            }
                        });
                        let completed = CompletedReply {
                            correlation_id: correlation.to_owned(),
                            operation_id,
                            payload,
                        };
                        state.remember_completed(completed.clone());
                        state.save(&config.state_path)?;
                        return send_cached_result(socket, config, state, &completed).await;
                    }
                },
            };
            let operation =
                OperationEnvelope::parse_str(&raw).map_err(|error| error.to_string())?;
            let OperationPayload::Request(request) = operation.payload else {
                return Err("operation.request parsed as a different payload type".into());
            };
            if let Err(error) = operation.envelope.validate_expiry_now() {
                if error.code != ErrorCode::Expired {
                    return Err(error.to_string());
                }
                let dispatch_started = state
                    .pending_by_correlation(correlation)
                    .and_then(|pending| pending.dispatch_started);
                match dispatch_started {
                    Some(false) => {
                        let completed = CompletedReply {
                            correlation_id: correlation.to_owned(),
                            operation_id: request.operation_id.to_string(),
                            payload: operation_expired_reply(&request.operation_id),
                        };
                        return persist_and_send_completed(socket, config, state, completed).await;
                    }
                    Some(true) => {
                        // A prior process may have crossed the side-effect
                        // boundary. Re-enter the runtime idempotency path to
                        // recover its result; never replace it with "expired".
                        tracing::warn!(
                            operation_id = %request.operation_id,
                            "reconciling an expired operation whose dispatch had started"
                        );
                    }
                    None => {
                        // Pre-marker state cannot distinguish "accepted" from
                        // "side effect completed before crash". Refuse both a
                        // blind replay and a fabricated expiry outcome.
                        let completed = CompletedReply {
                            correlation_id: correlation.to_owned(),
                            operation_id: request.operation_id.to_string(),
                            payload: dispatch_outcome_unknown_reply(&request.operation_id),
                        };
                        return persist_and_send_completed(socket, config, state, completed).await;
                    }
                }
            }

            // Cancel must run on the live loop so it can signal an in-flight op
            // without waiting for that op's runtime lock. Exact-action binding is
            // still mandatory: unsigned/expired/mismatched cancels must not signal.
            let action = action_of(&request);
            if request.capability == "operation.cancel"
                || action == "cancel"
                || action == "ownmesh_cancel_operation"
            {
                let envelope_expires_at = operation
                    .envelope
                    .expires_at
                    .as_ref()
                    .map(|exp| exp.at.to_rfc3339());
                if let Err(message) = verify_exact_action_binding(
                    &config.device_id,
                    &request,
                    envelope_expires_at.as_deref(),
                ) {
                    let payload = json!({
                        "operation_contract": OPERATION_CONTRACT_V1,
                        "operation_id": request.operation_id.to_string(),
                        "status": "failed",
                        "error": {
                            "code": "OWNMESH_E_ACTION_BINDING_MISMATCH",
                            "message": message,
                            "retryable": false
                        }
                    });
                    let completed = CompletedReply {
                        correlation_id: correlation.to_owned(),
                        operation_id: request.operation_id.to_string(),
                        payload,
                    };
                    state.remember_completed(completed.clone());
                    state.save(&config.state_path)?;
                    return send_cached_result(socket, config, state, &completed).await;
                }
                state.mark_dispatch_started(correlation)?;
                state.save(&config.state_path)?;
                let target = request
                    .arguments
                    .get("target_operation_id")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let signalled = if target.is_empty() {
                    false
                } else {
                    cancel_registry.cancel(&target).await
                };
                let payload = json!({
                    "operation_contract": OPERATION_CONTRACT_V1,
                    "operation_id": request.operation_id.to_string(),
                    "status": "completed",
                    "result": {
                        "cancelled": signalled,
                        "target_operation_id": target,
                        "signal_delivered": signalled,
                        "note": if signalled {
                            "cancel delivered to in-flight process tree"
                        } else {
                            "no matching in-flight operation; target may have already finished"
                        }
                    }
                });
                let completed = CompletedReply {
                    correlation_id: correlation.to_owned(),
                    operation_id: request.operation_id.to_string(),
                    payload,
                };
                state.remember_completed(completed.clone());
                state.save(&config.state_path)?;
                return send_cached_result(socket, config, state, &completed).await;
            }

            let Some(runtime) = runtime.map(Arc::clone) else {
                let payload = unsupported_surface_payload(&request.operation_id);
                let completed = CompletedReply {
                    correlation_id: correlation.to_owned(),
                    operation_id: request.operation_id.to_string(),
                    payload,
                };
                state.remember_completed(completed.clone());
                state.save(&config.state_path)?;
                return send_cached_result(socket, config, state, &completed).await;
            };

            // Fail closed under backpressure rather than enqueueing unbounded work.
            // try_acquire avoids blocking the live loop (which would deadlock finish_rx).
            let permit = match Arc::clone(in_flight).try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let payload = agent_backpressure_payload(&request.operation_id);
                    let completed = CompletedReply {
                        correlation_id: correlation.to_owned(),
                        operation_id: request.operation_id.to_string(),
                        payload,
                    };
                    state.remember_completed(completed.clone());
                    state.save(&config.state_path)?;
                    return send_cached_result(socket, config, state, &completed).await;
                }
            };

            // In-process exact-once: do not start a second side effect while one runs
            // (Duplicate redelivery or crash-outbox resume during the same session).
            {
                let mut active = active_dispatches.lock().await;
                if !active.insert(correlation.to_owned()) {
                    return Ok(());
                }
            }

            // Persist the side-effect boundary before the task can run. If the
            // process dies after this write, reconnect must use the runtime's
            // idempotency journal even when the original envelope has expired.
            state.mark_dispatch_started(correlation)?;
            state.save(&config.state_path)?;

            // Register cancel before spawn so a concurrent cancel cannot miss the
            // window between accept and dispatch start.
            let operation_id = request.operation_id.to_string();
            let cancel_rx = cancel_registry.register(&operation_id).await;
            let correlation_owned = correlation.to_owned();
            let cancel_registry = Arc::clone(cancel_registry);
            let finish_tx = finish_tx.clone();
            let active_dispatches = Arc::clone(active_dispatches);
            let device_id = config.device_id.clone();
            let device_key = Arc::clone(&config.key);
            let preflight_ephemerals = Arc::clone(&config.preflight_ephemerals);
            // Transfer sessions outlive the control-socket dispatch turn.  They
            // own a cloned, non-persisted connection configuration so no
            // network wait ever holds the daemon runtime mutex.
            let transfer_config = config.clone();
            let envelope_expires_at = operation
                .envelope
                .expires_at
                .as_ref()
                .map(|exp| exp.at.to_rfc3339());
            tokio::spawn(async move {
                let _permit: OwnedSemaphorePermit = permit;
                let payload = dispatch_remote_operation(
                    &runtime,
                    &device_id,
                    &device_key,
                    &preflight_ephemerals,
                    &transfer_config,
                    &request,
                    envelope_expires_at.as_deref(),
                    &cancel_registry,
                    Some(cancel_rx),
                )
                .await;
                cancel_registry.forget(&operation_id).await;
                let completed = CompletedReply {
                    correlation_id: correlation_owned.clone(),
                    operation_id,
                    payload,
                };
                // Backpressure: wait for the live loop to drain rather than drop
                // or grow an unbounded queue while the WebSocket consumer is slow.
                let _ = finish_tx.send(FinishedRemoteOp { completed }).await;
                let mut active = active_dispatches.lock().await;
                active.remove(&correlation_owned);
            });
            Ok(())
        }
        "error" => {
            let code = envelope
                .payload
                .get("code")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            let message = envelope
                .payload
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("");
            // Result CAS rejects are operation-scoped; keep the Agent socket alive so
            // subsequent work (and reconnect recovery) is not denied by one reject.
            if code == "OWNMESH_E_RESULT_REJECTED" {
                tracing::warn!(
                    code,
                    message,
                    correlation_id = envelope.correlation_id.as_deref().unwrap_or(""),
                    "control plane rejected an operation result; continuing Agent session"
                );
                return Ok(());
            }
            Err(format!(
                "control plane returned an Agent protocol error ({code}): {message}"
            ))
        }
        other => Err(format!("unsupported control-plane message type '{other}'")),
    }
}

fn unsupported_surface_payload(operation_id: &ownmesh_domain::OperationId) -> Value {
    json!({
        "operation_contract": OPERATION_CONTRACT_V1,
        "operation_id": operation_id,
        "status": "failed",
        "error": {
            "code": "OWNMESH_E_UNSUPPORTED_SURFACE",
            "message": "remote operation routing is unavailable without a local runtime handle",
            "retryable": false
        }
    })
}

fn agent_backpressure_payload(operation_id: &ownmesh_domain::OperationId) -> Value {
    json!({
        "operation_contract": OPERATION_CONTRACT_V1,
        "operation_id": operation_id,
        "status": "failed",
        "error": {
            "code": "OWNMESH_E_AGENT_BACKPRESSURE",
            "message": format!(
                "agent in-flight remote operation limit reached ({MAX_IN_FLIGHT_REMOTE_OPS}); retry after drain"
            ),
            "retryable": true,
            "details": {
                "max_in_flight": MAX_IN_FLIGHT_REMOTE_OPS,
                "max_completion_queue": MAX_COMPLETION_QUEUE
            }
        }
    })
}

/// Stable JSON encoding matching control-plane `stableStringify` (sorted object keys).
fn stable_stringify(value: &Value) -> String {
    match value {
        Value::Null => "null".to_owned(),
        Value::Bool(v) => {
            if *v {
                "true".to_owned()
            } else {
                "false".to_owned()
            }
        }
        Value::Number(n) => n.to_string(),
        Value::String(s) => serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_owned()),
        Value::Array(items) => {
            let mut out = String::from("[");
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&stable_stringify(item));
            }
            out.push(']');
            out
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut out = String::from("{");
            let mut first = true;
            for key in keys {
                let Some(v) = map.get(key) else {
                    continue;
                };
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_owned()));
                out.push(':');
                out.push_str(&stable_stringify(v));
            }
            out.push('}');
            out
        }
    }
}

fn sha256_hex_str(input: &str) -> String {
    use sha2::{Digest, Sha256};
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(input.as_bytes());
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn recompute_action_facts(arguments: &Map<String, Value>) -> Result<Map<String, Value>, String> {
    let mut facts = Map::new();
    for (key, value) in arguments {
        if matches!(
            key.as_str(),
            "action"
                | "device_id"
                | "async"
                | "tool"
                | "operation_id"
                | "_client_hints"
                | "force_allow"
                | "bypass_policy"
                | "skip_approval"
                | "allow"
                | "approved"
                | "intent_summary"
                | "risk_note"
                | "principal"
                | "principal_id"
                | "tenant_id"
                | "policy_result"
                | "payload_hash"
                | "risk_level"
                // "decision" is intentionally NOT skipped: approval.decision binds it.
                | "idempotency_key"
                | "workspace_id"
        ) {
            continue;
        }
        if key == "content" {
            if let Some(text) = value.as_str() {
                facts.insert("content_sha256".into(), Value::String(sha256_hex_str(text)));
                facts.insert(
                    "content_bytes".into(),
                    Value::Number(serde_json::Number::from(text.len() as u64)),
                );
                continue;
            }
        }
        if key == "env" {
            facts.insert("env".into(), normalize_env_fact(value)?);
            continue;
        }
        facts.insert(key.clone(), value.clone());
    }
    Ok(facts)
}

/// Bound + order-stable environment fact used in exact-action binding.
fn normalize_env_fact(value: &Value) -> Result<Value, String> {
    const MAX_ENV_ENTRIES: usize = 32;
    const MAX_ENV_KEY_BYTES: usize = 128;
    const MAX_ENV_VALUE_BYTES: usize = 4_096;
    const MAX_ENV_TOTAL_BYTES: usize = 16_384;
    let Some(obj) = value.as_object() else {
        return Err("env must be an object of string values".into());
    };
    if obj.len() > MAX_ENV_ENTRIES {
        return Err(format!("env exceeds {MAX_ENV_ENTRIES} entries"));
    }
    let mut keys: Vec<&String> = obj.keys().collect();
    keys.sort();
    let mut out = Map::new();
    let mut total = 0usize;
    for key in keys {
        if key.is_empty()
            || key.len() > MAX_ENV_KEY_BYTES
            || key.contains('\0')
            || key.contains('=')
        {
            return Err("env key is empty, too long, or contains NUL/=".into());
        }
        let Some(raw) = obj.get(key).and_then(Value::as_str) else {
            return Err("env values must be strings".into());
        };
        if raw.len() > MAX_ENV_VALUE_BYTES || raw.contains('\0') {
            return Err("env value is too long or contains NUL".into());
        }
        total = total.saturating_add(key.len()).saturating_add(raw.len());
        if total > MAX_ENV_TOTAL_BYTES {
            return Err(format!("env exceeds {MAX_ENV_TOTAL_BYTES} total bytes"));
        }
        out.insert(key.clone(), Value::String(raw.to_owned()));
    }
    Ok(Value::Object(out))
}

/// Verify control-plane exact-action binding immediately before side effects.
///
/// Integrity model: the Agent hop is authenticated to the control plane. The
/// binding object must hash to `payload_hash` and must agree with the request
/// envelope/arguments so a substituted body cannot execute under a stale hash.
fn verify_exact_action_binding(
    device_id: &DeviceId,
    request: &OperationRequestPayload,
    envelope_expires_at: Option<&str>,
) -> Result<(), String> {
    let Some(authorization) = request.authorization.as_ref() else {
        // Cancel and approval.decision are live control-plane actions: binding is
        // mandatory so an unauthenticated/unsigned frame cannot approve or signal.
        return Err(
            "remote side-effect operations require authorization.bound_action and payload_hash"
                .into(),
        );
    };
    let Some(payload_hash) = request.payload_hash.as_deref() else {
        return Err("authorization binding requires payload_hash".into());
    };
    let bound = &authorization.bound_action;
    let Some(bound_obj) = bound.as_object() else {
        return Err("authorization.bound_action must be an object".into());
    };

    let recomputed = sha256_hex_str(&stable_stringify(bound));
    if !recomputed.eq_ignore_ascii_case(payload_hash) {
        return Err("payload_hash does not match authorization.bound_action".into());
    }

    let bound_op = bound_obj
        .get("operation_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if bound_op != request.operation_id.as_str() {
        return Err("bound operation_id mismatch".into());
    }
    let bound_device = bound_obj
        .get("device_id")
        .and_then(Value::as_str)
        .unwrap_or("");
    if bound_device != device_id.as_str() {
        return Err("bound device_id mismatch".into());
    }
    let bound_cap = bound_obj
        .get("capability")
        .and_then(Value::as_str)
        .unwrap_or("");
    if bound_cap != request.capability {
        return Err("bound capability mismatch".into());
    }
    let action = action_of(request);
    let bound_action = bound_obj
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !action.is_empty() && bound_action != action {
        return Err("bound action mismatch".into());
    }
    let bound_expires = bound_obj
        .get("expires_at")
        .and_then(Value::as_str)
        .unwrap_or("");
    if let Some(env_exp) = envelope_expires_at {
        // Normalize via Timestamp parse so `.000Z` vs `Z` and equivalent RFC3339
        // forms from JS/Rust do not false-reject an otherwise valid binding.
        let bound_ts = ownmesh_domain::Timestamp::parse(bound_expires)
            .map_err(|_| "bound expires_at is not a valid timestamp".to_owned())?;
        let env_ts = ownmesh_domain::Timestamp::parse(env_exp)
            .map_err(|_| "envelope expires_at is not a valid timestamp".to_owned())?;
        if bound_ts != env_ts {
            return Err("bound expires_at does not match envelope expires_at".into());
        }
    } else if !bound_expires.is_empty() {
        return Err("envelope missing expires_at required by binding".into());
    }

    let bound_workspace = bound_obj
        .get("workspace_id")
        .cloned()
        .unwrap_or(Value::Null);
    let request_workspace = request
        .workspace_id
        .as_ref()
        .map(|w| Value::String(w.as_str().to_owned()))
        .unwrap_or(Value::Null);
    if bound_workspace != request_workspace {
        return Err("bound workspace_id mismatch".into());
    }
    let bound_workspace_version = bound_obj
        .get("workspace_version")
        .cloned()
        .unwrap_or(Value::Null);
    if request.workspace_id.is_some()
        && bound_workspace_version
            .as_u64()
            .is_none_or(|version| version == 0)
    {
        return Err("bound workspace_version is required for a workspace-bound request".into());
    }
    if request.workspace_id.is_none() && !bound_workspace_version.is_null() {
        return Err("unbound request cannot claim a workspace_version".into());
    }

    // Recompute action facts from the live arguments and require exact match.
    let mut args = args_object(request);
    if request.capability == "transfer.start" {
        // The opaque bearer is intentionally absent from bound/audited facts.
        // Fail closed on its wire shape here, then remove only this field for
        // exact-facts comparison. The signed ticket and every embedded plan,
        // role, device, workspace, epoch and fence are independently checked
        // twice below before the Room socket or ephemeral private key is used.
        let ticket = args
            .get("ticket")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty() && value.len() <= MAX_TRANSFER_TICKET_WIRE_BYTES)
            .ok_or("transfer.start requires a bounded string ticket")?;
        let _ = ticket;
        args.remove("ticket");
    }
    let live_facts = recompute_action_facts(&args)?;
    let bound_facts = bound_obj
        .get("facts")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    if live_facts != bound_facts {
        return Err("bound action facts do not match request arguments".into());
    }

    // Principal/tenant/oauth/claim must be present on the bound object (server-set).
    for required in ["principal_id", "tenant_id", "claim_version", "tool"] {
        if !bound_obj.contains_key(required) {
            return Err(format!("bound_action missing required field '{required}'"));
        }
    }
    Ok(())
}

/// Derive the runtime principal from the already-verified bound_action.
///
/// Format: `client:remote:<tenant_id>:<principal_id>`. Never trust client-supplied
/// principal fields from free-form arguments — only the server-hashed binding.
fn remote_agent_client_from_bound(
    request: &OperationRequestPayload,
) -> Result<ClientIdentity, String> {
    let bound = request
        .authorization
        .as_ref()
        .and_then(|a| a.bound_action.as_object())
        .ok_or_else(|| {
            "remote principal requires verified authorization.bound_action".to_owned()
        })?;
    let principal_id = bound
        .get("principal_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "bound_action.principal_id missing".to_owned())?;
    let tenant_id = bound
        .get("tenant_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "bound_action.tenant_id missing".to_owned())?;
    if principal_id.len() > 128 || tenant_id.len() > 128 {
        return Err("bound principal_id/tenant_id exceed 128-char budget".into());
    }
    if principal_id
        .chars()
        .any(|c| c.is_control() || c == ':' || c == '/' || c == '\\')
        || tenant_id
            .chars()
            .any(|c| c.is_control() || c == ':' || c == '/' || c == '\\')
    {
        return Err("bound principal_id/tenant_id contain invalid characters".into());
    }
    // Lowercase via canonicalize path on the runtime side; keep the label stable here.
    let key = format!(
        "client:remote:{}:{}",
        tenant_id.to_ascii_lowercase(),
        principal_id.to_ascii_lowercase()
    );
    Ok(ClientIdentity::new(key, env!("CARGO_PKG_VERSION")))
}

/// Read the control-plane credential generation from the already hashed
/// `bound_action`.  The field is optional for ordinary operations while the
/// control plane is upgraded, but an elevated broker handoff requires it and
/// rejects a missing value rather than inventing a surrogate from claim data.
fn remote_principal_credential_generation_from_bound(
    request: &OperationRequestPayload,
) -> Result<Option<u64>, String> {
    let bound = request
        .authorization
        .as_ref()
        .and_then(|authorization| authorization.bound_action.as_object())
        .ok_or_else(|| "remote credential generation requires verified bound_action".to_owned())?;
    let Some(value) = bound.get("principal_credential_generation") else {
        return Ok(None);
    };
    value
        .as_u64()
        .filter(|generation| *generation > 0)
        .map(Some)
        .ok_or_else(|| {
            "bound principal_credential_generation must be a positive integer".to_owned()
        })
}

fn action_of(request: &OperationRequestPayload) -> String {
    request
        .arguments
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

fn args_object(request: &OperationRequestPayload) -> Map<String, Value> {
    request.arguments.as_object().cloned().unwrap_or_default()
}

fn strip_control_fields(args: &mut Map<String, Value>) {
    for key in [
        "action",
        "device_id",
        "async",
        "tool",
        "operation_id",
        "_client_hints",
        "force_allow",
        "bypass_policy",
        "skip_approval",
        "allow",
        "approved",
        "intent_summary",
        "risk_note",
        "principal",
        "principal_id",
        "tenant_id",
        "policy_result",
        "payload_hash",
        "risk_level",
    ] {
        args.remove(key);
    }
}

fn map_request_to_method(
    request: &OperationRequestPayload,
) -> Result<(&'static str, Value), String> {
    let action = action_of(request);
    let mut args = args_object(request);
    bind_envelope_workspace(request, &mut args)?;
    require_workspace_binding_for_remote_action(request, &action, &args)?;
    // Only private exact-bound transfer operations receive server-derived peer
    // facts. `transfer.start` needs the complete signed plan so its local
    // runtime can reconstruct exactly what the Room ticket authorizes; it is
    // admitted here only after `verify_exact_action_binding` has authenticated
    // the whole action. Public transfer calls remain unable to inject them.
    let internal_preflight = matches!(
        request.capability.as_str(),
        "transfer.preflight_source" | "transfer.preflight_destination"
    );
    let internal_start = request.capability == "transfer.start"
        && request
            .authorization
            .as_ref()
            .is_some_and(|authorization| authorization.bound_action.is_object());
    if (request.capability.starts_with("transfer.") || action.starts_with("transfer."))
        && !internal_preflight
        && !internal_start
    {
        for forbidden in [
            "tenant_id",
            "principal_id",
            "source_principal_id",
            "destination_principal_id",
            "source_device_id",
            "destination_device_id",
            "payload_hash",
            "grant_id",
            "expires_at",
            "consent",
            "approved",
            "allow",
            "relay",
            "relay_url",
            "overwrite",
            "force",
        ] {
            if args.contains_key(forbidden) {
                return Err(format!(
                    "transfer parameter '{forbidden}' is server-derived or unsupported"
                ));
            }
        }
    }
    strip_control_fields(&mut args);

    // Cancel targets another operation; it does not re-run a side effect.
    if request.capability == "operation.cancel"
        || ((action == "cancel" || action == "ownmesh_cancel_operation")
            && request.capability != "transfer.cancel")
    {
        return Ok(("__cancel__", Value::Object(args)));
    }

    // Optional recovery/admin approval decision notification from the control plane.
    // Local policy remains authoritative; this is not a ChatGPT attestation.
    if request.capability == "approval.decision" || action == "approval.decision" {
        return Ok(("__approval_decision__", Value::Object(args)));
    }

    let capability = request.capability.as_str();
    let method = match (capability, action.as_str()) {
        ("admin.policy.preset", "admin.policy.preset") => methods::ADMIN_POLICY_PRESET_REQUEST,
        ("admin.policy.rule_add", "admin.policy.rule_add") => {
            if let Some(decision) = args.remove("rule_decision") {
                args.insert("decision".into(), decision);
            }
            methods::ADMIN_POLICY_RULE_ADD_REQUEST
        }
        ("admin.policy.rule_remove", "admin.policy.rule_remove") => {
            methods::ADMIN_POLICY_RULE_REMOVE_REQUEST
        }
        ("admin.daemon.unlock", "admin.daemon.unlock") => methods::ADMIN_DAEMON_UNLOCK_REQUEST,
        ("admin.token.revoke", "admin.token.revoke") => {
            if let Some(principal) = args.remove("target_principal") {
                args.insert("principal".into(), principal);
            }
            methods::ADMIN_TOKEN_REVOKE_REQUEST
        }
        ("admin.approval.bridge", "admin.approval.bridge") => {
            if let Some(decision) = args.remove("requested_decision") {
                args.insert("decision".into(), decision);
            }
            methods::ADMIN_APPROVAL_BRIDGE_REQUEST
        }
        ("policy.show", "policy.show" | "ownmesh_policy_show" | "show") => methods::POLICY_SHOW,
        ("filesystem.read", "fs.list" | "ownmesh_fs_list" | "ownmesh_list_files") => {
            methods::OPS_FS_LIST
        }
        ("filesystem.read", "fs.stat" | "ownmesh_fs_stat") => methods::OPS_FS_STAT,
        ("filesystem.read", "fs.read" | "ownmesh_fs_read" | "ownmesh_read_file") => {
            methods::OPS_FS_READ
        }
        ("filesystem.write", "fs.write" | "ownmesh_fs_write" | "ownmesh_write_file") => {
            methods::OPS_FS_WRITE
        }
        ("filesystem.write", "fs.patch" | "ownmesh_fs_patch") => {
            // Hash-checked whole-file replace or bounded unified-diff apply (E7).
            methods::OPS_FS_WRITE
        }
        ("filesystem.write", "fs.delete" | "ownmesh_fs_delete" | "ownmesh_delete_file")
        | ("filesystem.delete", _) => methods::OPS_FS_DELETE,
        ("command.run", "command.shell" | "ownmesh_command_shell" | "ownmesh_run_shell") => {
            // Raw shell is a distinct action; force kind so policy/classifiers see it.
            args.entry("kind".to_owned())
                .or_insert_with(|| Value::String("raw_shell".into()));
            if !args.contains_key("program") {
                if let Some(command) = args.get("command").cloned() {
                    args.insert("program".into(), command);
                }
            }
            methods::OPS_EXEC
        }
        ("command.run", "command.run" | "ownmesh_command_run" | "ownmesh_run_command" | "") => {
            args.entry("kind".to_owned())
                .or_insert_with(|| Value::String("structured".into()));
            methods::OPS_EXEC
        }
        // Cloud session surface (E5): map to local session IPC methods. ownmeshd
        // owns a live PTY host for kind=pty; write/resize/replay drain real I/O.
        ("session.open" | "session", "session.open" | "ownmesh_session_open" | "open") => {
            // MCP uses program/args; session manager expects command argv.
            if !args.contains_key("command") {
                let mut cmd = Vec::new();
                if let Some(Value::String(program)) = args.get("program") {
                    if !program.is_empty() {
                        cmd.push(Value::String(program.clone()));
                    }
                }
                if let Some(Value::Array(a)) = args.get("args") {
                    cmd.extend(a.iter().cloned());
                }
                if !cmd.is_empty() {
                    args.insert("command".into(), Value::Array(cmd));
                }
            }
            // Attach path: MCP session_id → runtime id.
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::OPEN
        }
        ("session.attach" | "session", "session.attach" | "ownmesh_session_attach" | "attach") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            // Normalize MCP role into a bound semantic field. Observer must never
            // default into a controller claim (exact-action integrity).
            match args.get("role").and_then(|v| v.as_str()).map(str::trim) {
                Some("observer") => {
                    args.insert("read_only".into(), Value::Bool(true));
                }
                Some("controller") => {
                    args.insert("read_only".into(), Value::Bool(false));
                }
                Some(other) if !other.is_empty() => {
                    return Err(format!(
                        "session.attach role must be observer|controller (got '{other}')"
                    ));
                }
                Some(_) | None => {
                    // Accept explicit read_only only when role omitted (legacy IPC).
                    if !args.contains_key("read_only") {
                        return Err("session.attach requires role=observer|controller".into());
                    }
                }
            }
            crate::runtime::session_methods::ATTACH
        }
        ("session.list" | "session", "session.list" | "ownmesh_session_list" | "list") => {
            crate::runtime::session_methods::LIST
        }
        ("session.show" | "session", "session.show" | "ownmesh_session_show" | "show") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::SHOW
        }
        ("session.claim" | "session", "session.claim" | "ownmesh_session_claim" | "claim") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::CLAIM
        }
        ("session.renew" | "session", "session.renew" | "ownmesh_session_renew" | "renew") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::RENEW
        }
        ("session.detach" | "session", "session.detach" | "ownmesh_session_detach" | "detach") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::DETACH
        }
        (
            "session.release" | "session",
            "session.release" | "ownmesh_session_release" | "release",
        ) => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::RELEASE
        }
        ("session.give" | "session", "session.give" | "ownmesh_session_give" | "give") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::GIVE
        }
        (
            "session.write" | "session",
            "session.write" | "ownmesh_session_write" | "write" | "input",
        ) => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::WRITE
        }
        ("session.resize" | "session", "session.resize" | "ownmesh_session_resize" | "resize") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::RESIZE
        }
        ("session.replay" | "session", "session.replay" | "ownmesh_session_replay" | "replay") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::REPLAY
        }
        ("session.close" | "session", "session.close" | "ownmesh_session_close" | "close") => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::CLOSE
        }
        (
            "session.terminate" | "session",
            "session.terminate" | "ownmesh_session_terminate" | "terminate",
        ) => {
            if let Some(sid) = args.get("session_id").cloned() {
                args.entry("id".to_owned()).or_insert(sid);
            }
            crate::runtime::session_methods::TERMINATE
        }
        // Read-only git review surfaces (E7 foundation).
        ("git.status" | "git", "git.status" | "ownmesh_git_status" | "status") => {
            crate::runtime::ops_methods::GIT_STATUS
        }
        ("git.diff" | "git", "git.diff" | "ownmesh_git_diff" | "diff") => {
            crate::runtime::ops_methods::GIT_DIFF
        }
        ("review.start" | "review", "review.start" | "ownmesh_review_start" | "start") => {
            crate::runtime::ops_methods::REVIEW_START
        }
        ("review.show" | "review", "review.show" | "ownmesh_review_show" | "show") => {
            crate::runtime::ops_methods::REVIEW_SHOW
        }
        ("review.page" | "review", "review.page" | "ownmesh_review_page" | "page") => {
            crate::runtime::ops_methods::REVIEW_PAGE
        }
        // Device-local workspace registry CRUD (E4 configuration).
        ("workspace.list" | "workspace", "workspace.list" | "ownmesh_workspace_list" | "list") => {
            crate::runtime::ops_methods::WORKSPACE_LIST
        }
        ("workspace.show" | "workspace", "workspace.show" | "ownmesh_workspace_show" | "show") => {
            crate::runtime::ops_methods::WORKSPACE_SHOW
        }
        ("workspace.add" | "workspace", "workspace.add" | "ownmesh_workspace_add" | "add") => {
            crate::runtime::ops_methods::WORKSPACE_ADD
        }
        (
            "workspace.update" | "workspace",
            "workspace.update" | "ownmesh_workspace_update" | "update",
        ) => crate::runtime::ops_methods::WORKSPACE_UPDATE,
        (
            "workspace.remove" | "workspace",
            "workspace.remove" | "ownmesh_workspace_remove" | "remove",
        ) => crate::runtime::ops_methods::WORKSPACE_REMOVE,
        // E6 official profile detection (local PATH only; no credential exfil).
        (
            "profile.list" | "profile",
            "profile.list" | "ownmesh_list_profiles" | "ownmesh_profile_list" | "list",
        ) => methods::PROFILE_LIST,
        ("profile.scan" | "profile", "profile.scan" | "ownmesh_profile_scan" | "scan") => {
            methods::PROFILE_SCAN
        }
        ("profile.show" | "profile", "profile.show" | "ownmesh_profile_show" | "show") => {
            methods::PROFILE_SHOW
        }
        ("system.diagnose", "system.diagnose" | "ownmesh_system_diagnose" | "diagnose") => {
            crate::runtime::ops_methods::SYSTEM_DIAGNOSE
        }
        // Accept short fixture-style capability names used by the E0 contract samples.
        ("fs.read", _) => methods::OPS_FS_READ,
        ("fs.write", _) => methods::OPS_FS_WRITE,
        ("fs.list", _) => methods::OPS_FS_LIST,
        ("transfer.preflight_source", "transfer.preflight_source" | "preflight_source") => {
            methods::TRANSFER_PREFLIGHT_SOURCE
        }
        (
            "transfer.preflight_destination",
            "transfer.preflight_destination" | "preflight_destination",
        ) => methods::TRANSFER_PREFLIGHT_DESTINATION,
        ("transfer.start", "transfer.start" | "start") => "transfer.start",
        ("transfer.plan", "transfer.plan" | "plan") => methods::TRANSFER_PLAN,
        ("transfer.source_open", "transfer.source_open" | "source_open") => {
            methods::TRANSFER_SOURCE_OPEN
        }
        ("transfer.source_chunk", "transfer.source_chunk" | "source_chunk") => {
            methods::TRANSFER_SOURCE_CHUNK
        }
        (
            "transfer.destination_prepare",
            "transfer.destination_prepare" | "destination_prepare",
        ) => methods::TRANSFER_DESTINATION_PREPARE,
        ("transfer.destination_chunk", "transfer.destination_chunk" | "destination_chunk") => {
            methods::TRANSFER_DESTINATION_CHUNK
        }
        ("transfer.finalize", "transfer.finalize" | "finalize") => methods::TRANSFER_FINALIZE,
        ("transfer.status", "transfer.status" | "status") => methods::TRANSFER_STATUS,
        ("transfer.list", "transfer.list" | "list") => methods::TRANSFER_LIST,
        ("transfer.cancel", "transfer.cancel" | "cancel") => methods::TRANSFER_CANCEL,
        ("transfer.source_cleanup", "transfer.source_cleanup" | "source_cleanup") => {
            methods::TRANSFER_CANCEL
        }
        ("transfer.artifact_get", "transfer.artifact_get" | "artifact_get") => {
            methods::TRANSFER_ARTIFACT_GET
        }
        (other_cap, other_action) => {
            return Err(format!(
                "unsupported remote capability '{other_cap}' action '{other_action}'"
            ));
        }
    };

    // The operation contract key is the sole remote idempotency authority.
    // A different arguments-side key could otherwise retrieve a prior
    // same-principal journal result under a new signed operation.
    if let Some(candidate) = args.get("idempotency_key") {
        if candidate.as_str() != Some(request.idempotency_key.as_str()) {
            return Err("arguments idempotency_key differs from operation contract".into());
        }
    }
    // The private transfer admission methods do not use the generic local
    // side-effect journal and deliberately expose strict, ticket/plan-bound
    // parameter schemas.  Still validate any duplicate arguments-side key
    // above, but do not leak the transport contract field into those schemas.
    if internal_preflight
        || internal_start
        || request.capability == "transfer.artifact_get"
        || request.capability == "transfer.source_cleanup"
    {
        args.remove("idempotency_key");
        if request.capability == "transfer.source_cleanup" {
            args.remove("workspace_id");
        }
    } else {
        args.insert(
            "idempotency_key".into(),
            Value::String(request.idempotency_key.clone()),
        );
    }
    Ok((method, Value::Object(args)))
}

/// Filesystem, Git, and command actions must carry the exact workspace selected
/// by the control plane. An explicit absolute path/cwd compatibility request
/// remains unbound (`workspace_id = null`) and the runtime admits it only in
/// Full Access, never as `ws_default`. The other unbound exception is the
/// read-only system diagnosis itself: it accesses no path and reports the
/// restricted/Full Access boundary as a fixed enum.
fn require_workspace_binding_for_remote_action(
    request: &OperationRequestPayload,
    action: &str,
    args: &Map<String, Value>,
) -> Result<(), String> {
    let workspace_scoped = matches!(
        (request.capability.as_str(), action),
        (
            "filesystem.read",
            "fs.list"
                | "fs.stat"
                | "fs.read"
                | "ownmesh_fs_list"
                | "ownmesh_list_files"
                | "ownmesh_fs_stat"
                | "ownmesh_fs_read"
                | "ownmesh_read_file"
        ) | (
            "filesystem.write",
            "fs.write"
                | "fs.patch"
                | "fs.delete"
                | "ownmesh_fs_write"
                | "ownmesh_write_file"
                | "ownmesh_fs_patch"
                | "ownmesh_fs_delete"
        ) | ("filesystem.delete", _)
            | ("system.diagnose", _)
            | ("fs.read" | "fs.list" | "fs.write", _)
            | ("git.status" | "git.diff" | "git", _)
            | ("command.run", _)
    );
    if !workspace_scoped
        || request.workspace_id.is_some()
        || request.capability == "system.diagnose"
    {
        return Ok(());
    }

    let absolute = match request.capability.as_str() {
        "command.run" => args
            .get("cwd")
            .and_then(Value::as_str)
            .is_some_and(is_absolute_path),
        "git.status" | "git.diff" | "git" | "filesystem.read" | "filesystem.write"
        | "filesystem.delete" | "fs.read" | "fs.list" | "fs.write" => args
            .get("path")
            .and_then(Value::as_str)
            .is_some_and(is_absolute_path),
        _ => false,
    };
    if absolute {
        Ok(())
    } else {
        Err("workspace_id is required for remote filesystem, Git, and command actions".into())
    }
}

fn is_absolute_path(path: &str) -> bool {
    let path = path.trim();
    path.starts_with('/')
        || path.starts_with(r"\\")
        || (path.len() >= 3
            && path.as_bytes()[0].is_ascii_alphabetic()
            && path.as_bytes()[1] == b':'
            && matches!(path.as_bytes()[2], b'/' | b'\\'))
}

/// The envelope workspace is part of the authenticated exact action.  It is
/// deliberately excluded from generic `facts` because it is a top-level
/// routing/ownership boundary, so preserve it separately and never let an
/// arguments-side value nominate a different runtime workspace.
fn bind_envelope_workspace(
    request: &OperationRequestPayload,
    args: &mut Map<String, Value>,
) -> Result<(), String> {
    match request.workspace_id.as_ref() {
        Some(workspace) => {
            let expected = workspace.as_str();
            if expected.trim().is_empty() {
                return Err("envelope workspace_id is empty".into());
            }
            if let Some(candidate) = args.get("workspace_id") {
                if candidate.as_str() != Some(expected) {
                    return Err(
                        "arguments workspace_id differs from verified envelope workspace".into(),
                    );
                }
            }
            args.insert("workspace_id".into(), Value::String(expected.to_owned()));
            Ok(())
        }
        None => {
            if args.contains_key("workspace_id") {
                Err("arguments workspace_id is forbidden when envelope has no workspace".into())
            } else {
                Ok(())
            }
        }
    }
}

fn bind_remote_result_workspace(mut result: Value, request: &OperationRequestPayload) -> Value {
    let scoped = matches!(
        request.capability.as_str(),
        "system.diagnose"
            | "filesystem.read"
            | "filesystem.write"
            | "filesystem.delete"
            | "fs.read"
            | "fs.list"
            | "fs.write"
            | "git.status"
            | "git.diff"
            | "git"
            | "command.run"
    );
    if !scoped {
        return result;
    }
    let workspace = request
        .workspace_id
        .as_ref()
        .map(|id| Value::String(id.as_str().to_owned()))
        .unwrap_or(Value::Null);
    let workspace_version = request
        .authorization
        .as_ref()
        .and_then(|authorization| authorization.bound_action.get("workspace_version"))
        .cloned()
        .unwrap_or(Value::Null);
    if let Some(object) = result.as_object_mut() {
        object.insert("workspace_id".into(), workspace);
        object.insert("workspace_version".into(), workspace_version);
        result
    } else {
        json!({ "workspace_id": workspace, "workspace_version": workspace_version, "value": result })
    }
}

fn bound_result_object(value: Value) -> Value {
    // Keep Agent → DeviceRoom envelopes inside the 1_000_000-byte frame budget.
    // Prefer preserving cursor / integrity facts over a generic stand-in so clients
    // can continue paging without re-running a side effect.
    const MAX_RESULT_JSON_BYTES: usize = 750_000;
    let Ok(serialized) = serde_json::to_vec(&value) else {
        return json!({
            "truncated": true,
            "error": {
                "code": "OWNMESH_E_INTERNAL",
                "message": "failed to serialize operation result",
                "retryable": false
            }
        });
    };
    if serialized.len() <= MAX_RESULT_JSON_BYTES {
        return value;
    }

    let mut preserved = serde_json::Map::new();
    preserved.insert("truncated".into(), json!(true));
    preserved.insert("agent_envelope_truncated".into(), json!(true));
    preserved.insert("returned_bytes".into(), json!(0));
    preserved.insert("total_bytes".into(), json!(serialized.len()));
    preserved.insert(
        "message".into(),
        json!("operation result exceeded the Agent envelope budget; request a smaller range or use pagination — cursors and integrity facts are preserved when known"),
    );
    if let Some(obj) = value.as_object() {
        for key in [
            "path",
            "encoding",
            "offset",
            "bytes",
            "returned_bytes",
            "total_bytes",
            "sha256",
            "next_offset",
            "next_cursor",
            "exit_code",
            "timed_out",
            "duration_ms",
            "replayed",
            "cancelled",
            "signal_delivered",
            "workspace_id",
            "workspace_version",
            "approval_decision_applied",
            "approval_id",
            "local_approval_id",
            "decision",
            "target_operation_id",
            "total_matched",
            "entries_returned",
            "program",
            "command",
            "cwd",
            "status",
            "error",
        ] {
            if let Some(v) = obj.get(key) {
                preserved.insert(key.to_owned(), v.clone());
            }
        }
        if let Some(Value::String(content)) = obj.get("content") {
            let preview: String = content.chars().take(256).collect();
            preserved.insert("content_preview".into(), json!(preview));
        }
        if let Some(Value::String(stdout)) = obj.get("stdout") {
            let preview: String = stdout.chars().take(256).collect();
            preserved.insert("stdout_preview".into(), json!(preview));
        }
        if let Some(Value::String(stderr)) = obj.get("stderr") {
            let preview: String = stderr.chars().take(256).collect();
            preserved.insert("stderr_preview".into(), json!(preview));
        }
        if let Some(Value::Array(entries)) = obj.get("entries") {
            preserved.insert("entries_returned".into(), json!(entries.len()));
        }
    }
    Value::Object(preserved)
}

fn preflight_cache_key(fields: &[&str]) -> String {
    let mut key = String::new();
    for field in fields {
        key.push_str(&field.len().to_string());
        key.push(':');
        key.push_str(field);
        key.push('|');
    }
    key
}

fn preflight_text<'a>(body: &'a Value, name: &str) -> Result<&'a str, String> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or_else(|| format!("transfer preflight result missing {name}"))
}

fn preflight_u64(body: &Value, name: &str) -> Result<u64, String> {
    body.get(name)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("transfer preflight result missing {name}"))
}

/// Convert the local runtime's metadata-only preflight into the exact proof
/// envelope consumed by DeviceRoom. The X25519 private half remains only in
/// this in-memory cache for a subsequent ticket-bound start operation.
async fn signed_transfer_preflight_result(
    body: &Value,
    operation_id: &str,
    device_key: &DeviceKeyPair,
    cache: &Arc<Mutex<HashMap<String, PreflightEphemeral>>>,
) -> Result<Value, String> {
    let role = preflight_text(body, "role")?;
    if !matches!(role, "source" | "destination") {
        return Err("invalid transfer preflight role".into());
    }
    let transfer_id = preflight_text(body, "transfer_id")?;
    let tenant_id = preflight_text(body, "tenant_id")?;
    let principal_id = preflight_text(body, "principal_id")?;
    let device_id = preflight_text(body, "device_id")?;
    let workspace_id = preflight_text(body, "workspace_id")?;
    let plan_sha256 = preflight_text(body, "plan_sha256")?;
    let session_nonce = preflight_text(body, "session_nonce")?;
    let coordinator_request_id = preflight_text(body, "coordinator_request_id")?;
    let epoch = u32::try_from(preflight_u64(body, "epoch")?)
        .map_err(|_| "transfer preflight epoch overflow")?;
    let fence = preflight_u64(body, "fence")?;
    let expires_at = preflight_u64(body, "expires_at")?;
    let workspace_version = preflight_u64(body, "workspace_version")?;
    if epoch == 0 || fence == 0 || workspace_version == 0 || expires_at == 0 {
        return Err("invalid transfer preflight metadata".into());
    }
    let cache_key = preflight_cache_key(&[
        role,
        transfer_id,
        device_id,
        workspace_id,
        plan_sha256,
        session_nonce,
        &epoch.to_string(),
        &fence.to_string(),
        &expires_at.to_string(),
    ]);
    let public = {
        let mut guard = cache.lock().await;
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "clock before unix epoch")?
            .as_millis() as u64;
        guard.retain(|_, entry| entry.expires_at_ms > now_ms);
        if let Some(entry) = guard.get(&cache_key) {
            if entry.role != role
                || entry.transfer_id != transfer_id
                || entry.epoch != epoch
                || entry.fence != fence
                || entry.session_nonce != session_nonce
                || entry.expires_at_ms != expires_at
            {
                return Err("transfer ephemeral cache binding mismatch".into());
            }
            *entry.key.public()
        } else {
            if guard.len() >= 32 {
                return Err("transfer ephemeral cache capacity reached".into());
            }
            let key = TransferEphemeral::generate()?;
            let public = *key.public();
            guard.insert(
                cache_key,
                PreflightEphemeral {
                    role: role.to_owned(),
                    transfer_id: transfer_id.to_owned(),
                    epoch,
                    fence,
                    session_nonce: session_nonce.to_owned(),
                    expires_at_ms: expires_at,
                    key,
                },
            );
            public
        }
    };
    let public_hex = hex_encode(&public);
    let proof = canonical_ephemeral_proof(
        transfer_id,
        tenant_id,
        role,
        device_id,
        workspace_id,
        plan_sha256,
        epoch,
        fence,
        session_nonce,
        &public_hex,
        expires_at,
    )?;
    let signature = hex_encode(device_key.sign(&proof).expose());
    // Source-side plan identity/size/content digest are immutable metadata, not
    // transfer data. They are retained only for the same Agent's later
    // ticket-bound start; no chunk, ciphertext, or key is put on this path.
    let source_plan = if role == "source" {
        let plan_id = preflight_text(body, "plan_id")?;
        let sha256 = preflight_text(body, "sha256")?;
        let size_bytes = preflight_u64(body, "size_bytes")?;
        if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err("invalid source transfer plan digest".into());
        }
        Some(json!({ "plan_id": plan_id, "sha256": sha256, "size_bytes": size_bytes }))
    } else {
        None
    };
    let mut result = json!({
        "transfer_preflight": {
            "role": role,
            "transfer_id": transfer_id,
            "tenant_id": tenant_id,
            "device_id": device_id,
            "workspace_id": workspace_id,
            "plan_sha256": plan_sha256,
            "epoch": epoch,
            "fence": fence,
            "session_nonce": session_nonce,
            "expires_at": expires_at,
            "ephemeral_public_key": public_hex,
            "ephemeral_signature": signature,
        },
        "operation_id": operation_id,
        "coordinator_request_id": coordinator_request_id,
        "principal_id": principal_id,
        "workspace_version": workspace_version,
    });
    if let Some(source_plan) = source_plan {
        result["source_plan"] = source_plan;
    }
    Ok(result)
}

async fn dispatch_remote_operation(
    runtime: &Arc<Mutex<DaemonRuntime>>,
    device_id: &DeviceId,
    device_key: &DeviceKeyPair,
    preflight_ephemerals: &Arc<Mutex<HashMap<String, PreflightEphemeral>>>,
    transfer_config: &AgentTransportConfig,
    request: &OperationRequestPayload,
    envelope_expires_at: Option<&str>,
    cancel_registry: &CancelRegistry,
    cancel_rx: Option<watch::Receiver<bool>>,
) -> Value {
    let operation_id = request.operation_id.to_string();

    // E3: verify server-issued exact-action binding before any policy/side effect.
    // Cancel remains a control path and still verifies when a binding is present.
    if let Err(message) = verify_exact_action_binding(device_id, request, envelope_expires_at) {
        return json!({
            "operation_contract": OPERATION_CONTRACT_V1,
            "operation_id": operation_id,
            "status": "failed",
            "error": {
                "code": "OWNMESH_E_ACTION_BINDING_MISMATCH",
                "message": message,
                "retryable": false
            }
        });
    }

    let mapped = match map_request_to_method(request) {
        Ok(mapped) => mapped,
        Err(message) => {
            return json!({
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": operation_id,
                "status": "failed",
                "error": {
                    "code": "OWNMESH_E_UNSUPPORTED_SURFACE",
                    "message": message,
                    "retryable": false
                }
            });
        }
    };
    let transfer_start_args = (request.capability == "transfer.start").then(|| mapped.1.clone());
    let session_cancel = cancel_rx.clone();

    // Reject a malformed/foreign ticket before policy or runtime admission.
    // The private ephemeral is intentionally consumed only by the actual pump
    // after this admission succeeds, so a malformed retry cannot burn it.
    let transfer_start_ticket = if request.capability == "transfer.start" {
        let ticket = mapped
            .1
            .get("ticket")
            .and_then(Value::as_str)
            .ok_or_else(|| "missing transfer ticket".to_owned())
            .and_then(parse_transfer_ticket_wire);
        match ticket.and_then(|ticket| {
            validate_ticket_for_start(&ticket, request, &mapped.1, device_id)?;
            Ok(ticket)
        }) {
            Ok(ticket) => Some(ticket),
            Err(_) => {
                return json!({ "operation_contract": OPERATION_CONTRACT_V1, "operation_id": operation_id, "status": "failed", "error": { "code": "OWNMESH_E_TRANSFER_TICKET", "message": "invalid transfer ticket", "retryable": false } })
            }
        }
    } else {
        None
    };

    if mapped.0 == "__cancel__" {
        // Cancel is handled on the live loop; this branch is defensive only.
        let target = mapped
            .1
            .get("target_operation_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        let signalled = if target.is_empty() {
            false
        } else {
            cancel_registry.cancel(target).await
        };
        return json!({
            "operation_contract": OPERATION_CONTRACT_V1,
            "operation_id": operation_id,
            "status": "completed",
            "result": {
                "cancelled": signalled,
                "target_operation_id": mapped.1.get("target_operation_id").cloned().unwrap_or(Value::Null),
                "signal_delivered": signalled,
                "note": "cancel delivered via dispatch fallback"
            }
        });
    }

    if mapped.0 == "__approval_decision__" {
        // Recovery/admin path: resolve the deferred device approval and
        // execute/deny exactly once. Binding was already verified above.
        // ChatGPT confirmation is not an OwnMesh attestation; this path runs
        // only after control-plane OAuth+CSRF claim + exact-action binding.
        let decision_target_operation_id = mapped
            .1
            .get("target_operation_id")
            .cloned()
            .unwrap_or(Value::Null);
        let decision_approval_id = mapped.1.get("approval_id").cloned().unwrap_or(Value::Null);
        let decision_value = mapped.1.get("decision").cloned().unwrap_or(Value::Null);
        let mut decision_params = mapped.1.clone();
        if let Some(obj) = decision_params.as_object_mut() {
            // Inject verified approver identity from bound_action (never client free-form).
            if let Some(bound) = request
                .authorization
                .as_ref()
                .and_then(|a| a.bound_action.as_object())
            {
                if let Some(pid) = bound.get("principal_id").and_then(Value::as_str) {
                    obj.entry("approver_principal".to_owned())
                        .or_insert_with(|| Value::String(pid.to_owned()));
                }
            }
        }
        let outcome = {
            let mut guard = runtime.lock().await;
            guard
                .apply_control_plane_approval_decision(Some(decision_params))
                .await
        };
        return match outcome {
            Ok(mut body) => {
                // decisionOpId stays on the envelope so DeviceRoom pending matches;
                // target_operation_id + execution live in result for store apply.
                if let Some(object) = body.as_object_mut() {
                    if let Some(actual) =
                        object.insert("approval_id".into(), decision_approval_id.clone())
                    {
                        if actual != decision_approval_id {
                            object.insert("local_approval_id".into(), actual);
                        }
                    }
                }
                json!({
                    "operation_contract": OPERATION_CONTRACT_V1,
                    "operation_id": operation_id,
                    "status": "completed",
                    "result": bound_result_object(body)
                })
            }
            Err(error) => {
                let (code, message) = match &error {
                    ownmesh_ipc::IpcError::Remote { code, message } => {
                        let mapped = match *code {
                            ownmesh_ipc::app_error::POLICY_DENIED => "OWNMESH_E_POLICY_DENIED",
                            ownmesh_ipc::app_error::UNAUTHORIZED
                            | ownmesh_ipc::app_error::TOKEN_REVOKED
                            | ownmesh_ipc::app_error::LOCKDOWN => "OWNMESH_E_AUTHORIZATION",
                            ownmesh_ipc::app_error::INVALID_PARAMS => "OWNMESH_E_INVALID_ARGUMENT",
                            ownmesh_ipc::app_error::CONFLICT => "OWNMESH_E_CONFLICT",
                            _ => "OWNMESH_E_INTERNAL",
                        };
                        (mapped.to_owned(), message.clone())
                    }
                    other => ("OWNMESH_E_INTERNAL".to_owned(), other.to_string()),
                };
                json!({
                    "operation_contract": OPERATION_CONTRACT_V1,
                    "operation_id": operation_id,
                    "status": "failed",
                    "result": {
                        "approval_decision_applied": false,
                        "target_operation_id": decision_target_operation_id,
                        "approval_id": decision_approval_id,
                        "decision": decision_value,
                    },
                    "error": {
                        "code": code,
                        "message": message,
                        "retryable": false
                    }
                })
            }
        };
    }

    let client = match remote_agent_client_from_bound(request) {
        Ok(c) => c,
        Err(message) => {
            return json!({
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": operation_id,
                "status": "failed",
                "error": {
                    "code": "OWNMESH_E_ACTION_BINDING_MISMATCH",
                    "message": message,
                    "retryable": false
                }
            });
        }
    };
    let remote_principal_credential_generation =
        match remote_principal_credential_generation_from_bound(request) {
            Ok(generation) => generation,
            Err(message) => {
                return json!({
                    "operation_contract": OPERATION_CONTRACT_V1,
                    "operation_id": operation_id,
                    "status": "failed",
                    "error": {
                        "code": "OWNMESH_E_ACTION_BINDING_MISMATCH",
                        "message": message,
                        "retryable": false
                    }
                });
            }
        };
    // Capture remote exact-action expiry/hash onto any deferred ApprovalRecord.
    let remote_expires_unix = envelope_expires_at.and_then(|raw| {
        ownmesh_domain::Timestamp::parse(raw)
            .ok()
            .map(|ts| ts.date_time().unix_timestamp())
    });
    let remote_payload_hash = request.payload_hash.clone();
    let outcome = {
        let mut guard = runtime.lock().await;
        guard
            .dispatch_cancellable_bound_with_generation(
                mapped.0,
                Some(mapped.1),
                &client,
                cancel_rx,
                Some(operation_id.clone()),
                remote_expires_unix,
                remote_payload_hash.clone(),
                Some(device_id.as_str().to_owned()),
                remote_principal_credential_generation,
            )
            .await
    };

    match outcome {
        Ok(body) => {
            if let (Some(args), Some(ticket)) = (transfer_start_args, transfer_start_ticket) {
                let session = async {
                    let ticket_wire = args
                        .get("ticket")
                        .and_then(Value::as_str)
                        .ok_or("missing transfer ticket")?;
                    // Re-check the same exact action immediately before the
                    // one-time preflight cache is consumed and before opening
                    // the Room socket.  This keeps a substituted bearer from
                    // spending a legitimate ephemeral proof.
                    validate_ticket_for_start(&ticket, request, &args, device_id)?;
                    let expected_artifact_sha256 = args
                        .get("content_sha256")
                        .and_then(Value::as_str);
                    let cipher =
                        consume_preflight_cipher(preflight_ephemerals, device_id.as_str(), &ticket)
                            .await?;
                    let plan_id = body
                        .get("plan_id")
                        .and_then(Value::as_str)
                        .ok_or("transfer start plan id missing")?;
                    let authority = TransferSessionAuthority {
                        client: client.clone(),
                        operation_id: operation_id.clone(),
                        expires_at_unix: remote_expires_unix
                            .ok_or("transfer authority expiry missing")?,
                        payload_hash: remote_payload_hash
                            .clone()
                            .ok_or("transfer authority hash missing")?,
                        device_id: device_id.as_str().to_owned(),
                    };
                    let mut socket =
                        connect_transfer_socket(transfer_config, ticket_wire, &ticket).await?;
                    let mut cancel =
                        session_cancel.ok_or("transfer cancellation channel missing")?;
                    let cursor = transfer_ready_cursor(&mut socket, &ticket, &mut cancel).await?;
                    let pumped = if ticket.role == "source" {
                        run_source_transfer_pump(
                            &mut socket,
                            runtime,
                            &authority,
                            &ticket,
                            cipher,
                            plan_id,
                            cursor,
                            &mut cancel,
                        )
                        .await
                    } else {
                        run_destination_transfer_pump(
                            &mut socket,
                            runtime,
                            &authority,
                            &ticket,
                            cipher,
                            plan_id,
                            cursor,
                            &mut cancel,
                        )
                        .await
                    };
                    // A controller-side cancellation must become a durable room
                    // transition and remove the local receiver part file.  The
                    // cancel frame is best-effort only: local cleanup is still
                    // attempted if the peer has already disconnected.
                    let failure = pumped
                        .as_ref()
                        .err()
                        .map(|error| classify_transfer_failure(error));
                    if *cancel.borrow()
                        || matches!(failure, Some(TransferSessionFailure::Cancelled | TransferSessionFailure::Terminal))
                    {
                        if *cancel.borrow()
                            || matches!(failure, Some(TransferSessionFailure::Terminal))
                        {
                            let _ = socket
                                .send(Message::Text(
                                    json!({"protocol":"ownmesh.transfer/1.0","type":"cancel","transfer_id":ticket.transfer_id,"epoch":ticket.epoch,"fence":ticket.fence,"plan_sha256":ticket.plan_sha256})
                                        .to_string()
                                        .into(),
                                ))
                                .await;
                        }
                        let cleanup = transfer_runtime_call(
                            runtime,
                            &authority,
                            methods::TRANSFER_CANCEL,
                            json!({"plan_id":plan_id,"epoch":ticket.epoch,"fence":ticket.fence}),
                            None,
                        )
                        .await;
                        if ticket.role == "source" && cleanup.is_err() {
                            return Err("source cleanup pending".into());
                        }
                    }
                    let pump_receipt = pumped?;
                    transfer_start_result(
                        &body,
                        &ticket,
                        true,
                        (ticket.role == "destination").then_some(&pump_receipt),
                        expected_artifact_sha256,
                    )
                }
                .await;
                return match session {
                    Ok(result) => {
                        json!({"operation_contract":OPERATION_CONTRACT_V1,"operation_id":operation_id,"status":"completed","result":result})
                    }
                    Err(error) => {
                        let cleanup_pending = error == "source cleanup pending";
                        let (code, message, retryable) = match classify_transfer_failure(&error) {
                            TransferSessionFailure::Reconnect => ("OWNMESH_E_TRANSFER_RECONNECT", "transfer connection interrupted; obtain a fresh ticket to reconnect", true),
                            TransferSessionFailure::Cancelled => ("OWNMESH_E_TRANSFER_CANCELLED", "transfer cancelled", false),
                            TransferSessionFailure::Terminal => ("OWNMESH_E_TRANSFER_SESSION", "transfer session failed", false),
                        };
                        let code = if cleanup_pending {
                            "OWNMESH_E_TRANSFER_CLEANUP_PENDING"
                        } else {
                            code
                        };
                        let message = if cleanup_pending {
                            "source transfer cleanup is pending"
                        } else {
                            message
                        };
                        json!({"operation_contract":OPERATION_CONTRACT_V1,"operation_id":operation_id,"status":"failed","error":{"code":code,"message":message,"retryable":retryable}})
                    }
                };
            }
            // Runtime may surface policy ask without executing.
            if body.get("approval_required") == Some(&Value::Bool(true)) {
                // Always echo the remote MCP operation id (never a local mint) so
                // DeviceRoom operation_id binding accepts the approval_required result.
                return json!({
                    "operation_contract": OPERATION_CONTRACT_V1,
                    "operation_id": operation_id,
                    "status": "failed",
                    "error": {
                        "code": "OWNMESH_E_APPROVAL_REQUIRED",
                        "message": body.get("reason").and_then(Value::as_str).unwrap_or("device policy requires local approval"),
                        "retryable": false,
                        "details": {
                            "approval_required": true,
                            "approval_id": body.get("approval_id").cloned(),
                            "operation_id": operation_id,
                            "reason": body.get("reason").cloned(),
                            "target_preview": body.get("target_preview").cloned(),
                            "note": "ChatGPT confirmation is not an OwnMesh cryptographic attestation; local policy still requires an approved device grant when configured to ask. Browser/CLI recovery approval remains available."
                        }
                    }
                });
            }
            let result = if matches!(
                request.capability.as_str(),
                "transfer.preflight_source" | "transfer.preflight_destination"
            ) {
                match signed_transfer_preflight_result(
                    &body,
                    &operation_id,
                    device_key,
                    preflight_ephemerals,
                )
                .await
                {
                    Ok(result) => result,
                    Err(message) => {
                        return json!({
                            "operation_contract": OPERATION_CONTRACT_V1,
                            "operation_id": operation_id,
                            "status": "failed",
                            "error": {
                                "code": "OWNMESH_E_TRANSFER_PREFLIGHT",
                                "message": message,
                                "retryable": false
                            }
                        });
                    }
                }
            } else {
                body.get("result").cloned().unwrap_or(body)
            };
            let result = bind_remote_result_workspace(result, request);
            json!({
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": operation_id,
                "status": "completed",
                "result": bound_result_object(result)
            })
        }
        Err(error) => {
            let (status, code, message) = match &error {
                ownmesh_ipc::IpcError::Remote { code, message }
                    if *code == ownmesh_ipc::app_error::CONFLICT
                        && message.to_ascii_lowercase().contains("cancelled") =>
                {
                    (
                        "cancelled",
                        "OWNMESH_E_CANCELLED".to_owned(),
                        message.clone(),
                    )
                }
                ownmesh_ipc::IpcError::Remote { code, message } => {
                    let mapped = match *code {
                        ownmesh_ipc::app_error::POLICY_DENIED => "OWNMESH_E_POLICY_DENIED",
                        ownmesh_ipc::app_error::UNAUTHORIZED
                        | ownmesh_ipc::app_error::TOKEN_REVOKED
                        | ownmesh_ipc::app_error::LOCKDOWN => "OWNMESH_E_AUTHORIZATION",
                        ownmesh_ipc::app_error::INVALID_PARAMS => "OWNMESH_E_INVALID_ARGUMENT",
                        ownmesh_ipc::app_error::METHOD_NOT_FOUND => "OWNMESH_E_UNSUPPORTED_SURFACE",
                        ownmesh_ipc::app_error::PLATFORM_UNSUPPORTED => {
                            "OWNMESH_E_PLATFORM_UNSUPPORTED"
                        }
                        ownmesh_ipc::app_error::CONFLICT => "OWNMESH_E_CONFLICT",
                        _ => "OWNMESH_E_INTERNAL",
                    };
                    ("failed", mapped.to_owned(), message.clone())
                }
                other => ("failed", "OWNMESH_E_INTERNAL".to_owned(), other.to_string()),
            };
            json!({
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": operation_id,
                "status": status,
                "error": {
                    "code": code,
                    "message": message,
                    "retryable": false
                }
            })
        }
    }
}

async fn send_cached_result(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    completed: &CompletedReply,
) -> Result<(), String> {
    let bytes = next_envelope_bytes(
        config,
        state,
        "operation.result",
        completed.payload.clone(),
        Some(&completed.correlation_id),
    )?;
    OperationEnvelope::parse_slice(&bytes)
        .map_err(|error| format!("refusing to send invalid operation.result: {error}"))?;
    socket
        .send(Message::Text(
            String::from_utf8(bytes)
                .map_err(|error| format!("serialize operation.result UTF-8: {error}"))?
                .into(),
        ))
        .await
        .map_err(|error| format!("send operation.result: {error}"))
}

async fn send_envelope(
    socket: &mut AgentSocket,
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    message_type: &str,
    payload: Value,
    correlation_id: Option<&str>,
) -> Result<(), String> {
    let bytes = next_envelope_bytes(config, state, message_type, payload, correlation_id)?;
    let text = String::from_utf8(bytes)
        .map_err(|error| format!("serialize Agent envelope UTF-8: {error}"))?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|error| format!("send Agent envelope: {error}"))
}

fn next_envelope_bytes(
    config: &AgentTransportConfig,
    state: &mut AgentTransportState,
    message_type: &str,
    payload: Value,
    correlation_id: Option<&str>,
) -> Result<Vec<u8>, String> {
    let seq = state.next_seq()?;
    // Reserve the outbound sequence durably before network send. A crash may
    // leave a gap, but never reuses an authenticated session sequence.
    state.save(&config.state_path)?;
    let message_id = MessageId::parse(format!("msg_{}", Uuid::new_v4().simple()))
        .map_err(|error| format!("generate message id: {error}"))?;
    Envelope {
        protocol: PROTOCOL_DEVICE_V1.into(),
        message_id,
        message_type: message_type.to_owned(),
        device_id: config.device_id.clone(),
        correlation_id: correlation_id.map(str::to_owned),
        seq,
        sent_at: Timestamp::now(),
        expires_at: None,
        payload,
    }
    .to_vec()
    .map_err(|error| error.to_string())
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_identity::verify_from_public_key_hex;
    use tempfile::tempdir;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    #[test]
    fn agent_url_preserves_issuer_path_and_uses_secure_scheme() {
        let secure = agent_connect_url("https://cp.example/base", "dev_alpha").unwrap();
        assert_eq!(secure.scheme(), "wss");
        assert_eq!(secure.path(), "/base/agent/connect");
        assert_eq!(
            secure
                .query_pairs()
                .find(|(key, _)| key == "role")
                .unwrap()
                .1,
            "agent"
        );

        let loopback = agent_connect_url("http://127.0.0.1:8787", "dev_alpha").unwrap();
        assert_eq!(loopback.scheme(), "ws");
        assert_eq!(loopback.port(), Some(8787));
    }

    #[tokio::test(start_paused = true)]
    async fn reconnect_backoff_resets_after_authenticated_ready_session() {
        let mut backoff = ReconnectBackoff::default();

        // Two failures before the ready handshake retain exponential backoff.
        let first_delay = backoff.next_delay();
        assert_eq!(first_delay, Duration::from_secs(2));
        paused_sleep_completes_after(first_delay).await;

        let second_delay = backoff.next_delay();
        assert_eq!(second_delay, Duration::from_secs(4));
        paused_sleep_completes_after(second_delay).await;

        // A peer disconnect after an authenticated ready session is a new
        // reconnect history, so its delay returns to the existing base delay.
        backoff.reset_after_ready();
        let post_ready_delay = backoff.next_delay();
        assert_eq!(post_ready_delay, Duration::from_secs(2));
        paused_sleep_completes_after(post_ready_delay).await;
    }

    async fn paused_sleep_completes_after(delay: Duration) {
        let (complete_tx, mut complete_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = complete_tx.send(());
        });
        tokio::task::yield_now().await;
        assert!(matches!(
            complete_rx.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Empty)
        ));
        tokio::time::advance(delay).await;
        complete_rx.await.unwrap();
    }

    #[test]
    fn state_rejects_corruption_and_bounds_replay_windows() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("transport.json");
        let device = DeviceId::parse("dev_state").unwrap();
        let mut state = AgentTransportState::fresh("https://cp.example", &device);
        for index in 0..(MAX_REPLAY_ENTRIES + 7) {
            state.remember_message(format!("msg_{index}"));
        }
        state.save(&path).unwrap();
        let loaded = AgentTransportState::load(&path, "https://cp.example", &device).unwrap();
        assert_eq!(loaded.seen_message_ids.len(), MAX_REPLAY_ENTRIES);
        assert!(!loaded.has_seen_message("msg_0"));

        std::fs::write(&path, b"{not-json").unwrap();
        assert!(AgentTransportState::load(&path, "https://cp.example", &device).is_err());
    }

    #[test]
    fn inbound_replay_is_rejected_before_sequence_rewind() {
        let dir = tempdir().unwrap();
        let device = DeviceId::parse("dev_replay").unwrap();
        let config = AgentTransportConfig {
            issuer: "http://127.0.0.1:1".into(),
            ws_url: agent_connect_url("http://127.0.0.1:1", device.as_str()).unwrap(),
            origin: "http://127.0.0.1:1".into(),
            device_id: device.clone(),
            credential: SecretString::new("redacted-test-credential"),
            key: Arc::new(DeviceKeyPair::generate()),
            preflight_ephemerals: Arc::new(Mutex::new(HashMap::new())),
            state_path: dir.path().join("transport.json"),
        };
        let mut state = AgentTransportState::fresh(&config.issuer, &device);
        let envelope = Envelope {
            protocol: PROTOCOL_DEVICE_V1.into(),
            message_id: MessageId::parse("msg_replay").unwrap(),
            message_type: "pong".into(),
            device_id: device,
            correlation_id: None,
            seq: 1,
            sent_at: Timestamp::now(),
            expires_at: None,
            payload: json!({}),
        };
        let raw = String::from_utf8(envelope.to_vec().unwrap()).unwrap();
        assert!(matches!(
            parse_and_record_inbound(&raw, &config, &mut state).unwrap(),
            InboundFrame::New { .. }
        ));
        assert!(matches!(
            parse_and_record_inbound(&raw, &config, &mut state).unwrap(),
            InboundFrame::Duplicate(_)
        ));

        let mut rewind: Value = serde_json::from_str(&raw).unwrap();
        rewind["message_id"] = Value::String("msg_rewind".into());
        assert!(parse_and_record_inbound(&rewind.to_string(), &config, &mut state).is_err());
    }

    #[test]
    fn operation_request_persists_pending_outbox_across_crash_reload() {
        let dir = tempdir().unwrap();
        let device = DeviceId::parse("dev_outbox").unwrap();
        let config = AgentTransportConfig {
            issuer: "http://127.0.0.1:1".into(),
            ws_url: agent_connect_url("http://127.0.0.1:1", device.as_str()).unwrap(),
            origin: "http://127.0.0.1:1".into(),
            device_id: device.clone(),
            credential: SecretString::new("redacted-test-credential"),
            key: Arc::new(DeviceKeyPair::generate()),
            preflight_ephemerals: Arc::new(Mutex::new(HashMap::new())),
            state_path: dir.path().join("transport.json"),
        };
        let mut state = AgentTransportState::fresh(&config.issuer, &device);
        let sent_at = Timestamp::now();
        let expires_at = sent_at.checked_add(Duration::from_secs(60)).unwrap();
        let raw_value = json!({
            "protocol": PROTOCOL_DEVICE_V1,
            "message_id": "msg_outbox_1",
            "type": "operation.request",
            "device_id": device.as_str(),
            "correlation_id": "op_outbox_1",
            "seq": 1,
            "sent_at": sent_at,
            "expires_at": expires_at,
            "payload": {
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": "op_outbox_1",
                "capability": "fs.read",
                "idempotency_key": "idem_outbox_1",
                "arguments": { "path": "a.txt" }
            }
        });
        let raw = raw_value.to_string();
        assert!(matches!(
            parse_and_record_inbound(&raw, &config, &mut state).unwrap(),
            InboundFrame::New { .. }
        ));
        assert_eq!(state.pending_dispatches.len(), 1);
        assert_eq!(state.pending_dispatches[0].correlation_id, "op_outbox_1");
        assert_eq!(state.pending_dispatches[0].raw, raw);

        // Simulate crash: reload only what was durably saved.
        let reloaded =
            AgentTransportState::load(&config.state_path, &config.issuer, &device).unwrap();
        assert_eq!(reloaded.pending_dispatches.len(), 1);
        assert!(reloaded.has_seen_message("msg_outbox_1"));
        assert!(reloaded.completed("op_outbox_1").is_none());

        // Duplicate after crash still surfaces as Duplicate, with outbox raw intact.
        let mut reloaded = reloaded;
        assert!(matches!(
            parse_and_record_inbound(&raw, &config, &mut reloaded).unwrap(),
            InboundFrame::Duplicate(_)
        ));
        let pending = reloaded
            .pending_by_correlation("op_outbox_1")
            .expect("outbox must retain raw for resume");
        assert_eq!(pending.raw, raw);

        // Terminal completion clears the outbox (exact-once finish).
        reloaded.remember_completed(CompletedReply {
            correlation_id: "op_outbox_1".into(),
            operation_id: "op_outbox_1".into(),
            payload: json!({
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": "op_outbox_1",
                "status": "completed",
                "result": { "ok": true }
            }),
        });
        assert!(reloaded.pending_by_correlation("op_outbox_1").is_none());
        assert!(reloaded.completed("op_outbox_1").is_some());
    }

    #[test]
    fn transfer_start_crash_receipt_excludes_bearer_and_requires_fresh_session() {
        let dir = tempdir().unwrap();
        let device = DeviceId::parse("dev_transfer_receipt").unwrap();
        let config = AgentTransportConfig {
            issuer: "http://127.0.0.1:1".into(),
            ws_url: agent_connect_url("http://127.0.0.1:1", device.as_str()).unwrap(),
            origin: "http://127.0.0.1:1".into(),
            device_id: device.clone(),
            credential: SecretString::new("redacted-test-credential"),
            key: Arc::new(DeviceKeyPair::generate()),
            preflight_ephemerals: Arc::new(Mutex::new(HashMap::new())),
            state_path: dir.path().join("transport.json"),
        };
        let mut state = AgentTransportState::fresh(&config.issuer, &device);
        let sent_at = Timestamp::now();
        let expires_at = sent_at.checked_add(Duration::from_secs(60)).unwrap();
        let raw = json!({
            "protocol": PROTOCOL_DEVICE_V1,
            "message_id": "msg_transfer_receipt",
            "type": "operation.request",
            "device_id": device.as_str(),
            "correlation_id": "op_transfer_receipt",
            "seq": 1,
            "sent_at": sent_at,
            "expires_at": expires_at,
            "payload": {
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": "op_transfer_receipt",
                "capability": "transfer.start",
                "arguments": {
                    "ticket": "ticket-secret-must-not-persist",
                    "jti": "jti-secret-must-not-persist",
                    "ephemeral_private_key": "key-secret-must-not-persist"
                }
            }
        })
        .to_string();
        parse_and_record_inbound(&raw, &config, &mut state).unwrap();
        let saved = std::fs::read_to_string(&config.state_path).unwrap();
        for forbidden in [
            "ticket-secret-must-not-persist",
            "jti-secret-must-not-persist",
            "key-secret-must-not-persist",
            "ticket\"",
            "ephemeral",
        ] {
            assert!(!saved.contains(forbidden), "state leaked {forbidden}");
        }
        let reloaded =
            AgentTransportState::load(&config.state_path, &config.issuer, &device).unwrap();
        let pending = reloaded
            .pending_by_correlation("op_transfer_receipt")
            .unwrap();
        assert!(pending.transfer_session_lost);
        assert!(pending.raw.is_empty());
        let recovery = transfer_session_lost_reply(&pending.operation_id);
        assert_eq!(recovery["error"]["code"], "OWNMESH_E_TRANSFER_SESSION_LOST");
        assert_eq!(recovery["error"]["retryable"], true);
        assert!(!recovery
            .to_string()
            .contains("ticket-secret-must-not-persist"));
    }

    #[test]
    fn pending_outbox_capacity_rejects_without_live_eviction() {
        let device = DeviceId::parse("dev_cap").unwrap();
        let mut state = AgentTransportState::fresh("http://127.0.0.1:1", &device);
        for i in 0..MAX_PENDING_DISPATCHES {
            state
                .remember_pending(PendingDispatch {
                    message_id: format!("msg_cap_{i}"),
                    correlation_id: format!("op_cap_{i}"),
                    operation_id: format!("op_cap_{i}"),
                    raw: format!(r#"{{"i":{i}}}"#),
                    accepted_at: Timestamp::now().to_rfc3339(),
                    transfer_session_lost: false,
                    expires_at: None,
                    dispatch_started: Some(false),
                })
                .unwrap();
        }
        let err = state
            .remember_pending(PendingDispatch {
                message_id: "msg_overflow".into(),
                correlation_id: "op_overflow".into(),
                operation_id: "op_overflow".into(),
                raw: r#"{"i":999}"#.into(),
                accepted_at: Timestamp::now().to_rfc3339(),
                transfer_session_lost: false,
                expires_at: None,
                dispatch_started: Some(false),
            })
            .expect_err("must reject when full");
        assert!(
            err.contains("no live eviction"),
            "capacity error must refuse eviction: {err}"
        );
        assert_eq!(state.pending_dispatches.len(), MAX_PENDING_DISPATCHES);
        assert!(state.pending_by_correlation("op_cap_0").is_some());
    }

    #[tokio::test]
    async fn terminal_receipt_survives_websocket_send_failure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket.send(Message::Close(None)).await.unwrap();
        });

        let dir = tempdir().unwrap();
        let device = DeviceId::parse("dev_failed_send").unwrap();
        let issuer = format!("http://{address}");
        let config = AgentTransportConfig {
            issuer: issuer.clone(),
            ws_url: agent_connect_url(&issuer, device.as_str()).unwrap(),
            origin: issuer,
            device_id: device.clone(),
            credential: SecretString::new("dcred_failed_send"),
            key: Arc::new(DeviceKeyPair::generate()),
            preflight_ephemerals: Arc::new(Mutex::new(HashMap::new())),
            state_path: dir.path().join("transport.json"),
        };
        let (mut socket, _) = tokio_tungstenite::connect_async(config.ws_url.as_str())
            .await
            .unwrap();
        assert!(matches!(
            socket.next().await.unwrap().unwrap(),
            Message::Close(_)
        ));

        let mut state = AgentTransportState::fresh(&config.issuer, &device);
        state
            .remember_pending(PendingDispatch {
                message_id: "msg_failed_send".into(),
                correlation_id: "op_failed_send".into(),
                operation_id: "op_failed_send".into(),
                raw: "accepted-operation".into(),
                accepted_at: Timestamp::now().to_rfc3339(),
                transfer_session_lost: false,
                expires_at: None,
                dispatch_started: Some(false),
            })
            .unwrap();
        state.save(&config.state_path).unwrap();
        let operation_id = ownmesh_domain::OperationId::parse("op_failed_send").unwrap();
        let completed = CompletedReply {
            correlation_id: operation_id.to_string(),
            operation_id: operation_id.to_string(),
            payload: operation_expired_reply(&operation_id),
        };
        assert!(
            persist_and_send_completed(&mut socket, &config, &mut state, completed)
                .await
                .is_err()
        );
        server.await.unwrap();

        let persisted =
            AgentTransportState::load(&config.state_path, &config.issuer, &config.device_id)
                .unwrap();
        assert!(persisted.pending_dispatches.is_empty());
        assert_eq!(persisted.completed_replies.len(), 1);
        assert_eq!(
            persisted.completed_replies[0].payload["error"]["code"],
            "OWNMESH_E_OPERATION_EXPIRED"
        );
    }

    #[tokio::test]
    async fn real_websocket_auth_reconnect_resume_and_correlation_dedup() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let dir = tempdir().unwrap();
        let device = DeviceId::parse("dev_loopback").unwrap();
        let key = DeviceKeyPair::generate();
        let public_key = key.public_identity().public_key_hex;
        let issuer = format!("http://{address}");
        let credential = "dcred_loopback_secret";
        let config = AgentTransportConfig {
            issuer: issuer.clone(),
            ws_url: agent_connect_url(&issuer, device.as_str()).unwrap(),
            origin: issuer.clone(),
            device_id: device.clone(),
            credential: SecretString::new(credential),
            key: Arc::new(key),
            preflight_ephemerals: Arc::new(Mutex::new(HashMap::new())),
            state_path: dir.path().join("transport.json"),
        };
        let runtime_dir = tempdir().unwrap();
        let runtime_paths = OwnMeshPaths::for_base(runtime_dir.path());
        let mut daemon = DaemonRuntime::open(&runtime_paths).unwrap();
        daemon.set_policy_for_test(ownmesh_policy::preset_document(
            ownmesh_policy::AccessPreset::FullAccess,
        ));
        let target = runtime_paths.state_dir.join("workspace/replay-once.txt");
        let (mut started_request, _) =
            sample_bound_request(device.as_str(), "replay-once.txt", Some("first result"));
        let started_expires_at = Timestamp::now()
            .checked_sub(Duration::from_secs(120))
            .unwrap();
        let bound = &mut started_request.authorization.as_mut().unwrap().bound_action;
        bound["expires_at"] = json!(started_expires_at.to_rfc3339());
        started_request.payload_hash = Some(sha256_hex_str(&stable_stringify(bound)));
        let runtime = Arc::new(Mutex::new(daemon));
        let seeded_result = dispatch_remote_operation(
            &runtime,
            &device,
            &config.key,
            &config.preflight_ephemerals,
            &config,
            &started_request,
            Some(&started_expires_at.to_rfc3339()),
            &CancelRegistry::default(),
            None,
        )
        .await;
        assert_eq!(seeded_result["status"], "completed");
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "first result");
        std::fs::write(&target, "sentinel after first execution").unwrap();

        // Windows persisted this exact shape before every reconnect: a typed
        // request plus the Expiry Display string in pending_dispatches.
        let mut state = AgentTransportState::fresh(&config.issuer, &config.device_id);
        let expired_raw = test_operation_request_raw(
            &device,
            1,
            "msg_expired_resume",
            "op_expired_resume",
            Timestamp::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap(),
        );
        parse_and_record_inbound(&expired_raw, &config, &mut state).unwrap();
        let pending = state.pending_by_correlation("op_expired_resume").unwrap();
        assert!(pending
            .expires_at
            .as_deref()
            .is_some_and(|expiry| expiry.starts_with("expires_at=")));
        let legacy_raw = test_operation_request_raw(
            &device,
            2,
            "msg_legacy_resume",
            "op_legacy_resume",
            Timestamp::now()
                .checked_sub(Duration::from_secs(120))
                .unwrap(),
        );
        parse_and_record_inbound(&legacy_raw, &config, &mut state).unwrap();
        state
            .pending_dispatches
            .iter_mut()
            .find(|pending| pending.correlation_id == "op_legacy_resume")
            .unwrap()
            .dispatch_started = None;
        let started_raw = json!({
            "protocol": PROTOCOL_DEVICE_V1,
            "message_id": "msg_started_resume",
            "type": "operation.request",
            "device_id": device.as_str(),
            "correlation_id": started_request.operation_id,
            "seq": 3,
            "sent_at": Timestamp::now(),
            "expires_at": started_expires_at,
            "payload": started_request
        })
        .to_string();
        OperationEnvelope::parse_str(&started_raw).unwrap();
        parse_and_record_inbound(&started_raw, &config, &mut state).unwrap();
        state.mark_dispatch_started("op_bind_test").unwrap();
        state.save(&config.state_path).unwrap();
        let saved: Value =
            serde_json::from_slice(&std::fs::read(&config.state_path).unwrap()).unwrap();
        let legacy = saved["pending_dispatches"]
            .as_array()
            .unwrap()
            .iter()
            .find(|pending| pending["correlation_id"] == "op_legacy_resume")
            .unwrap();
        assert!(legacy.get("dispatch_started").is_none());

        let server_device = device.clone();
        let server_origin = issuer.clone();
        let server_credential = credential.to_owned();
        let expected_started_result = seeded_result.clone();
        let replay_target = target.clone();
        let server = tokio::spawn(async move {
            let mut server_seq = 3_u64;
            let mut first_result: Option<Envelope> = None;
            let mut first_expired_payload: Option<Value> = None;
            for connection_index in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let expected_origin = server_origin.clone();
                let expected_authorization = format!("Bearer {server_credential}");
                let mut socket =
                    accept_hdr_async(stream, move |request: &Request, response: Response| {
                        assert_eq!(
                            request.headers().get(ORIGIN).unwrap().to_str().unwrap(),
                            expected_origin
                        );
                        assert_eq!(
                            request
                                .headers()
                                .get(AUTHORIZATION)
                                .unwrap()
                                .to_str()
                                .unwrap(),
                            expected_authorization
                        );
                        Ok(response)
                    })
                    .await
                    .unwrap();

                let hello = receive_test_envelope(&mut socket).await;
                assert_eq!(hello.message_type, "hello");
                if connection_index == 1 {
                    assert_eq!(hello.payload["resume"]["last_server_seq"].as_u64(), Some(7));
                    assert!(hello.payload["resume"]["next_outbound_seq"]
                        .as_u64()
                        .is_some_and(|seq| seq >= 4));
                }

                server_seq += 1;
                let challenge_message =
                    format!("ownmesh-device-challenge:nonce-{connection_index}:{server_device}");
                send_test_envelope(
                    &mut socket,
                    &server_device,
                    server_seq,
                    "challenge",
                    json!({
                        "message": challenge_message,
                        "connection_id": format!("conn_{connection_index}")
                    }),
                    None,
                )
                .await;

                let proof = receive_test_envelope(&mut socket).await;
                assert_eq!(proof.message_type, "proof");
                verify_from_public_key_hex(
                    &public_key,
                    challenge_message.as_bytes(),
                    proof.payload["signature"].as_str().unwrap(),
                )
                .unwrap();

                server_seq += 1;
                send_test_envelope(
                    &mut socket,
                    &server_device,
                    server_seq,
                    "accepted",
                    json!({
                        "selected_protocol": PROTOCOL_DEVICE_V1,
                        "session_parameters": {
                            "heartbeat_sec": 30,
                            "max_payload_bytes": MAX_PAYLOAD_BYTES
                        }
                    }),
                    None,
                )
                .await;
                let ready = receive_test_envelope(&mut socket).await;
                assert_eq!(ready.message_type, "ready");
                assert_eq!(ready.payload["remote_routing_enabled"], Value::Bool(true));

                server_seq += 1;
                send_test_envelope(
                    &mut socket,
                    &server_device,
                    server_seq,
                    "ready.ack",
                    json!({ "ok": true }),
                    None,
                )
                .await;

                if connection_index == 0 {
                    // Crash resume terminalizes the expired operation without
                    // closing the socket, then the normal request below runs.
                    let expired = receive_test_envelope(&mut socket).await;
                    assert_eq!(expired.correlation_id.as_deref(), Some("op_expired_resume"));
                    assert_eq!(
                        expired.payload["error"]["code"],
                        "OWNMESH_E_OPERATION_EXPIRED"
                    );
                    first_expired_payload = Some(expired.payload);
                    let legacy = receive_test_envelope(&mut socket).await;
                    assert_eq!(
                        legacy.payload["error"]["code"],
                        "OWNMESH_E_DISPATCH_OUTCOME_UNKNOWN"
                    );
                    assert_eq!(
                        legacy.payload["error"]["details"]["category"],
                        "dispatch_outcome_unknown"
                    );
                    let reconciled = receive_test_envelope(&mut socket).await;
                    assert_eq!(reconciled.correlation_id.as_deref(), Some("op_bind_test"));
                    assert_eq!(reconciled.payload, expected_started_result);
                    assert_eq!(
                        std::fs::read_to_string(&replay_target).unwrap(),
                        "sentinel after first execution"
                    );
                } else {
                    // A reconnect redelivery is answered from the durable
                    // terminal cache and never executes the request again.
                    server_seq += 1;
                    send_test_operation_request_named(
                        &mut socket,
                        &server_device,
                        server_seq,
                        "msg_expired_replay",
                        "op_expired_resume",
                    )
                    .await;
                    let cached = receive_test_envelope(&mut socket).await;
                    assert_eq!(cached.payload, first_expired_payload.clone().unwrap());
                }

                server_seq += 1;
                send_test_operation_request(
                    &mut socket,
                    &server_device,
                    server_seq,
                    if connection_index == 0 {
                        "msg_operation_first"
                    } else {
                        "msg_operation_replay"
                    },
                )
                .await;
                let result = receive_test_envelope(&mut socket).await;
                assert_eq!(result.message_type, "operation.result");
                assert_eq!(result.correlation_id.as_deref(), Some("op_loopback"));
                assert_eq!(result.payload["status"], "failed");
                assert_eq!(
                    result.payload["error"]["code"],
                    "OWNMESH_E_ACTION_BINDING_MISMATCH"
                );
                OperationEnvelope::parse_slice(&result.to_vec().unwrap()).unwrap();
                if let Some(first) = first_result.as_ref() {
                    assert!(result.seq > first.seq);
                    assert_ne!(result.message_id, first.message_id);
                    assert_eq!(result.payload, first.payload);
                } else {
                    first_result = Some(result);
                }
                socket.send(Message::Close(None)).await.unwrap();
            }
        });

        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut first_shutdown = shutdown_rx.clone();
        let mut first_reached_ready = false;
        assert!(connect_and_run(
            &config,
            Some(&runtime),
            &mut state,
            &mut first_shutdown,
            &mut first_reached_ready,
        )
        .await
        .is_err());
        assert!(first_reached_ready);
        let mut second_shutdown = shutdown_rx;
        let mut second_reached_ready = false;
        assert!(connect_and_run(
            &config,
            Some(&runtime),
            &mut state,
            &mut second_shutdown,
            &mut second_reached_ready,
        )
        .await
        .is_err());
        assert!(second_reached_ready);
        server.await.unwrap();

        let persisted =
            AgentTransportState::load(&config.state_path, &config.issuer, &config.device_id)
                .unwrap();
        assert_eq!(persisted.last_server_seq, 12);
        assert_eq!(persisted.completed_replies.len(), 4);
        assert!(persisted.pending_dispatches.is_empty());
        assert!(persisted.completed("op_loopback").is_some());
        assert_eq!(
            persisted.completed("op_expired_resume").unwrap().payload["error"]["code"],
            "OWNMESH_E_OPERATION_EXPIRED"
        );
        assert_eq!(
            persisted.completed("op_legacy_resume").unwrap().payload["error"]["code"],
            "OWNMESH_E_DISPATCH_OUTCOME_UNKNOWN"
        );
    }

    async fn receive_test_envelope<S>(socket: &mut WebSocketStream<S>) -> Envelope
    where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        loop {
            match socket.next().await.unwrap().unwrap() {
                Message::Text(text) => return Envelope::parse_str(text.as_str()).unwrap(),
                Message::Ping(payload) => socket.send(Message::Pong(payload)).await.unwrap(),
                other => panic!("unexpected test WebSocket message: {other:?}"),
            }
        }
    }

    async fn send_test_envelope<S>(
        socket: &mut WebSocketStream<S>,
        device_id: &DeviceId,
        seq: u64,
        message_type: &str,
        payload: Value,
        correlation_id: Option<&str>,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let envelope = Envelope {
            protocol: PROTOCOL_DEVICE_V1.into(),
            message_id: MessageId::parse(format!("msg_server_{seq}")).unwrap(),
            message_type: message_type.into(),
            device_id: device_id.clone(),
            correlation_id: correlation_id.map(str::to_owned),
            seq,
            sent_at: Timestamp::now(),
            expires_at: None,
            payload,
        };
        socket
            .send(Message::Text(
                String::from_utf8(envelope.to_vec().unwrap())
                    .unwrap()
                    .into(),
            ))
            .await
            .unwrap();
    }

    async fn send_test_operation_request<S>(
        socket: &mut WebSocketStream<S>,
        device_id: &DeviceId,
        seq: u64,
        message_id: &str,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let sent_at = Timestamp::now();
        let expires_at = sent_at.checked_add(Duration::from_secs(60)).unwrap();
        let raw = json!({
            "protocol": PROTOCOL_DEVICE_V1,
            "message_id": message_id,
            "type": "operation.request",
            "device_id": device_id,
            "correlation_id": "op_loopback",
            "seq": seq,
            "sent_at": sent_at,
            "expires_at": expires_at,
            "payload": {
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": "op_loopback",
                "capability": "fs.read",
                "idempotency_key": "idem_loopback",
                "arguments": { "path": "README.md" }
            }
        });
        OperationEnvelope::parse_slice(&serde_json::to_vec(&raw).unwrap()).unwrap();
        socket
            .send(Message::Text(raw.to_string().into()))
            .await
            .unwrap();
    }

    async fn send_test_operation_request_named<S>(
        socket: &mut WebSocketStream<S>,
        device_id: &DeviceId,
        seq: u64,
        message_id: &str,
        operation_id: &str,
    ) where
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    {
        let raw = test_operation_request_raw(
            device_id,
            seq,
            message_id,
            operation_id,
            Timestamp::now()
                .checked_add(Duration::from_secs(60))
                .unwrap(),
        );
        socket.send(Message::Text(raw.into())).await.unwrap();
    }

    fn test_operation_request_raw(
        device_id: &DeviceId,
        seq: u64,
        message_id: &str,
        operation_id: &str,
        expires_at: Timestamp,
    ) -> String {
        let raw = json!({
            "protocol": PROTOCOL_DEVICE_V1,
            "message_id": message_id,
            "type": "operation.request",
            "device_id": device_id,
            "correlation_id": operation_id,
            "seq": seq,
            "sent_at": Timestamp::now(),
            "expires_at": expires_at,
            "payload": {
                "operation_contract": OPERATION_CONTRACT_V1,
                "operation_id": operation_id,
                "capability": "fs.read",
                "idempotency_key": format!("idem_{operation_id}"),
                "arguments": { "path": "README.md" }
            }
        });
        OperationEnvelope::parse_slice(&serde_json::to_vec(&raw).unwrap()).unwrap();
        raw.to_string()
    }

    fn sample_bound_request(
        device_id: &str,
        path: &str,
        content: Option<&str>,
    ) -> (OperationRequestPayload, String) {
        use ownmesh_protocol::OperationAuthorizationBinding;
        let expires = Timestamp::now()
            .checked_add(Duration::from_secs(120))
            .unwrap()
            .to_rfc3339();
        let mut facts = Map::new();
        facts.insert("path".into(), Value::String(path.into()));
        if let Some(text) = content {
            facts.insert("content_sha256".into(), Value::String(sha256_hex_str(text)));
            facts.insert(
                "content_bytes".into(),
                Value::Number(serde_json::Number::from(text.len() as u64)),
            );
        }
        let mut bound = Map::new();
        bound.insert("capability".into(), json!("filesystem.write"));
        bound.insert("action".into(), json!("fs.write"));
        bound.insert("tool".into(), json!("ownmesh_fs_write"));
        bound.insert("device_id".into(), json!(device_id));
        bound.insert("principal_id".into(), json!("prin_dev"));
        bound.insert("tenant_id".into(), json!("ten_default"));
        bound.insert("oauth_client_id".into(), Value::Null);
        bound.insert("workspace_id".into(), json!("ws_default"));
        bound.insert("workspace_version".into(), json!(1));
        bound.insert("facts".into(), Value::Object(facts));
        bound.insert("operation_id".into(), json!("op_bind_test"));
        bound.insert("expires_at".into(), json!(expires));
        bound.insert("claim_version".into(), json!(1));
        let bound_value = Value::Object(bound);
        let hash = sha256_hex_str(&stable_stringify(&bound_value));
        let mut arguments = Map::new();
        arguments.insert("action".into(), json!("fs.write"));
        arguments.insert("path".into(), json!(path));
        if let Some(text) = content {
            arguments.insert("content".into(), json!(text));
        }
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_bind_test").unwrap(),
            capability: "filesystem.write".into(),
            workspace_id: Some(ownmesh_domain::WorkspaceId::parse("ws_default").unwrap()),
            idempotency_key: "idem_bind_test".into(),
            payload_hash: Some(hash.clone()),
            authorization: Some(OperationAuthorizationBinding {
                bound_action: bound_value,
            }),
            arguments: Value::Object(arguments),
        };
        (request, expires)
    }

    #[test]
    fn exact_action_binding_accepts_matching_request() {
        let device = DeviceId::parse("dev_bind_ok").unwrap();
        let (request, expires) = sample_bound_request(device.as_str(), "a.txt", Some("hello"));
        assert!(verify_exact_action_binding(&device, &request, Some(&expires)).is_ok());
    }

    fn refresh_bound_hash(request: &mut OperationRequestPayload) {
        let bound = request
            .authorization
            .as_ref()
            .expect("bound action")
            .bound_action
            .clone();
        request.payload_hash = Some(sha256_hex_str(&stable_stringify(&bound)));
    }

    #[test]
    fn admin_rule_request_is_exact_bound_then_typed_for_private_ipc() {
        let device = DeviceId::parse("dev_admin_rule").unwrap();
        let (mut request, expires) =
            sample_bound_request(device.as_str(), "unused.txt", Some("unused"));
        request.capability = "admin.policy.rule_add".into();
        request.arguments = json!({
            "action": "admin.policy.rule_add",
            "id": "rule_workspace_write",
            "rule_decision": "ask",
            "capability": "filesystem.write",
            "priority": 25
        });
        let facts = recompute_action_facts(request.arguments.as_object().unwrap()).unwrap();
        let bound = request
            .authorization
            .as_mut()
            .unwrap()
            .bound_action
            .as_object_mut()
            .unwrap();
        bound.insert("capability".into(), json!("admin.policy.rule_add"));
        bound.insert("action".into(), json!("admin.policy.rule_add"));
        bound.insert("tool".into(), json!("ownmesh_policy_rule_add"));
        bound.insert("facts".into(), Value::Object(facts));
        refresh_bound_hash(&mut request);

        assert!(verify_exact_action_binding(&device, &request, Some(&expires)).is_ok());
        let (method, params) = map_request_to_method(&request).unwrap();
        assert_eq!(method, methods::ADMIN_POLICY_RULE_ADD_REQUEST);
        assert_eq!(params["decision"], "ask");
        assert!(params.get("rule_decision").is_none());

        request.arguments["rule_decision"] = json!("deny");
        assert!(
            verify_exact_action_binding(&device, &request, Some(&expires))
                .unwrap_err()
                .contains("facts")
        );
    }

    #[test]
    fn oversized_approval_result_keeps_exact_decision_binding() {
        let bounded = bound_result_object(json!({
            "content": "x".repeat(800_000),
            "approval_decision_applied": true,
            "approval_id": "apr_cp_fallback",
            "local_approval_id": "apr_local_actual",
            "decision": "approve",
            "target_operation_id": "op_target"
        }));
        assert_eq!(bounded["truncated"], true);
        assert_eq!(bounded["approval_decision_applied"], true);
        assert_eq!(bounded["approval_id"], "apr_cp_fallback");
        assert_eq!(bounded["local_approval_id"], "apr_local_actual");
        assert_eq!(bounded["decision"], "approve");
        assert_eq!(bounded["target_operation_id"], "op_target");
    }

    #[test]
    fn verified_envelope_workspace_cannot_be_substituted_for_fs_or_elevated_command() {
        let device = DeviceId::parse("dev_workspace_bound").unwrap();
        let (mut fs_request, expires) =
            sample_bound_request(device.as_str(), "workspace.txt", Some("hello"));
        fs_request.workspace_id = Some(ownmesh_domain::WorkspaceId::parse("ws_verified").unwrap());
        fs_request
            .authorization
            .as_mut()
            .unwrap()
            .bound_action
            .as_object_mut()
            .unwrap()
            .insert("workspace_id".into(), json!("ws_verified"));
        fs_request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("workspace_id".into(), json!("ws_attacker"));
        refresh_bound_hash(&mut fs_request);
        assert!(verify_exact_action_binding(&device, &fs_request, Some(&expires)).is_ok());
        let bound_result = bind_remote_result_workspace(json!({ "entries": [] }), &fs_request);
        assert_eq!(bound_result["workspace_id"], "ws_verified");
        assert_eq!(bound_result["workspace_version"], 1);
        assert!(map_request_to_method(&fs_request).is_err());

        let mut command_request = fs_request.clone();
        command_request.capability = "command.run".into();
        command_request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("action".into(), json!("command.run"));
        let bound = command_request
            .authorization
            .as_mut()
            .unwrap()
            .bound_action
            .as_object_mut()
            .unwrap();
        bound.insert("capability".into(), json!("command.run"));
        bound.insert("action".into(), json!("command.run"));
        refresh_bound_hash(&mut command_request);
        assert!(verify_exact_action_binding(&device, &command_request, Some(&expires)).is_ok());
        assert!(map_request_to_method(&command_request).is_err());

        command_request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("workspace_id".into(), json!("ws_verified"));
        let (_, mapped) = map_request_to_method(&command_request).unwrap();
        assert_eq!(mapped["workspace_id"], "ws_verified");

        // Elevation is a signed command fact, not a local/Agent toggle. A
        // matching request reaches runtime; substitution is rejected by the
        // exact-action check before any broker handoff.
        command_request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("elevated".into(), json!(true));
        command_request
            .authorization
            .as_mut()
            .unwrap()
            .bound_action
            .as_object_mut()
            .unwrap()
            .get_mut("facts")
            .and_then(Value::as_object_mut)
            .unwrap()
            .insert("elevated".into(), json!(true));
        refresh_bound_hash(&mut command_request);
        assert!(verify_exact_action_binding(&device, &command_request, Some(&expires)).is_ok());
        let (_, mapped) = map_request_to_method(&command_request).unwrap();
        assert_eq!(mapped["elevated"], true);
        command_request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("elevated".into(), json!(false));
        assert!(verify_exact_action_binding(&device, &command_request, Some(&expires)).is_err());

        let (mut unscoped, unscoped_expires) =
            sample_bound_request(device.as_str(), "a.txt", Some("hello"));
        unscoped.workspace_id = None;
        unscoped
            .authorization
            .as_mut()
            .unwrap()
            .bound_action
            .as_object_mut()
            .unwrap()
            .insert("workspace_id".into(), Value::Null);
        refresh_bound_hash(&mut unscoped);
        assert!(verify_exact_action_binding(&device, &unscoped, Some(&unscoped_expires)).is_err());
        unscoped
            .authorization
            .as_mut()
            .unwrap()
            .bound_action
            .as_object_mut()
            .unwrap()
            .insert("workspace_version".into(), Value::Null);
        refresh_bound_hash(&mut unscoped);
        let unscoped_binding =
            verify_exact_action_binding(&device, &unscoped, Some(&unscoped_expires));
        assert!(unscoped_binding.is_ok(), "{unscoped_binding:?}");
        let unbound_result = bind_remote_result_workspace(json!({ "entries": [] }), &unscoped);
        assert_eq!(unbound_result["workspace_id"], Value::Null);
        assert_eq!(unbound_result["workspace_version"], Value::Null);
        assert!(map_request_to_method(&unscoped).is_err());
        unscoped
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("workspace_id".into(), json!("ws_attacker"));
        assert!(map_request_to_method(&unscoped).is_err());
    }

    #[test]
    fn unbound_system_diagnosis_maps_without_aliasing_a_default_workspace() {
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_diagnose_unbound_1").unwrap(),
            capability: "system.diagnose".into(),
            workspace_id: None,
            idempotency_key: "idem_diagnose_unbound_1".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({ "action": "system.diagnose" }),
        };
        let (method, mapped) = map_request_to_method(&request).unwrap();
        assert_eq!(method, crate::runtime::ops_methods::SYSTEM_DIAGNOSE);
        assert!(mapped.get("workspace_id").is_none());
    }

    #[test]
    fn remote_policy_show_maps_to_read_only_policy_ipc() {
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_policy_show_1").unwrap(),
            capability: "policy.show".into(),
            workspace_id: None,
            idempotency_key: "idem_policy_show_1".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({ "action": "policy.show" }),
        };
        let (method, mapped) = map_request_to_method(&request).unwrap();
        assert_eq!(method, methods::POLICY_SHOW);
        assert!(mapped.get("workspace_id").is_none());
    }

    #[test]
    fn contract_idempotency_cannot_be_replaced_with_an_old_journal_key() {
        let device = DeviceId::parse("dev_idempotency_bound").unwrap();
        let (mut request, _expires) = sample_bound_request(device.as_str(), "a.txt", Some("hello"));
        request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("idempotency_key".into(), json!("old-operation-journal-key"));
        assert!(map_request_to_method(&request).is_err());

        request.arguments.as_object_mut().unwrap().insert(
            "idempotency_key".into(),
            json!(request.idempotency_key.clone()),
        );
        let (_, mapped) = map_request_to_method(&request).unwrap();
        assert_eq!(mapped["idempotency_key"], request.idempotency_key);
    }

    #[test]
    fn exact_action_binding_rejects_argument_tamper() {
        let device = DeviceId::parse("dev_bind_tamper").unwrap();
        let (mut request, expires) = sample_bound_request(device.as_str(), "a.txt", Some("hello"));
        request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("path".into(), json!("evil.txt"));
        let err = verify_exact_action_binding(&device, &request, Some(&expires)).unwrap_err();
        assert!(err.contains("facts"), "{err}");
    }

    #[test]
    fn exact_action_binding_rejects_hash_tamper() {
        let device = DeviceId::parse("dev_bind_hash").unwrap();
        let (mut request, expires) = sample_bound_request(device.as_str(), "a.txt", Some("hello"));
        request.payload_hash = Some("0".repeat(64));
        let err = verify_exact_action_binding(&device, &request, Some(&expires)).unwrap_err();
        assert!(err.contains("payload_hash"), "{err}");
    }

    #[test]
    fn exact_action_binding_rejects_missing_binding_for_side_effect() {
        let device = DeviceId::parse("dev_bind_missing").unwrap();
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_missing").unwrap(),
            capability: "filesystem.write".into(),
            workspace_id: None,
            idempotency_key: "idem_missing".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({ "action": "fs.write", "path": "x" }),
        };
        let err = verify_exact_action_binding(&device, &request, None).unwrap_err();
        assert!(err.contains("authorization"), "{err}");
    }

    #[test]
    fn transfer_start_exact_binding_excludes_only_a_bounded_opaque_ticket() {
        let device = DeviceId::parse("dev_ticket_destination").unwrap();
        let expires = Timestamp::now()
            .checked_add(Duration::from_secs(300))
            .unwrap()
            .to_rfc3339();
        let arguments = json!({
            "action": "transfer.start",
            "ticket": "e30.signature",
            "transfer_id": "xfer_ticket_exact",
            "role": "destination",
            "plan_sha256": "a".repeat(64),
            "content_sha256": "b".repeat(64),
            "size_bytes": 7,
            "source_path": "source.bin",
            "destination_path": "destination.bin",
            "source_device_id": "dev_ticket_source",
            "destination_device_id": device.as_str(),
            "source_workspace_id": "ws_source",
            "destination_workspace_id": "ws_destination",
            "source_workspace_version": 1,
            "destination_workspace_version": 1,
            "workspace_id": "ws_destination",
            "workspace_version": 1,
            "epoch": 1,
            "fence": 1,
            "grant_id": "xfer_ticket_exact",
            "grant_operation_id": "xfer_ticket_exact",
            "grant_payload_sha256": "c".repeat(64),
            "grant_expires_at_unix": 4_102_444_800_u64,
        });
        let mut fact_args = arguments.as_object().unwrap().clone();
        fact_args.remove("ticket");
        let facts = recompute_action_facts(&fact_args).unwrap();
        let bound = json!({
            "capability": "transfer.start",
            "action": "transfer.start",
            "tool": "__transfer_start",
            "device_id": device.as_str(),
            "principal_id": "prin_ticket",
            "tenant_id": "ten_ticket",
            "workspace_id": "ws_destination",
            "workspace_version": 1,
            "claim_version": 1,
            "operation_id": "op_ticket_exact",
            "expires_at": expires,
            "facts": facts,
        });
        let mut request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_ticket_exact").unwrap(),
            capability: "transfer.start".into(),
            workspace_id: Some(ownmesh_domain::WorkspaceId::parse("ws_destination").unwrap()),
            idempotency_key: "idem_ticket_exact".into(),
            payload_hash: Some(sha256_hex_str(&stable_stringify(&bound))),
            authorization: Some(ownmesh_protocol::OperationAuthorizationBinding {
                bound_action: bound,
            }),
            arguments,
        };

        assert!(verify_exact_action_binding(&device, &request, Some(&expires)).is_ok());

        request.arguments.as_object_mut().unwrap().remove("ticket");
        assert!(
            verify_exact_action_binding(&device, &request, Some(&expires))
                .unwrap_err()
                .contains("bounded string ticket")
        );
        request.arguments["ticket"] = json!(7);
        assert!(
            verify_exact_action_binding(&device, &request, Some(&expires))
                .unwrap_err()
                .contains("bounded string ticket")
        );
        request.arguments["ticket"] = json!("x".repeat(MAX_TRANSFER_TICKET_WIRE_BYTES + 1));
        assert!(
            verify_exact_action_binding(&device, &request, Some(&expires))
                .unwrap_err()
                .contains("bounded string ticket")
        );

        // The bearer may change without entering durable/audited facts, but
        // the immediate ticket parser/admission layer still rejects it before
        // runtime admission or ephemeral-key consumption.
        request.arguments["ticket"] = json!("substituted.invalid");
        assert!(verify_exact_action_binding(&device, &request, Some(&expires)).is_ok());
        assert!(parse_transfer_ticket_wire("substituted.invalid").is_err());
    }

    fn sample_bound_cancel(
        device_id: &str,
        target_operation_id: &str,
        expires_skew_secs: i64,
    ) -> (OperationRequestPayload, String) {
        use ownmesh_protocol::OperationAuthorizationBinding;
        let expires = if expires_skew_secs >= 0 {
            Timestamp::now()
                .checked_add(Duration::from_secs(expires_skew_secs as u64))
                .unwrap()
                .to_rfc3339()
        } else {
            Timestamp::now()
                .checked_sub(Duration::from_secs((-expires_skew_secs) as u64))
                .unwrap()
                .to_rfc3339()
        };
        let mut facts = Map::new();
        facts.insert(
            "target_operation_id".into(),
            Value::String(target_operation_id.into()),
        );
        let mut bound = Map::new();
        bound.insert("capability".into(), json!("operation.cancel"));
        bound.insert("action".into(), json!("cancel"));
        bound.insert("tool".into(), json!("ownmesh_cancel_operation"));
        bound.insert("device_id".into(), json!(device_id));
        bound.insert("principal_id".into(), json!("prin_dev"));
        bound.insert("tenant_id".into(), json!("ten_default"));
        bound.insert("oauth_client_id".into(), Value::Null);
        bound.insert("workspace_id".into(), Value::Null);
        bound.insert("facts".into(), Value::Object(facts));
        bound.insert("operation_id".into(), json!("op_cancel_bind"));
        bound.insert("expires_at".into(), json!(expires.clone()));
        bound.insert("claim_version".into(), json!(1));
        let bound_value = Value::Object(bound);
        let hash = sha256_hex_str(&stable_stringify(&bound_value));
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_cancel_bind").unwrap(),
            capability: "operation.cancel".into(),
            workspace_id: None,
            idempotency_key: "idem_cancel_bind".into(),
            payload_hash: Some(hash),
            authorization: Some(OperationAuthorizationBinding {
                bound_action: bound_value,
            }),
            arguments: json!({
                "action": "cancel",
                "target_operation_id": target_operation_id
            }),
        };
        (request, expires)
    }

    #[test]
    fn cancel_binding_accepts_matching_target() {
        let device = DeviceId::parse("dev_cancel_ok").unwrap();
        let (request, expires) = sample_bound_cancel(device.as_str(), "op_target_1", 120);
        assert!(verify_exact_action_binding(&device, &request, Some(&expires)).is_ok());
    }

    #[test]
    fn cancel_binding_rejects_unsigned_cancel() {
        let device = DeviceId::parse("dev_cancel_unsigned").unwrap();
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_cancel_unsigned").unwrap(),
            capability: "operation.cancel".into(),
            workspace_id: None,
            idempotency_key: "idem_cancel_unsigned".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({
                "action": "cancel",
                "target_operation_id": "op_victim"
            }),
        };
        let err = verify_exact_action_binding(&device, &request, None).unwrap_err();
        assert!(err.contains("authorization"), "{err}");
    }

    #[test]
    fn cancel_binding_rejects_mismatched_target() {
        let device = DeviceId::parse("dev_cancel_mismatch").unwrap();
        let (mut request, expires) = sample_bound_cancel(device.as_str(), "op_target_a", 120);
        request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("target_operation_id".into(), json!("op_target_b"));
        let err = verify_exact_action_binding(&device, &request, Some(&expires)).unwrap_err();
        assert!(err.contains("facts"), "{err}");
    }

    #[test]
    fn cancel_binding_rejects_expired_envelope_mismatch() {
        let device = DeviceId::parse("dev_cancel_expired").unwrap();
        let (request, bound_expires) = sample_bound_cancel(device.as_str(), "op_target_exp", -30);
        // Envelope claims a fresh expiry while the bound action is already stale.
        let envelope_expires = Timestamp::now()
            .checked_add(Duration::from_secs(120))
            .unwrap()
            .to_rfc3339();
        let err =
            verify_exact_action_binding(&device, &request, Some(&envelope_expires)).unwrap_err();
        assert!(
            err.contains("expires_at") || err.contains("mismatch"),
            "bound={bound_expires} err={err}"
        );
    }

    fn sample_bound_approval_decision(
        device_id: &str,
        target_operation_id: &str,
        decision: &str,
        target_payload_hash: &str,
    ) -> (OperationRequestPayload, String) {
        use ownmesh_protocol::OperationAuthorizationBinding;
        let expires = Timestamp::now()
            .checked_add(Duration::from_secs(60))
            .unwrap()
            .to_rfc3339();
        let mut facts = Map::new();
        facts.insert(
            "target_operation_id".into(),
            Value::String(target_operation_id.into()),
        );
        facts.insert("decision".into(), Value::String(decision.into()));
        facts.insert("approval_id".into(), json!("apr_test1"));
        facts.insert("target_tool".into(), json!("ownmesh_fs_write"));
        facts.insert(
            "target_payload_hash".into(),
            Value::String(target_payload_hash.into()),
        );
        let mut bound = Map::new();
        bound.insert("capability".into(), json!("approval.decision"));
        bound.insert("action".into(), json!("approval.decision"));
        bound.insert("tool".into(), json!("ownmesh_approval_decision"));
        bound.insert("device_id".into(), json!(device_id));
        bound.insert("principal_id".into(), json!("prin_dev"));
        bound.insert("tenant_id".into(), json!("ten_default"));
        bound.insert("oauth_client_id".into(), Value::Null);
        bound.insert("workspace_id".into(), Value::Null);
        bound.insert("facts".into(), Value::Object(facts));
        bound.insert("operation_id".into(), json!("op_apr_decision"));
        bound.insert("expires_at".into(), json!(expires.clone()));
        bound.insert("claim_version".into(), json!(1));
        let bound_value = Value::Object(bound);
        let hash = sha256_hex_str(&stable_stringify(&bound_value));
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_apr_decision").unwrap(),
            capability: "approval.decision".into(),
            workspace_id: None,
            idempotency_key: "idem_apr_decision".into(),
            payload_hash: Some(hash),
            authorization: Some(OperationAuthorizationBinding {
                bound_action: bound_value,
            }),
            arguments: json!({
                "action": "approval.decision",
                "target_operation_id": target_operation_id,
                "decision": decision,
                "approval_id": "apr_test1",
                "target_tool": "ownmesh_fs_write",
                "target_payload_hash": target_payload_hash,
            }),
        };
        (request, expires)
    }

    #[test]
    fn approval_decision_binding_required_and_accepts_match() {
        let device = DeviceId::parse("dev_apr_ok").unwrap();
        let (request, expires) = sample_bound_approval_decision(
            device.as_str(),
            "op_target_write",
            "approve",
            &"ab".repeat(32),
        );
        assert!(verify_exact_action_binding(&device, &request, Some(&expires)).is_ok());
    }

    #[test]
    fn approval_decision_rejects_unsigned() {
        let device = DeviceId::parse("dev_apr_unsigned").unwrap();
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_apr_unsigned").unwrap(),
            capability: "approval.decision".into(),
            workspace_id: None,
            idempotency_key: "idem_apr_unsigned".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({
                "action": "approval.decision",
                "target_operation_id": "op_victim",
                "decision": "approve",
                "approval_id": "apr_x",
            }),
        };
        let err = verify_exact_action_binding(&device, &request, None).unwrap_err();
        assert!(err.contains("authorization"), "{err}");
    }

    #[test]
    fn approval_decision_rejects_decision_tamper() {
        let device = DeviceId::parse("dev_apr_tamper").unwrap();
        let (mut request, expires) = sample_bound_approval_decision(
            device.as_str(),
            "op_target_write",
            "approve",
            &"cd".repeat(32),
        );
        request
            .arguments
            .as_object_mut()
            .unwrap()
            .insert("decision".into(), json!("deny"));
        let err = verify_exact_action_binding(&device, &request, Some(&expires)).unwrap_err();
        assert!(err.contains("facts"), "{err}");
    }

    #[test]
    fn env_fact_normalizes_and_bounds_entries() {
        let mut args = Map::new();
        args.insert(
            "env".into(),
            json!({
                "B": "two",
                "A": "one"
            }),
        );
        let facts = recompute_action_facts(&args).unwrap();
        let env = facts.get("env").and_then(Value::as_object).unwrap();
        let keys: Vec<&str> = env.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["A", "B"]);

        let mut bad = Map::new();
        bad.insert("env".into(), json!({"BAD=KEY": "x"}));
        assert!(recompute_action_facts(&bad).is_err());
    }

    #[test]
    fn completion_queue_and_inflight_bounds_are_small_and_positive() {
        // Slow WSS consumers must not accumulate unbounded completed results.
        const {
            assert!(MAX_COMPLETION_QUEUE >= 1);
            assert!(MAX_COMPLETION_QUEUE <= 64);
            assert!(MAX_IN_FLIGHT_REMOTE_OPS >= MAX_COMPLETION_QUEUE);
            assert!(MAX_IN_FLIGHT_REMOTE_OPS <= 128);
        }
        // Rough worst-case queued payload budget stays well under prior unbounded risk
        // (1024 × ~700 KiB). Keep the product intentionally small.
        let worst_case_queued_mib = (MAX_IN_FLIGHT_REMOTE_OPS * MAX_PAYLOAD_BYTES) / (1024 * 1024);
        assert!(
            worst_case_queued_mib <= 32,
            "worst_case_mib={worst_case_queued_mib}"
        );
    }

    #[tokio::test]
    async fn bounded_completion_channel_applies_backpressure() {
        let (tx, mut rx) = mpsc::channel::<FinishedRemoteOp>(MAX_COMPLETION_QUEUE);
        // Fill the queue to capacity without a consumer drain.
        for i in 0..MAX_COMPLETION_QUEUE {
            tx.try_send(FinishedRemoteOp {
                completed: CompletedReply {
                    correlation_id: format!("cor_{i}"),
                    operation_id: format!("op_{i}"),
                    payload: json!({ "status": "completed", "i": i }),
                },
            })
            .expect("queue should accept up to capacity");
        }
        assert!(
            tx.try_send(FinishedRemoteOp {
                completed: CompletedReply {
                    correlation_id: "cor_overflow".into(),
                    operation_id: "op_overflow".into(),
                    payload: json!({ "status": "completed" }),
                },
            })
            .is_err(),
            "bounded channel must refuse beyond capacity"
        );

        // Drain one slot; capacity returns without sequence rewind of unread items.
        let first = rx.recv().await.expect("queued item");
        assert_eq!(first.completed.correlation_id, "cor_0");
        tx.try_send(FinishedRemoteOp {
            completed: CompletedReply {
                correlation_id: "cor_after_drain".into(),
                operation_id: "op_after_drain".into(),
                payload: json!({ "status": "completed" }),
            },
        })
        .expect("capacity after drain");

        // Remaining items stay ordered (no rewind/drop of live entries).
        let second = rx.recv().await.expect("second");
        assert_eq!(second.completed.correlation_id, "cor_1");
    }

    #[test]
    fn backpressure_payload_is_retryable_and_bounded() {
        let op = ownmesh_domain::OperationId::parse("op_bp_1").unwrap();
        let payload = agent_backpressure_payload(&op);
        assert_eq!(payload["status"], "failed");
        assert_eq!(payload["error"]["code"], "OWNMESH_E_AGENT_BACKPRESSURE");
        assert_eq!(payload["error"]["retryable"], true);
        assert_eq!(
            payload["error"]["details"]["max_in_flight"],
            MAX_IN_FLIGHT_REMOTE_OPS as u64
        );
        assert_eq!(
            payload["error"]["details"]["max_completion_queue"],
            MAX_COMPLETION_QUEUE as u64
        );
    }

    fn session_attach_request(role: Option<&str>) -> OperationRequestPayload {
        let mut arguments = Map::new();
        arguments.insert("action".into(), json!("session.attach"));
        arguments.insert("session_id".into(), json!("ses_test1"));
        if let Some(role) = role {
            arguments.insert("role".into(), json!(role));
        }
        OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_ses_attach_1").unwrap(),
            capability: "session.attach".into(),
            workspace_id: None,
            idempotency_key: "idem_ses_attach".into(),
            payload_hash: None,
            authorization: None,
            arguments: Value::Object(arguments),
        }
    }

    #[test]
    fn session_attach_observer_maps_to_read_only_true() {
        let (method, args) =
            map_request_to_method(&session_attach_request(Some("observer"))).unwrap();
        assert_eq!(method, crate::runtime::session_methods::ATTACH);
        assert_eq!(args.get("read_only"), Some(&Value::Bool(true)));
        assert_eq!(args.get("id"), Some(&json!("ses_test1")));
    }

    #[test]
    fn session_attach_controller_maps_to_read_only_false() {
        let (method, args) =
            map_request_to_method(&session_attach_request(Some("controller"))).unwrap();
        assert_eq!(method, crate::runtime::session_methods::ATTACH);
        assert_eq!(args.get("read_only"), Some(&Value::Bool(false)));
    }

    #[test]
    fn session_attach_missing_role_fail_closed() {
        let err = map_request_to_method(&session_attach_request(None)).unwrap_err();
        assert!(err.contains("role"), "{err}");
    }

    #[test]
    fn session_attach_invalid_role_fail_closed() {
        let err = map_request_to_method(&session_attach_request(Some("admin"))).unwrap_err();
        assert!(err.contains("observer|controller"), "{err}");
    }

    #[test]
    fn session_renew_and_detach_map_to_exact_lease_methods() {
        for (action, capability, expected) in [
            (
                "session.renew",
                "session.renew",
                crate::runtime::session_methods::RENEW,
            ),
            (
                "session.detach",
                "session.detach",
                crate::runtime::session_methods::DETACH,
            ),
        ] {
            let mut arguments = Map::new();
            arguments.insert("action".into(), json!(action));
            arguments.insert("session_id".into(), json!("ses_test1"));
            arguments.insert("lease_id".into(), json!("lease_exact"));
            arguments.insert("controller_epoch".into(), json!(2));
            if action == "session.renew" {
                arguments.insert("ttl_secs".into(), json!(60));
            }
            let request = OperationRequestPayload {
                operation_contract: ownmesh_protocol::OperationContract::V1,
                operation_id: ownmesh_domain::OperationId::parse("op_ses_lease_1").unwrap(),
                capability: capability.into(),
                workspace_id: None,
                idempotency_key: "idem_ses_lease".into(),
                payload_hash: None,
                authorization: None,
                arguments: Value::Object(arguments),
            };
            let (method, args) = map_request_to_method(&request).unwrap();
            assert_eq!(method, expected);
            assert_eq!(args.get("id"), Some(&json!("ses_test1")));
            assert_eq!(args.get("lease_id"), Some(&json!("lease_exact")));
            assert_eq!(args.get("controller_epoch"), Some(&json!(2)));
        }
    }

    #[test]
    fn internal_transfer_preflight_maps_but_normal_transfer_peer_authority_is_rejected() {
        let request = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_preflight_1").unwrap(),
            capability: "transfer.preflight_source".into(),
            workspace_id: Some(ownmesh_domain::WorkspaceId::parse("ws_source").unwrap()),
            idempotency_key: "idem_preflight_1".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({
                "action": "preflight_source",
                "tenant_id": "ten_1",
                "source_device_id": "dev_source",
                "destination_device_id": "dev_destination"
            }),
        };
        let (method, args) = map_request_to_method(&request).unwrap();
        assert_eq!(method, methods::TRANSFER_PREFLIGHT_SOURCE);
        assert_eq!(args["destination_device_id"], json!("dev_destination"));
        assert!(args.get("idempotency_key").is_none());

        let mut mismatched_preflight = request.clone();
        mismatched_preflight.arguments["idempotency_key"] = json!("other-contract");
        assert!(map_request_to_method(&mismatched_preflight)
            .unwrap_err()
            .contains("differs from operation contract"));

        let artifact = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_artifact_get_1").unwrap(),
            capability: "transfer.artifact_get".into(),
            workspace_id: Some(ownmesh_domain::WorkspaceId::parse("ws_destination").unwrap()),
            idempotency_key: "idem_artifact_get_1".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({
                "action": "artifact_get",
                "plan_id": "plan_destination",
                "offset": 0,
                "max_bytes": 32768,
            }),
        };
        let (method, args) = map_request_to_method(&artifact).unwrap();
        assert_eq!(method, methods::TRANSFER_ARTIFACT_GET);
        assert_eq!(args["workspace_id"], json!("ws_destination"));
        assert!(args.get("idempotency_key").is_none());
        let mut mismatched_artifact = artifact;
        mismatched_artifact.arguments["idempotency_key"] = json!("other-contract");
        assert!(map_request_to_method(&mismatched_artifact)
            .unwrap_err()
            .contains("differs from operation contract"));

        let cleanup = OperationRequestPayload {
            operation_contract: ownmesh_protocol::OperationContract::V1,
            operation_id: ownmesh_domain::OperationId::parse("op_source_cleanup_1").unwrap(),
            capability: "transfer.source_cleanup".into(),
            workspace_id: Some(ownmesh_domain::WorkspaceId::parse("ws_source").unwrap()),
            idempotency_key: "idem_source_cleanup_1".into(),
            payload_hash: None,
            authorization: None,
            arguments: json!({
                "action": "source_cleanup",
                "plan_id": "xfer_source_plan",
                "epoch": 2,
                "fence": 2,
            }),
        };
        let (method, args) = map_request_to_method(&cleanup).unwrap();
        assert_eq!(method, methods::TRANSFER_CANCEL);
        assert_eq!(
            args,
            json!({"plan_id":"xfer_source_plan","epoch":2,"fence":2})
        );

        let mut normal = request;
        normal.capability = "transfer.plan".into();
        normal.arguments["action"] = json!("plan");
        let error = map_request_to_method(&normal).unwrap_err();
        assert!(
            error.contains("tenant_id") || error.contains("destination_device_id"),
            "{error}"
        );

        // The private start envelope is already exact-action-bound before this
        // mapper is reached.  It must preserve the server-derived plan facts
        // for the local runtime, unlike every public transfer surface above.
        let mut start = normal;
        start.capability = "transfer.start".into();
        start.arguments = json!({
            "action": "transfer.start",
            "transfer_id": "xfer_start_1",
            "ticket": "opaque-ticket",
            "role": "source",
            "tenant_id": "ten_1",
            "source_device_id": "dev_source",
            "destination_device_id": "dev_destination",
            "grant_id": "xfer_start_1",
            "grant_expires_at_unix": 4_102_444_800_u64,
        });
        start.authorization = Some(ownmesh_protocol::OperationAuthorizationBinding {
            bound_action: json!({"exact": "server-bound action"}),
        });
        let (method, args) = map_request_to_method(&start).unwrap();
        assert_eq!(method, "transfer.start");
        assert_eq!(args["source_device_id"], json!("dev_source"));
        assert_eq!(args["grant_id"], json!("xfer_start_1"));
        assert!(args.get("idempotency_key").is_none());

        start.authorization = None;
        let error = map_request_to_method(&start).unwrap_err();
        assert!(
            error.contains("tenant_id") || error.contains("source_device_id"),
            "{error}"
        );
    }

    #[test]
    fn transfer_start_receipt_rejects_cross_ticket_substitution_and_emits_exact_destination_contract(
    ) {
        let mut ticket: AgentTransferTicket = serde_json::from_value(json!({
            "v": 1,
            "jti": "jti_1", "session_nonce": "session_1",
            "transfer_id": "xfer_expected", "tenant_id": "ten_1", "principal_id": "prin_1",
            "device_id": "dev_destination", "role": "destination",
            "source_device_id": "dev_source", "destination_device_id": "dev_destination",
            "source_workspace_id": "ws_source", "destination_workspace_id": "ws_destination",
            "plan_sha256": "a".repeat(64), "epoch": 1, "fence": 9, "max_bytes": 7,
            "ticket_exp": u64::MAX, "transfer_expires_at": u64::MAX,
            "source_device_public_key": "00".repeat(32), "destination_device_public_key": "00".repeat(32),
            "source_ephemeral_public_key": "00".repeat(32), "destination_ephemeral_public_key": "00".repeat(32),
            "source_ephemeral_signature": "00".repeat(64), "destination_ephemeral_signature": "00".repeat(64)
        }))
        .unwrap();
        let admission = json!({"transfer_id":"xfer_expected","plan_id":"plan_1","role":"destination","plan_sha256":"a".repeat(64),"epoch":1,"fence":9,"admitted":true});
        let publication =
            json!({"plan_id":"plan_1","published":true,"size_bytes":7,"sha256":"b".repeat(64)});
        let result = transfer_start_result(
            &admission,
            &ticket,
            true,
            Some(&publication),
            Some(&"b".repeat(64)),
        )
        .unwrap();
        assert_eq!(
            result,
            json!({"transfer_id":"xfer_expected","plan_id":"plan_1","role":"destination","plan_sha256":"a".repeat(64),"epoch":1,"fence":9,"admitted":true,"completed":true,"published":true,"artifact_sha256":"b".repeat(64)})
        );

        // A valid-looking ticket for a different transfer cannot attach to
        // this same-content admission and cannot produce a durable receipt.
        ticket.transfer_id = "xfer_substituted".into();
        assert!(transfer_start_result(
            &admission,
            &ticket,
            true,
            Some(&publication),
            Some(&"b".repeat(64)),
        )
        .is_err());
    }

    #[tokio::test]
    async fn preflight_proof_is_stable_for_retry_and_private_key_stays_memory_only() {
        let key = DeviceKeyPair::generate();
        let cache = Arc::new(Mutex::new(HashMap::new()));
        let body = json!({
            "role": "source",
            "transfer_id": "xfer_preflight",
            "tenant_id": "ten_1",
            "principal_id": "prin_1",
            "device_id": "dev_source",
            "workspace_id": "ws_source",
            "plan_sha256": "a".repeat(64),
            "epoch": 1,
            "fence": 1,
            "session_nonce": "nonce_1",
            "expires_at": (SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64) + 30_000,
            "coordinator_request_id": "coord_1",
            "workspace_version": 1,
            "plan_id": "xfer_local_preflight",
            "sha256": "b".repeat(64),
            "size_bytes": 1,
        });
        let first = signed_transfer_preflight_result(&body, "op_preflight", &key, &cache)
            .await
            .unwrap();
        let second = signed_transfer_preflight_result(&body, "op_preflight", &key, &cache)
            .await
            .unwrap();
        assert_eq!(
            first["transfer_preflight"]["ephemeral_public_key"],
            second["transfer_preflight"]["ephemeral_public_key"]
        );
        assert_eq!(cache.lock().await.len(), 1);
        let proof = canonical_ephemeral_proof(
            "xfer_preflight",
            "ten_1",
            "source",
            "dev_source",
            "ws_source",
            &"a".repeat(64),
            1,
            1,
            "nonce_1",
            first["transfer_preflight"]["ephemeral_public_key"]
                .as_str()
                .unwrap(),
            first["transfer_preflight"]["expires_at"].as_u64().unwrap(),
        )
        .unwrap();
        ownmesh_identity::verify_from_public_key_hex(
            &key.public_identity().public_key_hex,
            &proof,
            first["transfer_preflight"]["ephemeral_signature"]
                .as_str()
                .unwrap(),
        )
        .unwrap();
        assert!(!serde_json::to_string(&first).unwrap().contains("private"));
    }
}
#[test]
fn transfer_failure_classification_only_retries_connection_loss() {
    assert_eq!(
        classify_transfer_failure("transfer socket closed; fresh ticket required for reconnect"),
        TransferSessionFailure::Reconnect
    );
    assert_eq!(
        classify_transfer_failure("transfer socket ACK timeout"),
        TransferSessionFailure::Reconnect
    );
    assert_eq!(
        classify_transfer_failure("transfer cancelled"),
        TransferSessionFailure::Cancelled
    );
    assert_eq!(
        classify_transfer_failure("remote error: transfer lease is held by another owner"),
        TransferSessionFailure::Reconnect
    );
    assert_eq!(
        classify_transfer_failure("remote error: journal lease or fence is stale"),
        TransferSessionFailure::Reconnect
    );
    assert_eq!(
        classify_transfer_failure("source cleanup pending"),
        TransferSessionFailure::Reconnect
    );
    assert_eq!(
        classify_transfer_failure("transfer peer unavailable; fresh ticket required for reconnect"),
        TransferSessionFailure::Reconnect
    );
    for terminal in [
        "transfer frame binding mismatch",
        "chunk hash mismatch",
        "destination durable cursor differs from transfer room",
        "source ended before immutable transfer size",
    ] {
        assert_eq!(
            classify_transfer_failure(terminal),
            TransferSessionFailure::Terminal
        );
    }
}

#[test]
fn only_exact_room_peer_unavailable_errors_request_reconnect() {
    for code in ["destination_offline", "peer_unavailable"] {
        let frame = json!({
            "protocol": "ownmesh.transfer/1.0",
            "type": "error",
            "code": code,
        });
        assert!(transfer_room_reconnect_signal(frame.as_object().unwrap()));
    }
    for terminal in [
        json!({"protocol":"ownmesh.transfer/1.0","type":"error","code":"binding_mismatch"}),
        json!({"protocol":"ownmesh.transfer/1.0","type":"error","code":"non_contiguous_or_busy"}),
        json!({"protocol":"ownmesh.transfer/1.0","type":"error","code":"destination_offline","detail":"extra"}),
        json!({"protocol":"wrong","type":"error","code":"destination_offline"}),
    ] {
        assert!(!transfer_room_reconnect_signal(
            terminal.as_object().unwrap()
        ));
    }
}
