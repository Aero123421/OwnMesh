//! Authenticated control-plane WebSocket transport for the device Agent.
//!
//! E2 connects validated `operation.request` envelopes to the shared
//! policy-gated [`DaemonRuntime`]. Without a runtime handle the transport stays
//! fail-closed (`remote_routing_enabled: false`).

use crate::runtime::DaemonRuntime;
use futures_util::{SinkExt, StreamExt};
use ownmesh_config::{atomic_write, OwnMeshConfig, OwnMeshPaths};
use ownmesh_domain::{DeviceId, MessageId, Timestamp};
use ownmesh_identity::{
    load_device_credential, load_or_create_device_key, DeviceKeyPair, PreferredSecretStore,
    SecretString, DEFAULT_KEYCHAIN_SERVICE,
};
use ownmesh_ipc::{methods, ClientIdentity};
use ownmesh_protocol::{
    Envelope, OperationEnvelope, OperationPayload, OperationRequestPayload, OPERATION_CONTRACT_V1,
    PROTOCOL_DEVICE_V1,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
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

type AgentSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Fully bound transport inputs. Secret-bearing fields intentionally have no
/// `Debug` implementation.
pub struct AgentTransportConfig {
    issuer: String,
    ws_url: Url,
    origin: String,
    device_id: DeviceId,
    credential: SecretString,
    key: DeviceKeyPair,
    state_path: PathBuf,
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
        key,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CompletedReply {
    correlation_id: String,
    operation_id: String,
    payload: Value,
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
        }
    }

    fn load(path: &Path, issuer: &str, device_id: &DeviceId) -> Result<Self, String> {
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
        let compact = compact_completed_reply(reply);
        self.completed_replies
            .retain(|candidate| candidate.correlation_id != compact.correlation_id);
        self.completed_replies.push_back(compact);
        trim_front(&mut self.completed_replies, MAX_COMPLETED_REPLIES);
        self.enforce_completed_reply_budgets();
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
    let mut attempt = 0_u32;
    loop {
        if *shutdown.borrow() {
            return;
        }
        match connect_and_run(&config, runtime.as_ref(), &mut state, &mut shutdown).await {
            Ok(()) => return,
            Err(error) => {
                tracing::warn!(
                    issuer = %ownmesh_config::redact_control_plane_url(&config.issuer),
                    error = %error,
                    "Agent WebSocket disconnected; reconnecting"
                );
            }
        }
        attempt = attempt.saturating_add(1).min(10);
        let shift = attempt.min(5);
        let delay = Duration::from_secs(1_u64 << shift).min(MAX_RECONNECT_DELAY);
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

    perform_handshake(&mut socket, config, state, runtime.is_some()).await?;
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
    remote_routing_enabled: bool,
) -> Result<(), String> {
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
    send_envelope(
        socket,
        config,
        state,
        "ready",
        json!({
            "capabilities": capabilities,
            "operation_contracts": [OPERATION_CONTRACT_V1],
            "remote_routing_enabled": remote_routing_enabled,
        }),
        None,
    )
    .await?;
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
            let Some(raw) = raw else {
                return Ok(());
            };
            let operation =
                OperationEnvelope::parse_str(&raw).map_err(|error| error.to_string())?;
            operation
                .envelope
                .validate_expiry_now()
                .map_err(|error| error.to_string())?;
            let OperationPayload::Request(request) = operation.payload else {
                return Err("operation.request parsed as a different payload type".into());
            };

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

            // Register cancel before spawn so a concurrent cancel cannot miss the
            // window between accept and dispatch start.
            let operation_id = request.operation_id.to_string();
            let cancel_rx = cancel_registry.register(&operation_id).await;
            let correlation_owned = correlation.to_owned();
            let cancel_registry = Arc::clone(cancel_registry);
            let finish_tx = finish_tx.clone();
            let device_id = config.device_id.clone();
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
                    &request,
                    envelope_expires_at.as_deref(),
                    &cancel_registry,
                    Some(cancel_rx),
                )
                .await;
                cancel_registry.forget(&operation_id).await;
                let completed = CompletedReply {
                    correlation_id: correlation_owned,
                    operation_id,
                    payload,
                };
                // Backpressure: wait for the live loop to drain rather than drop
                // or grow an unbounded queue while the WebSocket consumer is slow.
                let _ = finish_tx.send(FinishedRemoteOp { completed }).await;
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
                | "decision"
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
        // Cancel is a live control plane action: binding is mandatory so an
        // unauthenticated/unsigned cancel cannot signal process trees.
        // approval.decision remains an optional recovery notification only.
        let action = action_of(request);
        if request.capability == "approval.decision" || action == "approval.decision" {
            return Ok(());
        }
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

    // Recompute action facts from the live arguments and require exact match.
    let args = args_object(request);
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

fn remote_agent_client(device_id: &DeviceId) -> ClientIdentity {
    // Remote MCP ops are authenticated by the device credential on the control
    // plane hop. Local side effects run as this daemon-bound remote principal;
    // never trust client-supplied principal/policy fields from the payload.
    ClientIdentity::new(
        format!("client:remote-agent:{}", device_id.as_str()),
        env!("CARGO_PKG_VERSION"),
    )
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
    strip_control_fields(&mut args);

    // Cancel targets another operation; it does not re-run a side effect.
    if request.capability == "operation.cancel"
        || action == "cancel"
        || action == "ownmesh_cancel_operation"
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
            // Hash-checked whole-file replacement (bounded unified-diff is E7).
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
        // Accept short fixture-style capability names used by the E0 contract samples.
        ("fs.read", _) => methods::OPS_FS_READ,
        ("fs.write", _) => methods::OPS_FS_WRITE,
        ("fs.list", _) => methods::OPS_FS_LIST,
        (other_cap, other_action) => {
            return Err(format!(
                "unsupported remote capability '{other_cap}' action '{other_action}'"
            ));
        }
    };

    // Bind server-side idempotency to the operation contract key when the caller
    // did not supply one inside arguments.
    if !args.contains_key("idempotency_key") {
        args.insert(
            "idempotency_key".into(),
            Value::String(request.idempotency_key.clone()),
        );
    }
    Ok((method, Value::Object(args)))
}

fn bound_result_object(value: Value) -> Value {
    // Keep Agent → DeviceRoom envelopes inside the 1_000_000-byte frame budget.
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
    json!({
        "truncated": true,
        "returned_bytes": 0,
        "total_bytes": serialized.len(),
        "message": "operation result exceeded the Agent envelope budget; request a smaller range or use pagination",
        "preview": String::from_utf8_lossy(&serialized[..MAX_RESULT_JSON_BYTES.min(256)]).into_owned(),
    })
}

async fn dispatch_remote_operation(
    runtime: &Arc<Mutex<DaemonRuntime>>,
    device_id: &DeviceId,
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
        return json!({
            "operation_contract": OPERATION_CONTRACT_V1,
            "operation_id": operation_id,
            "status": "completed",
            "result": {
                "approval_decision_received": true,
                "decision": mapped.1.get("decision").cloned().unwrap_or(Value::Null),
                "approval_id": mapped.1.get("approval_id").cloned().unwrap_or(Value::Null),
                "note": "device acknowledged control-plane approval decision; local policy/grants remain authoritative"
            }
        });
    }

    let client = remote_agent_client(device_id);
    let outcome = {
        let mut guard = runtime.lock().await;
        guard
            .dispatch_cancellable(mapped.0, Some(mapped.1), &client, cancel_rx)
            .await
    };

    match outcome {
        Ok(body) => {
            // Runtime may surface policy ask without executing.
            if body.get("approval_required") == Some(&Value::Bool(true)) {
                return json!({
                    "operation_contract": OPERATION_CONTRACT_V1,
                    "operation_id": body.get("operation_id").cloned().unwrap_or_else(|| Value::String(operation_id.clone())),
                    "status": "failed",
                    "error": {
                        "code": "OWNMESH_E_APPROVAL_REQUIRED",
                        "message": body.get("reason").and_then(Value::as_str).unwrap_or("device policy requires local approval"),
                        "retryable": false,
                        "details": {
                            "approval_required": true,
                            "approval_id": body.get("approval_id").cloned(),
                            "reason": body.get("reason").cloned(),
                            "note": "ChatGPT confirmation is not an OwnMesh cryptographic attestation; local policy still requires an approved device grant when configured to ask"
                        }
                    }
                });
            }
            let result = body.get("result").cloned().unwrap_or(body);
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
            key: DeviceKeyPair::generate(),
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
            key,
            state_path: dir.path().join("transport.json"),
        };

        let server_device = device.clone();
        let server_origin = issuer.clone();
        let server_credential = credential.to_owned();
        let server = tokio::spawn(async move {
            let mut server_seq = 0_u64;
            let mut first_result: Option<Envelope> = None;
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
                    assert_eq!(hello.payload["resume"]["last_server_seq"].as_u64(), Some(4));
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
                assert_eq!(ready.payload["remote_routing_enabled"], Value::Bool(false));

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
                    "OWNMESH_E_UNSUPPORTED_SURFACE"
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

        let mut state = AgentTransportState::fresh(&config.issuer, &config.device_id);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let mut first_shutdown = shutdown_rx.clone();
        assert!(
            connect_and_run(&config, None, &mut state, &mut first_shutdown)
                .await
                .is_err()
        );
        let mut second_shutdown = shutdown_rx;
        assert!(
            connect_and_run(&config, None, &mut state, &mut second_shutdown)
                .await
                .is_err()
        );
        server.await.unwrap();

        let persisted =
            AgentTransportState::load(&config.state_path, &config.issuer, &config.device_id)
                .unwrap();
        assert_eq!(persisted.last_server_seq, 8);
        assert_eq!(persisted.completed_replies.len(), 1);
        assert_eq!(persisted.completed_replies[0].correlation_id, "op_loopback");
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
        bound.insert("workspace_id".into(), Value::Null);
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
            workspace_id: None,
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
}
