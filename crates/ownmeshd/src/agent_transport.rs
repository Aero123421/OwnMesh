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
use tokio::sync::{mpsc, watch, Mutex};
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
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const MAX_PAYLOAD_BYTES: usize = 1_000_000;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(30);
const MAX_RECONNECT_DELAY: Duration = Duration::from_secs(30);

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
        Ok(state)
    }

    fn save(&self, path: &Path) -> Result<(), String> {
        let mut bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| format!("serialize transport state: {error}"))?;
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
        self.completed_replies
            .retain(|candidate| candidate.correlation_id != reply.correlation_id);
        self.completed_replies.push_back(reply);
        trim_front(&mut self.completed_replies, MAX_COMPLETED_REPLIES);
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
    let (finish_tx, mut finish_rx) = mpsc::unbounded_channel::<FinishedRemoteOp>();

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
        Message::Close(_) => Err("control plane closed the WebSocket".into()),
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
    finish_tx: &mpsc::UnboundedSender<FinishedRemoteOp>,
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
            // without waiting for that op's runtime lock.
            let action = action_of(&request);
            if request.capability == "operation.cancel"
                || action == "cancel"
                || action == "ownmesh_cancel_operation"
            {
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

            // Register cancel before spawn so a concurrent cancel cannot miss the
            // window between accept and dispatch start.
            let operation_id = request.operation_id.to_string();
            let cancel_rx = cancel_registry.register(&operation_id).await;
            let correlation_owned = correlation.to_owned();
            let cancel_registry = Arc::clone(cancel_registry);
            let finish_tx = finish_tx.clone();
            let device_id = config.device_id.clone();
            tokio::spawn(async move {
                let payload = dispatch_remote_operation(
                    &runtime,
                    &device_id,
                    &request,
                    &cancel_registry,
                    Some(cancel_rx),
                )
                .await;
                cancel_registry.forget(&operation_id).await;
                let _ = finish_tx.send(FinishedRemoteOp {
                    completed: CompletedReply {
                        correlation_id: correlation_owned,
                        operation_id,
                        payload,
                    },
                });
            });
            Ok(())
        }
        "error" => Err("control plane returned an Agent protocol error".into()),
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
    cancel_registry: &CancelRegistry,
    cancel_rx: Option<watch::Receiver<bool>>,
) -> Value {
    let operation_id = request.operation_id.to_string();
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
}
