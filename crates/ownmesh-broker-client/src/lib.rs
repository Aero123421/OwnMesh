//! `OwnMesh` client library for the privileged broker.
//!
//! Request MACs use a shared [`BrokerSecret`]. Capability tokens are **asymmetric**:
//! only the broker holds [`CapabilitySigningKey`]; clients hold [`CapabilityVerifyKey`]
//! (or none) and cannot mint valid capabilities from the request-MAC secret alone.
//!
//! Capability claims bind OS peer identity (pid / uid / executable path) so
//! authorization does not rely on a self-asserted `caller_principal` string.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::single_match_else,
    clippy::redundant_closure_for_method_calls,
    clippy::case_sensitive_file_extension_comparisons,
    clippy::needless_borrows_for_generic_args,
    clippy::cast_possible_wrap,
    clippy::struct_excessive_bools
)]

mod transport;

pub use transport::{
    broker_endpoint_display, build_cancel_intent_v2, connect_and_call, connect_and_cancel_v2,
    connect_and_execute_v2, connect_and_execute_v2_cancellable, default_broker_endpoint,
    is_loopback_socket_addr, resolve_broker_endpoint, BrokerEndpoint, BrokerV2ClientError,
    BrokerV2ClientResult, PeerCred, TransportKind, V2TimeoutPhase,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

type HmacSha256 = Hmac<Sha256>;

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Crate version string from Cargo package metadata.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Protocol version.
pub const BROKER_PROTOCOL_VERSION: u32 = 1;

/// Production broker wire protocol.  Version 1 remains available only for
/// compatibility with the pre-E8 in-process test helpers; it is never a
/// substitute for this exact-action protocol.
pub const BROKER_PROTOCOL_V2: u32 = 2;

/// Hard byte ceiling for one JSON broker request before deserialization.
pub const MAX_BROKER_REQUEST_BYTES: usize = 64 * 1024;
/// Bounded cardinality ceilings for an exact structured command.
pub const MAX_BROKER_ARGV: usize = 128;
pub const MAX_BROKER_ENV: usize = 64;
pub const MAX_BROKER_FIELD_BYTES: usize = 4096;
/// Maximum exact action limits accepted by protocol v2.
pub const MAX_BROKER_TIMEOUT_MS: u64 = 300_000;
pub const MAX_BROKER_OUTPUT_BYTES: usize = 1_000_000;
/// Hard byte ceiling for one v2 JSON broker response, including both bounded
/// output streams and envelope overhead.
pub const MAX_BROKER_RESPONSE_BYTES: usize = (2 * MAX_BROKER_OUTPUT_BYTES) + (16 * 1024);

/// Default local endpoint basename (pipe / socket).
pub const DEFAULT_BROKER_ENDPOINT: &str = "ownmesh-privileged";

/// Capability token lifetime default (seconds).
pub const DEFAULT_CAPABILITY_TTL_SECS: i64 = 300;

/// Scope value required on every elevated-exec capability token.
pub const ELEVATED_CAPABILITY_SCOPE: &str = "elevated.exec";

/// Domain separation tag for request MAC payload.
const REQUEST_MAC_DOMAIN: &[u8] = b"ownmesh-broker-req-mac-v1";

/// Domain separation tag for capability signature payload.
const CAPABILITY_SIG_DOMAIN: &[u8] = b"ownmesh-broker-cap-ed25519-v1";
const REQUEST_V2_MAC_DOMAIN: &[u8] = b"ownmesh-broker-req-mac-v2";
const CAPABILITY_V2_SIG_DOMAIN: &[u8] = b"ownmesh-broker-cap-ed25519-v2";
const OPERATION_FACTS_V2_DOMAIN: &[u8] = b"ownmesh-broker-operation-facts-v2";

/// Broker client errors.
#[derive(Debug, Error)]
pub enum BrokerError {
    #[error("invalid token")]
    InvalidToken,
    #[error("expired request")]
    Expired,
    #[error("replay detected")]
    Replay,
    #[error("signature mismatch")]
    BadSignature,
    #[error("unauthorized caller")]
    Unauthorized,
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("io: {0}")]
    Io(String),
    #[error("networkless violation: {0}")]
    Networkless(String),
}

pub type BrokerResult<T> = Result<T, BrokerError>;

/// Shared secret material for **request MAC only** (not capability minting).
///
/// Stored where ownmeshd can read it. Capability signing keys must never be
/// derived from or colocated with this secret in a way that grants mint rights.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct BrokerSecret {
    bytes: Vec<u8>,
}

impl BrokerSecret {
    #[must_use]
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn generate() -> Self {
        let mut bytes = vec![0u8; 32];
        let u = Uuid::new_v4();
        let t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut h = Sha256::new();
        h.update(u.as_bytes());
        h.update(t.to_le_bytes());
        h.update(b"ownmesh-broker-secret-v1");
        bytes.copy_from_slice(&h.finalize());
        Self { bytes }
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Broker-only Ed25519 signing key used to mint capability tokens.
///
/// Must not be readable by ownmeshd (separate file / privileges from [`BrokerSecret`]).
#[derive(Clone, ZeroizeOnDrop)]
pub struct CapabilitySigningKey {
    #[zeroize(skip)]
    key: SigningKey,
}

impl CapabilitySigningKey {
    /// Generate a fresh capability signing key (broker install / first run).
    #[must_use]
    pub fn generate() -> Self {
        Self {
            key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Reconstruct from a 32-byte seed.
    pub fn from_bytes(bytes: &[u8]) -> BrokerResult<Self> {
        if bytes.len() != 32 {
            return Err(BrokerError::Protocol(format!(
                "capability signing key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(bytes);
        Ok(Self {
            key: SigningKey::from_bytes(&seed),
        })
    }

    /// Raw 32-byte seed (secret).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    /// Corresponding verify key (safe to distribute to clients).
    #[must_use]
    pub fn verify_key(&self) -> CapabilityVerifyKey {
        CapabilityVerifyKey {
            key: self.key.verifying_key(),
        }
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.key.sign(message).to_bytes()
    }
}

impl std::fmt::Debug for CapabilitySigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CapabilitySigningKey([redacted])")
    }
}

/// Public half of the capability key pair (verify-only; cannot mint).
#[derive(Clone)]
pub struct CapabilityVerifyKey {
    key: VerifyingKey,
}

impl CapabilityVerifyKey {
    /// Reconstruct from a 32-byte compressed public key.
    pub fn from_bytes(bytes: &[u8]) -> BrokerResult<Self> {
        if bytes.len() != 32 {
            return Err(BrokerError::Protocol(format!(
                "capability verify key must be 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(bytes);
        let key = VerifyingKey::from_bytes(&pk)
            .map_err(|e| BrokerError::Protocol(format!("invalid capability verify key: {e}")))?;
        Ok(Self { key })
    }

    /// Raw 32-byte public key.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    fn verify(&self, message: &[u8], signature: &[u8]) -> BrokerResult<()> {
        if signature.len() != 64 {
            return Err(BrokerError::BadSignature);
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = Signature::from_bytes(&sig_bytes);
        self.key
            .verify(message, &sig)
            .map_err(|_| BrokerError::BadSignature)
    }
}

impl std::fmt::Debug for CapabilityVerifyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CapabilityVerifyKey")
            .field("public_key_hex", &hex::encode(self.to_bytes()))
            .finish()
    }
}

impl PartialEq for CapabilityVerifyKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for CapabilityVerifyKey {}

/// OS peer identity claims bound into a capability token.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct PeerBind {
    pub pid: i32,
    pub uid: u32,
    /// Absolute executable path when the OS exposes it; empty when unavailable.
    #[serde(default)]
    pub exe_path: String,
}

impl PeerBind {
    #[must_use]
    pub fn new(pid: i32, uid: u32, exe_path: impl Into<String>) -> Self {
        Self {
            pid,
            uid,
            exe_path: exe_path.into(),
        }
    }

    /// Build from socket peer credentials plus optional resolved exe path.
    #[must_use]
    pub fn from_peer_cred(cred: &PeerCred, exe_path: impl Into<String>) -> Self {
        Self {
            pid: cred.pid,
            uid: cred.uid,
            exe_path: exe_path.into(),
        }
    }

    /// True only when pid, uid, and a non-empty executable path all match exactly.
    ///
    /// Missing executable identity is never a wildcard: privileged authorization
    /// must fail closed when the OS cannot resolve either side of the binding.
    #[must_use]
    pub fn matches(&self, other: &PeerBind) -> bool {
        self.pid > 0
            && other.pid > 0
            && self.pid == other.pid
            && self.uid == other.uid
            && !self.exe_path.trim().is_empty()
            && !other.exe_path.trim().is_empty()
            && paths_equivalent(&self.exe_path, &other.exe_path)
    }
}

fn paths_equivalent(a: &str, b: &str) -> bool {
    #[cfg(windows)]
    {
        // Windows production serving is unsupported, but token verification keeps
        // conventional case-insensitive path comparison for portable tests.
        a.replace('\\', "/")
            .eq_ignore_ascii_case(&b.replace('\\', "/"))
    }
    #[cfg(not(windows))]
    {
        // Linux executable paths are canonicalized before binding. Backslash is a
        // valid filename byte, so no separator rewriting or fuzzy matching is safe.
        a == b
    }
}

/// Capability token bound to peer OS identity, scope, and operation (Ed25519 over claims).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    pub token_id: String,
    /// Informational label only — never sufficient for authorization by itself.
    pub principal: String,
    pub scope: String,
    /// Operation this token is authorized to invoke (bound at issue time).
    #[serde(default)]
    pub operation_id: String,
    /// OS peer pid bound at mint time.
    #[serde(default)]
    pub peer_pid: i32,
    /// OS peer uid bound at mint time.
    #[serde(default)]
    pub peer_uid: u32,
    /// OS peer executable path bound at mint time (may be empty).
    #[serde(default)]
    pub peer_exe: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    /// hex-encoded Ed25519 signature over typed canonical claims.
    pub signature: String,
}

impl CapabilityToken {
    /// Peer bind claims embedded in this token.
    #[must_use]
    pub fn peer_bind(&self) -> PeerBind {
        PeerBind {
            pid: self.peer_pid,
            uid: self.peer_uid,
            exe_path: self.peer_exe.clone(),
        }
    }

    /// Issue a capability token (broker-only; requires signing key).
    ///
    /// Prefer [`Self::issue_for_operation`] so the token is bound to a concrete operation.
    #[must_use]
    pub fn issue(
        signing_key: &CapabilitySigningKey,
        peer: &PeerBind,
        principal: impl Into<String>,
        scope: impl Into<String>,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Self {
        Self::issue_for_operation(
            signing_key,
            peer,
            principal,
            scope,
            String::new(),
            now_unix,
            ttl_secs,
        )
    }

    /// Issue a capability token bound to peer OS identity, `scope`, and `operation_id`.
    ///
    /// Only holders of [`CapabilitySigningKey`] can produce a token that verifies.
    /// [`BrokerSecret`] alone is not sufficient and must not be used here.
    #[must_use]
    pub fn issue_for_operation(
        signing_key: &CapabilitySigningKey,
        peer: &PeerBind,
        principal: impl Into<String>,
        scope: impl Into<String>,
        operation_id: impl Into<String>,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Self {
        let mut tok = Self {
            token_id: format!("cap_{}", Uuid::new_v4().simple()),
            principal: principal.into(),
            scope: scope.into(),
            operation_id: operation_id.into(),
            peer_pid: peer.pid,
            peer_uid: peer.uid,
            peer_exe: peer.exe_path.clone(),
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + ttl_secs,
            signature: String::new(),
        };
        let sig = signing_key.sign(&canonical_capability_bytes(&tok));
        tok.signature = hex::encode(sig);
        tok
    }

    /// Verify Ed25519 signature + expiry + non-empty identity fields.
    pub fn verify(&self, verify_key: &CapabilityVerifyKey, now_unix: i64) -> BrokerResult<()> {
        if now_unix > self.expires_at_unix {
            return Err(BrokerError::Expired);
        }
        if self.token_id.trim().is_empty() {
            return Err(BrokerError::InvalidToken);
        }
        // PID and executable are mandatory. Empty executable claims must never
        // degrade into wildcard peer matching.
        if self.peer_pid <= 0 || self.peer_exe.trim().is_empty() {
            return Err(BrokerError::InvalidToken);
        }
        let sig = hex::decode(&self.signature).map_err(|_| BrokerError::BadSignature)?;
        verify_key.verify(&canonical_capability_bytes(self), &sig)?;
        Ok(())
    }

    /// Verify signature/expiry and that claims match the live OS peer.
    pub fn verify_for_peer(
        &self,
        verify_key: &CapabilityVerifyKey,
        peer: &PeerBind,
        now_unix: i64,
    ) -> BrokerResult<()> {
        self.verify(verify_key, now_unix)?;
        if !self.peer_bind().matches(peer) {
            return Err(BrokerError::Unauthorized);
        }
        Ok(())
    }
}

/// Elevated command request body (structured only — no opaque shell blob).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ElevatedCommand {
    pub program: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub cwd: Option<String>,
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

/// Signed broker request envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerRequest {
    pub protocol_version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub nonce: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    /// Self-asserted label only — broker must not authorize on this alone.
    pub caller_principal: String,
    /// Capability token (minted by broker signing key; optional on the wire when
    /// the broker mints after OS peer verification).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityToken>,
    pub command: ElevatedCommand,
    /// hex-encoded HMAC-SHA256 over typed canonical payload (request MAC secret).
    pub mac: String,
}

/// Broker response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrokerResponse {
    pub request_id: String,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
}

/// Strict response emitted by the production v2 broker wire.
///
/// The response is deliberately execution-only.  It never transports a
/// capability, signing material, or request-MAC secret back to the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerResponseV2 {
    pub request_id: String,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub error: Option<String>,
    pub timed_out: bool,
    pub cancelled: bool,
    pub truncated: bool,
    pub duration_ms: u64,
}

/// Pin for the executable selected by the unprivileged operation planner.
/// The broker compares this immutable fact with its independently checked peer
/// and executable policy before starting a process.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutablePinV2 {
    pub canonical_path: String,
    /// SHA-256 of the executable image, lower-case hex.
    pub image_sha256: String,
    /// Exact length checked on the already-open source descriptor before
    /// broker-private staging. A pathname and digest alone cannot close a
    /// replacement race.
    #[serde(default)]
    pub image_len: u64,
}

/// OS-derived process identity captured while the authenticated daemon peer is
/// live. `birth_id` prevents a later PID reuse from satisfying the binding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PeerProcessBindV2 {
    pub pid: i32,
    pub uid: u32,
    pub executable_path: String,
    pub process_birth_id: u64,
    /// OS-derived identity of the image held by the peer process (for example
    /// a device/inode tuple encoded by the platform-specific verifier).
    pub image_identity: String,
}

/// Complete, canonical facts of the action that was policy-authorized.
///
/// A `BTreeMap` is intentional: environment ordering supplied by an untrusted
/// caller can never change the action digest.  Values are still signed and are
/// not normalized or silently filtered by this transport layer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OperationFactsV2 {
    pub operation: String,
    pub remote_payload_sha256: String,
    pub principal_id: String,
    /// Tenant identity is an authorization boundary, not audit-only metadata.
    pub tenant_id: String,
    pub principal_credential_generation: u64,
    pub timeout_ms: u64,
    pub max_output_bytes: usize,
    pub device_id: String,
    pub workspace_id: String,
    /// Structured argv, including argv[0]; opaque shell strings are absent.
    pub argv: Vec<String>,
    pub canonical_cwd: Option<String>,
    pub sanitized_env: BTreeMap<String, String>,
    pub executable: ExecutablePinV2,
}

/// Broker-issued v2 capability.  Unlike a daemon-readable request MAC, this
/// is signed under the broker-private key and cannot be minted from the MAC
/// secret.  It is bound to exactly one nonce and one facts digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CapabilityTokenV2 {
    pub token_id: String,
    pub broker_instance_id: String,
    pub broker_key_id: String,
    pub principal: String,
    pub scope: String,
    pub operation_id: String,
    pub operation_facts_digest: String,
    pub nonce: String,
    pub peer: PeerProcessBindV2,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    /// Hex Ed25519 signature over the canonical fields above (except itself).
    pub signature: String,
}

/// Strict production v2 request wire envelope.  All unknown JSON keys are
/// rejected at every level, so adding an authority-bearing field needs an
/// intentional protocol version and reauthorization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerRequestV2 {
    pub protocol_version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub nonce: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub facts: OperationFactsV2,
    /// Optional only at the daemon-to-broker boundary.  A missing capability
    /// may be minted solely after the broker has authenticated the live OS
    /// peer; a request MAC on its own never grants that authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityTokenV2>,
    /// HMAC is message authentication only; it is never capability authority.
    pub mac: String,
}

/// Unprivileged production wire. This is intentionally separate from
/// [`BrokerRequestV2`], the broker-internal prepared envelope which can carry
/// a minted capability. A daemon cannot put a capability on this wire.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "intent", rename_all = "snake_case", deny_unknown_fields)]
pub enum BrokerWireIntentV2 {
    Execute(ExecuteIntentV2),
    Cancel(CancelIntentV2),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecuteIntentV2 {
    pub protocol_version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub nonce: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub facts: OperationFactsV2,
    pub mac: String,
}

/// Cancellation has a separate fresh nonce and is fenced to the exact
/// original request/action digest. It is never a free-form operation ID.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CancelIntentV2 {
    pub protocol_version: u32,
    pub request_id: String,
    pub operation_id: String,
    pub nonce: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    pub target_request_id: String,
    pub target_operation_id: String,
    pub target_nonce: String,
    pub target_facts_digest: String,
    pub mac: String,
}

impl ExecuteIntentV2 {
    #[must_use]
    pub fn into_unprepared_request(self) -> BrokerRequestV2 {
        BrokerRequestV2 {
            protocol_version: self.protocol_version,
            request_id: self.request_id,
            operation_id: self.operation_id,
            nonce: self.nonce,
            issued_at_unix: self.issued_at_unix,
            expires_at_unix: self.expires_at_unix,
            facts: self.facts,
            capability: None,
            mac: self.mac,
        }
    }
}

impl CapabilityTokenV2 {
    /// Issue a v2 token from broker-only signing material.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        signing_key: &CapabilitySigningKey,
        broker_instance_id: impl Into<String>,
        broker_key_id: impl Into<String>,
        principal: impl Into<String>,
        operation_id: impl Into<String>,
        facts: &OperationFactsV2,
        nonce: impl Into<String>,
        peer: PeerProcessBindV2,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Self {
        let mut token = Self {
            token_id: format!("cap2_{}", Uuid::new_v4().simple()),
            broker_instance_id: broker_instance_id.into(),
            broker_key_id: broker_key_id.into(),
            principal: principal.into(),
            scope: ELEVATED_CAPABILITY_SCOPE.into(),
            operation_id: operation_id.into(),
            operation_facts_digest: operation_facts_digest(facts),
            nonce: nonce.into(),
            peer,
            issued_at_unix: now_unix,
            expires_at_unix: now_unix.saturating_add(ttl_secs),
            signature: String::new(),
        };
        token.signature = hex::encode(signing_key.sign(&canonical_capability_v2_bytes(&token)));
        token
    }
}

/// Decode a bounded strict v2 envelope.  This must be used at the socket
/// boundary instead of an unbounded line/String deserializer.
pub fn parse_broker_request_v2(bytes: &[u8]) -> BrokerResult<BrokerRequestV2> {
    if bytes.len() > MAX_BROKER_REQUEST_BYTES {
        return Err(BrokerError::Protocol("request exceeds byte limit".into()));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| BrokerError::Protocol(format!("invalid strict v2 request: {e}")))
}

/// Decode the sole accepted production wire format. Capability-bearing
/// `BrokerRequestV2` values are internal and deliberately cannot decode here.
pub fn parse_broker_wire_intent_v2(bytes: &[u8]) -> BrokerResult<BrokerWireIntentV2> {
    if bytes.len() > MAX_BROKER_REQUEST_BYTES {
        return Err(BrokerError::Protocol("request exceeds byte limit".into()));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| BrokerError::Protocol(format!("invalid strict v2 intent: {e}")))
}

#[must_use]
pub fn compute_execute_intent_mac_v2(secret: &BrokerSecret, intent: &ExecuteIntentV2) -> String {
    compute_mac_v2(secret, &intent.clone().into_unprepared_request())
}

pub fn verify_execute_intent_v2_message_auth(
    secret: &BrokerSecret,
    intent: &ExecuteIntentV2,
    now_unix: i64,
) -> BrokerResult<()> {
    verify_request_v2_message_auth(secret, &intent.clone().into_unprepared_request(), now_unix)
}

#[must_use]
pub fn compute_cancel_intent_mac_v2(secret: &BrokerSecret, intent: &CancelIntentV2) -> String {
    hmac_hex(secret, &canonical_cancel_intent_v2_bytes(intent))
}

pub fn verify_cancel_intent_v2_message_auth(
    secret: &BrokerSecret,
    intent: &CancelIntentV2,
    now_unix: i64,
) -> BrokerResult<()> {
    if intent.protocol_version != BROKER_PROTOCOL_V2
        || now_unix > intent.expires_at_unix
        || intent.issued_at_unix > now_unix
        || intent.expires_at_unix < intent.issued_at_unix
        || intent.expires_at_unix.saturating_sub(intent.issued_at_unix)
            > DEFAULT_CAPABILITY_TTL_SECS
        || !is_sha256_hex(&intent.target_facts_digest)
    {
        return Err(BrokerError::Protocol(
            "invalid bounded cancel intent".into(),
        ));
    }
    for (name, value) in [
        ("request_id", intent.request_id.as_str()),
        ("operation_id", intent.operation_id.as_str()),
        ("nonce", intent.nonce.as_str()),
        ("target_request_id", intent.target_request_id.as_str()),
        ("target_operation_id", intent.target_operation_id.as_str()),
        ("target_nonce", intent.target_nonce.as_str()),
    ] {
        validate_bounded_field(name, value)?;
    }
    if !constant_time_hex_eq(&compute_cancel_intent_mac_v2(secret, intent), &intent.mac) {
        return Err(BrokerError::BadSignature);
    }
    Ok(())
}

/// SHA-256 digest of typed canonical operation facts.  This is the exact
/// action commitment signed by a v2 capability and persisted in the replay
/// ledger; JSON formatting or map iteration cannot alter it.
#[must_use]
pub fn operation_facts_digest(facts: &OperationFactsV2) -> String {
    hex::encode(Sha256::digest(canonical_operation_facts_v2_bytes(facts)))
}

/// Compute the v2 request MAC.  Possession proves only access to the local IPC
/// request secret; the separately signed capability is still mandatory.
#[must_use]
pub fn compute_mac_v2(secret: &BrokerSecret, req: &BrokerRequestV2) -> String {
    hmac_hex(secret, &canonical_request_v2_bytes(req))
}

/// Verify the strict v2 envelope, message MAC, capability signature, exact
/// facts digest, expiry, broker binding, and live peer process identity.
#[allow(clippy::too_many_arguments)]
pub fn verify_request_v2(
    secret: &BrokerSecret,
    verify_key: &CapabilityVerifyKey,
    req: &BrokerRequestV2,
    expected_broker_instance_id: &str,
    expected_broker_key_id: &str,
    peer: &PeerProcessBindV2,
    now_unix: i64,
) -> BrokerResult<()> {
    verify_request_v2_message_auth(secret, req, now_unix)?;
    verify_capability_v2(
        verify_key,
        req,
        expected_broker_instance_id,
        expected_broker_key_id,
        peer,
        now_unix,
    )
}

/// Verify only the broker-issued capability embedded in an already
/// message-authenticated request.  This supports the production sequence where
/// the external daemon frame carries no capability, the broker mints one after
/// OS peer authorization, and the internal-only clone is then verified.
#[allow(clippy::too_many_arguments)]
pub fn verify_capability_v2(
    verify_key: &CapabilityVerifyKey,
    req: &BrokerRequestV2,
    expected_broker_instance_id: &str,
    expected_broker_key_id: &str,
    peer: &PeerProcessBindV2,
    now_unix: i64,
) -> BrokerResult<()> {
    validate_v2_request_shape(req, now_unix)?;
    let cap = req.capability.as_ref().ok_or(BrokerError::InvalidToken)?;
    if now_unix > cap.expires_at_unix || cap.issued_at_unix > now_unix {
        return Err(BrokerError::Expired);
    }
    if cap.scope != ELEVATED_CAPABILITY_SCOPE
        || cap.operation_id != req.operation_id
        || cap.nonce != req.nonce
        || cap.broker_instance_id != expected_broker_instance_id
        || cap.broker_key_id != expected_broker_key_id
        || cap.operation_facts_digest != operation_facts_digest(&req.facts)
        || &cap.peer != peer
    {
        return Err(BrokerError::Unauthorized);
    }
    let signature = hex::decode(&cap.signature).map_err(|_| BrokerError::BadSignature)?;
    verify_key.verify(&canonical_capability_v2_bytes(cap), &signature)
}

/// Verify only strict request framing, exact facts, expiry, and the local
/// message MAC.  This deliberately returns no authority: production serving
/// must additionally authenticate a trusted OS peer before it mints a missing
/// capability or accepts a supplied one through [`verify_request_v2`].
pub fn verify_request_v2_message_auth(
    secret: &BrokerSecret,
    req: &BrokerRequestV2,
    now_unix: i64,
) -> BrokerResult<()> {
    validate_v2_request_shape(req, now_unix)?;
    if !constant_time_hex_eq(&compute_mac_v2(secret, req), &req.mac) {
        return Err(BrokerError::BadSignature);
    }
    Ok(())
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_i64(buf: &mut Vec<u8>, v: i64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_i32(buf: &mut Vec<u8>, v: i32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_map(buf: &mut Vec<u8>, values: &BTreeMap<String, String>) {
    put_u32(buf, u32::try_from(values.len()).unwrap_or(u32::MAX));
    for (key, value) in values {
        put_str(buf, key);
        put_str(buf, value);
    }
}

fn canonical_operation_facts_v2_bytes(facts: &OperationFactsV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(OPERATION_FACTS_V2_DOMAIN);
    put_str(&mut buf, &facts.operation);
    put_str(&mut buf, &facts.remote_payload_sha256);
    put_str(&mut buf, &facts.principal_id);
    put_str(&mut buf, &facts.tenant_id);
    put_u64(&mut buf, facts.principal_credential_generation);
    put_u64(&mut buf, facts.timeout_ms);
    put_u32(
        &mut buf,
        u32::try_from(facts.max_output_bytes).unwrap_or(u32::MAX),
    );
    put_str(&mut buf, &facts.device_id);
    put_str(&mut buf, &facts.workspace_id);
    put_u32(
        &mut buf,
        u32::try_from(facts.argv.len()).unwrap_or(u32::MAX),
    );
    for arg in &facts.argv {
        put_str(&mut buf, arg);
    }
    match &facts.canonical_cwd {
        Some(cwd) => {
            buf.push(1);
            put_str(&mut buf, cwd);
        }
        None => buf.push(0),
    }
    put_map(&mut buf, &facts.sanitized_env);
    put_str(&mut buf, &facts.executable.canonical_path);
    put_str(&mut buf, &facts.executable.image_sha256);
    put_u64(&mut buf, facts.executable.image_len);
    buf
}

fn canonical_peer_process_v2_bytes(buf: &mut Vec<u8>, peer: &PeerProcessBindV2) {
    put_i32(buf, peer.pid);
    put_u32(buf, peer.uid);
    put_str(buf, &peer.executable_path);
    put_u64(buf, peer.process_birth_id);
    put_str(buf, &peer.image_identity);
}

fn canonical_capability_v2_bytes(token: &CapabilityTokenV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(384);
    buf.extend_from_slice(CAPABILITY_V2_SIG_DOMAIN);
    put_str(&mut buf, &token.token_id);
    put_str(&mut buf, &token.broker_instance_id);
    put_str(&mut buf, &token.broker_key_id);
    put_str(&mut buf, &token.principal);
    put_str(&mut buf, &token.scope);
    put_str(&mut buf, &token.operation_id);
    put_str(&mut buf, &token.operation_facts_digest);
    put_str(&mut buf, &token.nonce);
    canonical_peer_process_v2_bytes(&mut buf, &token.peer);
    put_i64(&mut buf, token.issued_at_unix);
    put_i64(&mut buf, token.expires_at_unix);
    buf
}

fn canonical_request_v2_bytes(req: &BrokerRequestV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(768);
    buf.extend_from_slice(REQUEST_V2_MAC_DOMAIN);
    put_u32(&mut buf, req.protocol_version);
    put_str(&mut buf, &req.request_id);
    put_str(&mut buf, &req.operation_id);
    put_str(&mut buf, &req.nonce);
    put_i64(&mut buf, req.issued_at_unix);
    put_i64(&mut buf, req.expires_at_unix);
    let facts = canonical_operation_facts_v2_bytes(&req.facts);
    put_bytes(&mut buf, &facts);
    match &req.capability {
        Some(capability) => {
            buf.push(1);
            let capability = canonical_capability_v2_bytes(capability);
            put_bytes(&mut buf, &capability);
            put_str(
                &mut buf,
                req.capability.as_ref().map_or("", |cap| &cap.signature),
            );
        }
        None => buf.push(0),
    }
    buf
}

fn canonical_cancel_intent_v2_bytes(intent: &CancelIntentV2) -> Vec<u8> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(b"ownmesh.broker.cancel-intent.v2\0");
    put_u32(&mut buf, intent.protocol_version);
    put_str(&mut buf, &intent.request_id);
    put_str(&mut buf, &intent.operation_id);
    put_str(&mut buf, &intent.nonce);
    put_i64(&mut buf, intent.issued_at_unix);
    put_i64(&mut buf, intent.expires_at_unix);
    put_str(&mut buf, &intent.target_request_id);
    put_str(&mut buf, &intent.target_operation_id);
    put_str(&mut buf, &intent.target_nonce);
    put_str(&mut buf, &intent.target_facts_digest);
    buf
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value.as_bytes().iter().all(|byte| {
            byte.is_ascii_digit() || (byte.is_ascii_lowercase() && byte.is_ascii_hexdigit())
        })
}

fn validate_bounded_field(name: &str, value: &str) -> BrokerResult<()> {
    if value.trim().is_empty() || value.len() > MAX_BROKER_FIELD_BYTES || value.contains('\0') {
        return Err(BrokerError::Protocol(format!("invalid {name}")));
    }
    Ok(())
}

fn validate_v2_request_shape(req: &BrokerRequestV2, now_unix: i64) -> BrokerResult<()> {
    if req.protocol_version != BROKER_PROTOCOL_V2 {
        return Err(BrokerError::Protocol(
            "unsupported v2 protocol version".into(),
        ));
    }
    if now_unix > req.expires_at_unix || req.issued_at_unix > now_unix {
        return Err(BrokerError::Expired);
    }
    if req.expires_at_unix < req.issued_at_unix
        || req.expires_at_unix.saturating_sub(req.issued_at_unix) > DEFAULT_CAPABILITY_TTL_SECS
    {
        return Err(BrokerError::Protocol("invalid request lifetime".into()));
    }
    for (name, value) in [
        ("request_id", req.request_id.as_str()),
        ("operation_id", req.operation_id.as_str()),
        ("nonce", req.nonce.as_str()),
        ("facts.operation", req.facts.operation.as_str()),
        ("principal_id", req.facts.principal_id.as_str()),
        ("tenant_id", req.facts.tenant_id.as_str()),
        ("device_id", req.facts.device_id.as_str()),
        ("workspace_id", req.facts.workspace_id.as_str()),
        (
            "executable path",
            req.facts.executable.canonical_path.as_str(),
        ),
    ] {
        validate_bounded_field(name, value)?;
    }
    if req.facts.operation != req.operation_id
        || req.facts.argv.is_empty()
        || req.facts.argv.len() > MAX_BROKER_ARGV
        || req.facts.sanitized_env.len() > MAX_BROKER_ENV
        // Production broker v2 deliberately has a fixed empty environment.
        // Accepting a caller-selected loader/runtime/PATH variable would turn a
        // signed command fact into a confused-deputy executable selection.
        || !req.facts.sanitized_env.is_empty()
        || !is_sha256_hex(&req.facts.remote_payload_sha256)
        || !is_sha256_hex(&req.facts.executable.image_sha256)
        || req.facts.argv[0] != req.facts.executable.canonical_path
        || req.facts.timeout_ms == 0
        || req.facts.timeout_ms > MAX_BROKER_TIMEOUT_MS
        || req.facts.max_output_bytes == 0
        || req.facts.max_output_bytes > MAX_BROKER_OUTPUT_BYTES
        || req.facts.executable.image_len == 0
        || req.facts.executable.image_len > 64 * 1024 * 1024
    {
        return Err(BrokerError::Protocol(
            "invalid bounded operation facts".into(),
        ));
    }
    for arg in &req.facts.argv {
        validate_bounded_field("argv", arg)?;
    }
    if let Some(cwd) = &req.facts.canonical_cwd {
        validate_bounded_field("canonical cwd", cwd)?;
        if !std::path::Path::new(cwd).is_absolute() {
            return Err(BrokerError::Protocol(
                "canonical cwd must be absolute".into(),
            ));
        }
    }
    for (key, value) in &req.facts.sanitized_env {
        validate_bounded_field("environment name", key)?;
        if key.contains('=') {
            return Err(BrokerError::Protocol(
                "environment name contains '='".into(),
            ));
        }
        if value.len() > MAX_BROKER_FIELD_BYTES || value.contains('\0') {
            return Err(BrokerError::Protocol("invalid environment value".into()));
        }
    }
    if let Some(cap) = &req.capability {
        for (name, value) in [
            ("capability token id", cap.token_id.as_str()),
            ("broker instance id", cap.broker_instance_id.as_str()),
            ("broker key id", cap.broker_key_id.as_str()),
            ("capability principal", cap.principal.as_str()),
            ("peer executable path", cap.peer.executable_path.as_str()),
            ("peer image identity", cap.peer.image_identity.as_str()),
        ] {
            validate_bounded_field(name, value)?;
        }
        if !is_sha256_hex(&cap.operation_facts_digest)
            || cap.peer.pid <= 0
            || cap.peer.process_birth_id == 0
        {
            return Err(BrokerError::Protocol("invalid capability binding".into()));
        }
    }
    Ok(())
}

/// Typed, field-fixed canonical bytes for a capability token (excludes signature).
fn canonical_capability_bytes(tok: &CapabilityToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(160);
    buf.extend_from_slice(CAPABILITY_SIG_DOMAIN);
    put_str(&mut buf, &tok.token_id);
    put_str(&mut buf, &tok.principal);
    put_str(&mut buf, &tok.scope);
    put_str(&mut buf, &tok.operation_id);
    put_i32(&mut buf, tok.peer_pid);
    put_u32(&mut buf, tok.peer_uid);
    put_str(&mut buf, &tok.peer_exe);
    put_i64(&mut buf, tok.issued_at_unix);
    put_i64(&mut buf, tok.expires_at_unix);
    buf
}

/// Typed, field-fixed canonical bytes for a broker request (excludes request MAC).
fn canonical_request_bytes(req: &BrokerRequest) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(REQUEST_MAC_DOMAIN);
    put_u32(&mut buf, req.protocol_version);
    put_str(&mut buf, &req.request_id);
    put_str(&mut buf, &req.operation_id);
    put_str(&mut buf, &req.nonce);
    put_i64(&mut buf, req.issued_at_unix);
    put_i64(&mut buf, req.expires_at_unix);
    put_str(&mut buf, &req.caller_principal);
    match &req.capability {
        Some(cap) => {
            buf.push(1);
            put_str(&mut buf, &cap.token_id);
            put_str(&mut buf, &cap.principal);
            put_str(&mut buf, &cap.scope);
            put_str(&mut buf, &cap.operation_id);
            put_i32(&mut buf, cap.peer_pid);
            put_u32(&mut buf, cap.peer_uid);
            put_str(&mut buf, &cap.peer_exe);
            put_i64(&mut buf, cap.issued_at_unix);
            put_i64(&mut buf, cap.expires_at_unix);
            put_str(&mut buf, &cap.signature);
        }
        None => buf.push(0),
    }
    put_str(&mut buf, &req.command.program);
    put_u32(&mut buf, req.command.args.len() as u32);
    for arg in &req.command.args {
        put_str(&mut buf, arg);
    }
    match &req.command.cwd {
        Some(cwd) => {
            buf.push(1);
            put_str(&mut buf, cwd);
        }
        None => buf.push(0),
    }
    put_u32(&mut buf, req.command.env.len() as u32);
    for (k, v) in &req.command.env {
        put_str(&mut buf, k);
        put_str(&mut buf, v);
    }
    buf
}

fn hmac_hex(secret: &BrokerSecret, data: &[u8]) -> String {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

/// Constant-time equality for hex-encoded MAC strings.
fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(a_bytes), Ok(b_bytes)) => {
            if a_bytes.len() != b_bytes.len() {
                return false;
            }
            bool::from(a_bytes.ct_eq(&b_bytes))
        }
        _ => {
            let a = a.as_bytes();
            let b = b.as_bytes();
            if a.len() != b.len() {
                return false;
            }
            bool::from(a.ct_eq(b))
        }
    }
}

/// Compute request HMAC-SHA256 over the typed canonical payload.
#[must_use]
pub fn compute_mac(secret: &BrokerSecret, req: &BrokerRequest) -> String {
    hmac_hex(secret, &canonical_request_bytes(req))
}

/// Build a signed request **without** a capability token.
///
/// Clients holding only [`BrokerSecret`] must not mint capabilities. The broker
/// mints (or verifies a broker-issued token) after OS peer authentication.
#[must_use]
pub fn build_request(
    secret: &BrokerSecret,
    caller_principal: impl Into<String>,
    operation_id: impl Into<String>,
    command: ElevatedCommand,
    now_unix: i64,
    ttl_secs: i64,
) -> BrokerRequest {
    build_request_with_capability(
        secret,
        caller_principal,
        operation_id,
        command,
        None,
        now_unix,
        ttl_secs,
    )
}

/// Build a signed request, optionally attaching a broker-issued capability token.
#[must_use]
pub fn build_request_with_capability(
    secret: &BrokerSecret,
    caller_principal: impl Into<String>,
    operation_id: impl Into<String>,
    command: ElevatedCommand,
    capability: Option<CapabilityToken>,
    now_unix: i64,
    ttl_secs: i64,
) -> BrokerRequest {
    let mut req = BrokerRequest {
        protocol_version: BROKER_PROTOCOL_VERSION,
        request_id: format!("brq_{}", Uuid::new_v4().simple()),
        operation_id: operation_id.into(),
        nonce: format!("n_{}", Uuid::new_v4().simple()),
        issued_at_unix: now_unix,
        expires_at_unix: now_unix + ttl_secs,
        caller_principal: caller_principal.into(),
        capability,
        command,
        mac: String::new(),
    };
    req.mac = compute_mac(secret, &req);
    req
}

/// Verify request HMAC, expiry, protocol version (capability not required).
pub fn verify_request_mac(
    secret: &BrokerSecret,
    req: &BrokerRequest,
    now_unix: i64,
) -> BrokerResult<()> {
    if req.protocol_version != BROKER_PROTOCOL_VERSION {
        return Err(BrokerError::Protocol(format!(
            "unsupported version {}",
            req.protocol_version
        )));
    }
    if now_unix > req.expires_at_unix {
        return Err(BrokerError::Expired);
    }
    if req.nonce.trim().is_empty() || req.request_id.trim().is_empty() {
        return Err(BrokerError::Protocol("missing nonce or request_id".into()));
    }
    let expected = compute_mac(secret, req);
    if !constant_time_hex_eq(&expected, &req.mac) {
        return Err(BrokerError::BadSignature);
    }
    if req.command.program.is_empty() {
        return Err(BrokerError::Protocol("empty program".into()));
    }
    if req.command.program.len() > 4096 || req.command.args.iter().any(|a| a.len() > 8192) {
        return Err(BrokerError::Protocol("command too large".into()));
    }
    if req.command.env.len() > 256 {
        return Err(BrokerError::Protocol("too many env vars".into()));
    }
    Ok(())
}

/// Verify request MAC + required capability bindings (signature + scope/op/peer).
///
/// Does not check the replay set. Capability is always required here and must
/// bind `scope == ELEVATED_CAPABILITY_SCOPE`, `operation_id == req.operation_id`,
/// and the provided `peer` OS identity. `caller_principal` is **not** used as
/// an authorization decision by itself.
pub fn verify_request(
    secret: &BrokerSecret,
    verify_key: &CapabilityVerifyKey,
    req: &BrokerRequest,
    peer: &PeerBind,
    now_unix: i64,
) -> BrokerResult<()> {
    verify_request_mac(secret, req, now_unix)?;

    let cap = req.capability.as_ref().ok_or(BrokerError::InvalidToken)?;
    cap.verify_for_peer(verify_key, peer, now_unix)?;
    if cap.operation_id != req.operation_id {
        return Err(BrokerError::Unauthorized);
    }
    if cap.scope != ELEVATED_CAPABILITY_SCOPE {
        return Err(BrokerError::Unauthorized);
    }
    Ok(())
}

/// Replay cache keyed by nonce/request_id with optional pruning by expiry.
#[derive(Debug, Default)]
pub struct ReplayCache {
    /// key -> expires_at_unix
    seen: HashMap<String, i64>,
}

impl ReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_insert(&mut self, req: &BrokerRequest) -> BrokerResult<()> {
        self.prune(req.issued_at_unix.saturating_sub(3600));
        let key = format!("{}:{}", req.request_id, req.nonce);
        if self.seen.contains_key(&key) {
            return Err(BrokerError::Replay);
        }
        self.seen.insert(key, req.expires_at_unix);
        Ok(())
    }

    fn prune(&mut self, before_unix: i64) {
        self.seen.retain(|_, exp| *exp >= before_unix);
    }
}

/// High-level helper: MAC-sign + send elevated command (no client-side capability mint).
///
/// The broker authenticates the OS peer and mints/verifies capability tokens.
pub async fn elevate(
    endpoint: &BrokerEndpoint,
    secret: &BrokerSecret,
    caller_principal: impl Into<String>,
    operation_id: impl Into<String>,
    command: ElevatedCommand,
    now_unix: i64,
    ttl_secs: i64,
) -> BrokerResult<BrokerResponse> {
    let req = build_request(
        secret,
        caller_principal,
        operation_id,
        command,
        now_unix,
        ttl_secs,
    );
    connect_and_call(endpoint, &req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_peer() -> PeerBind {
        PeerBind::new(4242, 1000, "/usr/bin/ownmeshd")
    }

    fn keys() -> (CapabilitySigningKey, CapabilityVerifyKey) {
        let sk = CapabilitySigningKey::generate();
        let vk = sk.verify_key();
        (sk, vk)
    }

    #[test]
    fn sign_and_verify_with_broker_minted_capability() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = keys();
        let peer = test_peer();
        let cmd = ElevatedCommand {
            program: "whoami".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };
        let cap = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op1",
            1_000,
            60,
        );
        let req =
            build_request_with_capability(&secret, "ownmeshd", "op1", cmd, Some(cap), 1_000, 60);
        verify_request(&secret, &vk, &req, &peer, 1_010).unwrap();
        assert!(verify_request(&secret, &vk, &req, &peer, 2_000).is_err());
    }

    #[test]
    fn rejects_tamper_and_replay() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = keys();
        let peer = test_peer();
        let mut req = {
            let cap = CapabilityToken::issue_for_operation(
                &sk,
                &peer,
                "daemon",
                ELEVATED_CAPABILITY_SCOPE,
                "op1",
                100,
                50,
            );
            build_request_with_capability(
                &secret,
                "daemon",
                "op1",
                ElevatedCommand {
                    program: "id".into(),
                    args: vec![],
                    cwd: None,
                    env: vec![],
                },
                Some(cap),
                100,
                50,
            )
        };
        req.command.program = "evil".into();
        assert!(verify_request(&secret, &vk, &req, &peer, 110).is_err());

        let cap = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "daemon",
            ELEVATED_CAPABILITY_SCOPE,
            "op1",
            100,
            50,
        );
        let req = build_request_with_capability(
            &secret,
            "daemon",
            "op1",
            ElevatedCommand {
                program: "id".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            Some(cap),
            100,
            50,
        );
        let mut cache = ReplayCache::new();
        cache.check_and_insert(&req).unwrap();
        assert!(cache.check_and_insert(&req).is_err());
    }

    #[test]
    fn peer_bind_requires_exact_non_empty_executable() {
        let exact = PeerBind::new(7, 1000, "/usr/bin/ownmeshd");
        assert!(exact.matches(&exact));
        assert!(!exact.matches(&PeerBind::new(7, 1000, "")));
        assert!(!PeerBind::new(7, 1000, "").matches(&exact));
        assert!(!exact.matches(&PeerBind::new(8, 1000, "/usr/bin/ownmeshd")));
        assert!(!exact.matches(&PeerBind::new(7, 1001, "/usr/bin/ownmeshd")));
        assert!(!exact.matches(&PeerBind::new(7, 1000, "/tmp/ownmeshd")));
    }

    #[test]
    fn capability_token_roundtrip_and_peer_mismatch() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = keys();
        let peer = test_peer();
        let tok = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            1000,
            60,
        );
        tok.verify(&vk, 1010).unwrap();
        assert!(tok.verify(&vk, 2000).is_err());

        let mut bad = tok.clone();
        bad.peer_uid = 0;
        assert!(bad.verify(&vk, 1010).is_err());

        let cmd = ElevatedCommand {
            program: "true".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };
        let req =
            build_request_with_capability(&secret, "ownmeshd", "op", cmd, Some(tok), 1000, 60);
        verify_request(&secret, &vk, &req, &peer, 1010).unwrap();

        let other_peer = PeerBind::new(peer.pid, peer.uid + 1, peer.exe_path.clone());
        assert!(matches!(
            verify_request(&secret, &vk, &req, &other_peer, 1010),
            Err(BrokerError::Unauthorized)
        ));
    }

    #[test]
    fn rejects_missing_capability_on_strict_verify() {
        let secret = BrokerSecret::generate();
        let (_sk, vk) = keys();
        let peer = test_peer();
        let req = build_request(
            &secret,
            "ownmeshd",
            "op_missing",
            ElevatedCommand {
                program: "true".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            1000,
            60,
        );
        assert!(req.capability.is_none());
        assert!(matches!(
            verify_request(&secret, &vk, &req, &peer, 1010),
            Err(BrokerError::InvalidToken)
        ));
        verify_request_mac(&secret, &req, 1010).unwrap();
    }

    #[test]
    fn rejects_scope_and_operation_mismatch() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = keys();
        let peer = test_peer();
        let cmd = ElevatedCommand {
            program: "true".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };

        let wrong_scope = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            "wrong.scope",
            "op_scope",
            1000,
            60,
        );
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op_scope",
            cmd.clone(),
            Some(wrong_scope),
            1000,
            60,
        );
        assert!(matches!(
            verify_request(&secret, &vk, &req, &peer, 1010),
            Err(BrokerError::Unauthorized)
        ));

        let wrong_op = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "other_op",
            1000,
            60,
        );
        let req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op_scope",
            cmd,
            Some(wrong_op),
            1000,
            60,
        );
        assert!(matches!(
            verify_request(&secret, &vk, &req, &peer, 1010),
            Err(BrokerError::Unauthorized)
        ));
    }

    #[test]
    fn mac_secret_cannot_mint_valid_capability() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = keys();
        let peer = test_peer();
        // Attacker with only BrokerSecret tries to mint by abusing secret bytes as seed.
        let forged_key = CapabilitySigningKey::from_bytes(secret.as_bytes())
            .expect("32-byte secret can load as a key material");
        let forged = CapabilityToken::issue_for_operation(
            &forged_key,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op_forge",
            1000,
            60,
        );
        assert!(
            forged.verify(&vk, 1010).is_err(),
            "token minted from MAC secret must not verify under broker verify key"
        );
        // Genuine mint still works.
        let good = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op_forge",
            1000,
            60,
        );
        good.verify(&vk, 1010).unwrap();
    }

    #[test]
    fn malformed_requests_rejected() {
        let secret = BrokerSecret::generate();
        let (sk, vk) = keys();
        let peer = test_peer();
        let cap = CapabilityToken::issue_for_operation(
            &sk,
            &peer,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            10,
            30,
        );
        let mut req = build_request_with_capability(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "x".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            Some(cap),
            10,
            30,
        );
        req.protocol_version = 99;
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &vk, &req, &peer, 11).is_err());

        req.protocol_version = BROKER_PROTOCOL_VERSION;
        req.command.program = String::new();
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &vk, &req, &peer, 11).is_err());

        req.command.program = "x".repeat(5000);
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &vk, &req, &peer, 11).is_err());

        req.command.program = "ok".into();
        req.nonce = String::new();
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &vk, &req, &peer, 11).is_err());
    }

    #[test]
    fn loopback_enforcement_helper() {
        assert!(is_loopback_socket_addr(
            &"127.0.0.1:9".parse().expect("addr")
        ));
        assert!(is_loopback_socket_addr(&"[::1]:9".parse().expect("addr")));
        assert!(!is_loopback_socket_addr(
            &"8.8.8.8:9".parse().expect("addr")
        ));
        assert!(!is_loopback_socket_addr(
            &"0.0.0.0:9".parse().expect("addr")
        ));
    }

    #[test]
    fn hmac_differs_from_sha256_concat() {
        // Guardrail: MAC must not be raw Sha256(secret||payload).
        let secret = BrokerSecret::from_bytes(vec![7u8; 32]);
        let req = build_request(
            &secret,
            "ownmeshd",
            "op_hmac",
            ElevatedCommand {
                program: "true".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            42,
            60,
        );
        let mut legacy = Sha256::new();
        legacy.update(secret.as_bytes());
        legacy.update(&canonical_request_bytes(&req));
        let legacy_hex = hex::encode(legacy.finalize());
        assert_ne!(req.mac, legacy_hex);
        assert_eq!(req.mac, compute_mac(&secret, &req));
    }

    #[test]
    fn elevate_does_not_attach_client_minted_capability() {
        let secret = BrokerSecret::generate();
        let req = build_request(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "true".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            1,
            30,
        );
        assert!(
            req.capability.is_none(),
            "client build_request must not mint capabilities"
        );
    }
}

#[cfg(test)]
mod v2_tests {
    use super::*;

    fn facts() -> OperationFactsV2 {
        OperationFactsV2 {
            operation: "command.exec.elevated".into(),
            remote_payload_sha256: "a".repeat(64),
            principal_id: "principal-1".into(),
            tenant_id: "tenant-1".into(),
            principal_credential_generation: 7,
            timeout_ms: 30_000,
            max_output_bytes: 64 * 1024,
            device_id: "device_1".into(),
            workspace_id: "workspace_1".into(),
            argv: vec!["/usr/bin/id".into(), "-u".into()],
            canonical_cwd: Some(std::env::temp_dir().display().to_string()),
            sanitized_env: BTreeMap::new(),
            executable: ExecutablePinV2 {
                canonical_path: "/usr/bin/id".into(),
                image_sha256: "b".repeat(64),
                image_len: 1,
            },
        }
    }

    fn peer() -> PeerProcessBindV2 {
        PeerProcessBindV2 {
            pid: 42,
            uid: 1000,
            executable_path: "/usr/bin/ownmeshd".into(),
            process_birth_id: 99,
            image_identity: "dev=1;ino=2".into(),
        }
    }

    fn signed_v2() -> (
        BrokerSecret,
        CapabilityVerifyKey,
        BrokerRequestV2,
        PeerProcessBindV2,
    ) {
        let secret = BrokerSecret::generate();
        let signing = CapabilitySigningKey::generate();
        let verify = signing.verify_key();
        let facts = facts();
        let peer = peer();
        let cap = CapabilityTokenV2::issue(
            &signing,
            "broker-instance",
            "broker-key-1",
            "principal-1",
            "command.exec.elevated",
            &facts,
            "nonce-1",
            peer.clone(),
            100,
            30,
        );
        let mut request = BrokerRequestV2 {
            protocol_version: BROKER_PROTOCOL_V2,
            request_id: "request-1".into(),
            operation_id: "command.exec.elevated".into(),
            nonce: "nonce-1".into(),
            issued_at_unix: 100,
            expires_at_unix: 130,
            facts,
            capability: Some(cap),
            mac: String::new(),
        };
        request.mac = compute_mac_v2(&secret, &request);
        (secret, verify, request, peer)
    }

    #[test]
    fn v2_binds_all_action_facts_and_peer_lifetime() {
        let (secret, verify, request, peer) = signed_v2();
        verify_request_v2(
            &secret,
            &verify,
            &request,
            "broker-instance",
            "broker-key-1",
            &peer,
            110,
        )
        .unwrap();

        let mut changed = request.clone();
        changed.facts.argv.push("--changed".into());
        changed.mac = compute_mac_v2(&secret, &changed);
        assert!(verify_request_v2(
            &secret,
            &verify,
            &changed,
            "broker-instance",
            "broker-key-1",
            &peer,
            110,
        )
        .is_err());

        let reused_pid = PeerProcessBindV2 {
            process_birth_id: peer.process_birth_id + 1,
            ..peer.clone()
        };
        assert!(verify_request_v2(
            &secret,
            &verify,
            &request,
            "broker-instance",
            "broker-key-1",
            &reused_pid,
            110,
        )
        .is_err());
        assert!(verify_request_v2(
            &secret,
            &verify,
            &request,
            "broker-instance",
            "broker-key-1",
            &peer,
            131,
        )
        .is_err());
    }

    #[test]
    fn v2_mac_only_frame_cannot_verify_as_a_capability() {
        let (secret, verify, mut request, peer) = signed_v2();
        request.capability = None;
        request.mac = compute_mac_v2(&secret, &request);
        verify_request_v2_message_auth(&secret, &request, 110).unwrap();
        assert!(matches!(
            verify_request_v2(
                &secret,
                &verify,
                &request,
                "broker-instance",
                "broker-key-1",
                &peer,
                110,
            ),
            Err(BrokerError::InvalidToken)
        ));
    }

    #[test]
    fn v2_rejects_unknown_and_oversized_wire_fields() {
        let (_, _, request, _) = signed_v2();
        let mut value = serde_json::to_value(request).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("forged_authority".into(), serde_json::Value::Bool(true));
        assert!(parse_broker_request_v2(&serde_json::to_vec(&value).unwrap()).is_err());
        assert!(parse_broker_request_v2(&vec![b'x'; MAX_BROKER_REQUEST_BYTES + 1]).is_err());
    }

    #[test]
    fn production_wire_never_accepts_capability_and_cancel_mac_is_fenced() {
        let (secret, _verify, request, _peer) = signed_v2();
        let execute = ExecuteIntentV2 {
            protocol_version: request.protocol_version,
            request_id: request.request_id.clone(),
            operation_id: request.operation_id.clone(),
            nonce: request.nonce.clone(),
            issued_at_unix: request.issued_at_unix,
            expires_at_unix: request.expires_at_unix,
            facts: request.facts.clone(),
            mac: String::new(),
        };
        let mut execute = execute;
        execute.mac = compute_execute_intent_mac_v2(&secret, &execute);
        let wire = serde_json::to_vec(&BrokerWireIntentV2::Execute(execute)).unwrap();
        assert!(matches!(
            parse_broker_wire_intent_v2(&wire),
            Ok(BrokerWireIntentV2::Execute(_))
        ));
        let capability_wire = serde_json::to_vec(&request).unwrap();
        assert!(parse_broker_wire_intent_v2(&capability_wire).is_err());

        let mut cancel = CancelIntentV2 {
            protocol_version: BROKER_PROTOCOL_V2,
            request_id: "cancel-request".into(),
            operation_id: "command.exec.elevated".into(),
            nonce: "fresh-cancel-nonce".into(),
            issued_at_unix: 100,
            expires_at_unix: 130,
            target_request_id: request.request_id,
            target_operation_id: request.operation_id,
            target_nonce: request.nonce,
            target_facts_digest: operation_facts_digest(&request.facts),
            mac: String::new(),
        };
        cancel.mac = compute_cancel_intent_mac_v2(&secret, &cancel);
        verify_cancel_intent_v2_message_auth(&secret, &cancel, 110).unwrap();
        cancel.target_nonce.push('x');
        assert!(verify_cancel_intent_v2_message_auth(&secret, &cancel, 110).is_err());
    }

    #[test]
    fn v2_digest_is_map_order_independent_but_value_sensitive() {
        let mut left = facts();
        let mut right = left.clone();
        right.sanitized_env = BTreeMap::new();
        assert_eq!(
            operation_facts_digest(&left),
            operation_facts_digest(&right)
        );
        left.sanitized_env
            .insert("LD_PRELOAD".into(), "evil.so".into());
        assert_ne!(
            operation_facts_digest(&left),
            operation_facts_digest(&right)
        );
    }

    #[test]
    fn v2_tenant_is_required_lowercase_hashes_are_strict_and_tenant_mutation_binds_mac() {
        let (secret, _verify, request, _peer) = signed_v2();
        let original_digest = operation_facts_digest(&request.facts);

        let mut changed = request.clone();
        changed.facts.tenant_id = "tenant-2".into();
        assert_ne!(original_digest, operation_facts_digest(&changed.facts));
        changed.mac = compute_mac_v2(&secret, &changed);
        assert_ne!(request.mac, changed.mac);

        let mut missing_tenant = serde_json::to_value(&request).unwrap();
        missing_tenant
            .get_mut("facts")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("tenant_id");
        assert!(parse_broker_request_v2(&serde_json::to_vec(&missing_tenant).unwrap()).is_err());

        let mut uppercase_hash = request.clone();
        uppercase_hash.facts.remote_payload_sha256 = "A".repeat(64);
        uppercase_hash.mac = compute_mac_v2(&secret, &uppercase_hash);
        assert!(verify_request_v2_message_auth(&secret, &uppercase_hash, 110).is_err());
    }
}
