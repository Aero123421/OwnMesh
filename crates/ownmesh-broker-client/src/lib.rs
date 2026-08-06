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
    clippy::cast_possible_wrap
)]

mod transport;

pub use transport::{
    broker_endpoint_display, connect_and_call, default_broker_endpoint, is_loopback_socket_addr,
    resolve_broker_endpoint, BrokerEndpoint, PeerCred, TransportKind,
};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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
