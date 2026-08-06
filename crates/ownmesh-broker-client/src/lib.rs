//! OwnMesh client library for the privileged broker.
//!
//! Capability tokens, request signing, OS-local transport, and networkless protocol types.
//! The broker itself never opens non-loopback network listeners.

mod transport;

pub use transport::{
    broker_endpoint_display, connect_and_call, default_broker_endpoint, is_loopback_socket_addr,
    resolve_broker_endpoint, BrokerEndpoint, PeerCred, TransportKind,
};

use hmac::{Hmac, Mac};
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

/// Domain separation tag for capability MAC payload.
const CAPABILITY_MAC_DOMAIN: &[u8] = b"ownmesh-broker-cap-mac-v1";

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

/// Shared secret material for MAC (stored in OS keystore in production).
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

/// Capability token bound to a caller principal, scope, and operation (MAC over claims).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    pub token_id: String,
    pub principal: String,
    pub scope: String,
    /// Operation this token is authorized to invoke (bound at issue time).
    #[serde(default)]
    pub operation_id: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    /// hex-encoded HMAC-SHA256.
    pub mac: String,
}

impl CapabilityToken {
    /// Issue a capability token for `principal` with the given `scope`.
    ///
    /// Prefer [`Self::issue_for_operation`] so the token is bound to a concrete operation.
    #[must_use]
    pub fn issue(
        secret: &BrokerSecret,
        principal: impl Into<String>,
        scope: impl Into<String>,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Self {
        Self::issue_for_operation(secret, principal, scope, String::new(), now_unix, ttl_secs)
    }

    /// Issue a capability token bound to `principal`, `scope`, and `operation_id`.
    #[must_use]
    pub fn issue_for_operation(
        secret: &BrokerSecret,
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
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + ttl_secs,
            mac: String::new(),
        };
        tok.mac = compute_capability_mac(secret, &tok);
        tok
    }

    /// Verify HMAC + expiry + non-empty identity fields.
    pub fn verify(&self, secret: &BrokerSecret, now_unix: i64) -> BrokerResult<()> {
        if now_unix > self.expires_at_unix {
            return Err(BrokerError::Expired);
        }
        let expected = compute_capability_mac(secret, self);
        if !constant_time_hex_eq(&expected, &self.mac) {
            return Err(BrokerError::BadSignature);
        }
        if self.principal.trim().is_empty() || self.token_id.trim().is_empty() {
            return Err(BrokerError::InvalidToken);
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
    pub caller_principal: String,
    /// Capability token (required on every verified request).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityToken>,
    pub command: ElevatedCommand,
    /// hex-encoded HMAC-SHA256 over typed canonical payload.
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

fn put_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    put_u32(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn put_str(buf: &mut Vec<u8>, s: &str) {
    put_bytes(buf, s.as_bytes());
}

/// Typed, field-fixed canonical bytes for a capability token (excludes MAC).
fn canonical_capability_bytes(tok: &CapabilityToken) -> Vec<u8> {
    let mut buf = Vec::with_capacity(128);
    buf.extend_from_slice(CAPABILITY_MAC_DOMAIN);
    put_str(&mut buf, &tok.token_id);
    put_str(&mut buf, &tok.principal);
    put_str(&mut buf, &tok.scope);
    put_str(&mut buf, &tok.operation_id);
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
            put_i64(&mut buf, cap.issued_at_unix);
            put_i64(&mut buf, cap.expires_at_unix);
            put_str(&mut buf, &cap.mac);
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

fn compute_capability_mac(secret: &BrokerSecret, tok: &CapabilityToken) -> String {
    hmac_hex(secret, &canonical_capability_bytes(tok))
}

/// Compute request HMAC-SHA256 over the typed canonical payload.
#[must_use]
pub fn compute_mac(secret: &BrokerSecret, req: &BrokerRequest) -> String {
    hmac_hex(secret, &canonical_request_bytes(req))
}

/// Build a signed request with a freshly issued, operation-bound capability token.
#[must_use]
pub fn build_request(
    secret: &BrokerSecret,
    caller_principal: impl Into<String>,
    operation_id: impl Into<String>,
    command: ElevatedCommand,
    now_unix: i64,
    ttl_secs: i64,
) -> BrokerRequest {
    let caller = caller_principal.into();
    let op = operation_id.into();
    let cap_ttl = ttl_secs.max(DEFAULT_CAPABILITY_TTL_SECS);
    let cap = CapabilityToken::issue_for_operation(
        secret,
        caller.clone(),
        ELEVATED_CAPABILITY_SCOPE,
        op.clone(),
        now_unix,
        cap_ttl,
    );
    build_request_with_capability(secret, caller, op, command, Some(cap), now_unix, ttl_secs)
}

/// Build a signed request, optionally attaching a capability token.
///
/// Production verify paths require a valid capability; pass `Some(...)` (or use
/// [`build_request`] / [`elevate`], which issue one automatically).
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

/// Verify request HMAC, expiry, protocol version, and required capability bindings.
///
/// Does not check the replay set. Capability is always required and must bind
/// `scope == ELEVATED_CAPABILITY_SCOPE`, `operation_id == req.operation_id`, and principal.
pub fn verify_request(
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
    // length guards
    if req.command.program.is_empty() {
        return Err(BrokerError::Protocol("empty program".into()));
    }
    if req.command.program.len() > 4096 || req.command.args.iter().any(|a| a.len() > 8192) {
        return Err(BrokerError::Protocol("command too large".into()));
    }
    if req.command.env.len() > 256 {
        return Err(BrokerError::Protocol("too many env vars".into()));
    }

    let cap = req.capability.as_ref().ok_or(BrokerError::InvalidToken)?;
    cap.verify(secret, now_unix)?;
    if cap.principal != req.caller_principal {
        return Err(BrokerError::Unauthorized);
    }
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

/// High-level helper: sign + send elevated command.
pub async fn elevate(
    endpoint: &BrokerEndpoint,
    secret: &BrokerSecret,
    caller_principal: impl Into<String>,
    operation_id: impl Into<String>,
    command: ElevatedCommand,
    now_unix: i64,
    ttl_secs: i64,
) -> BrokerResult<BrokerResponse> {
    let caller = caller_principal.into();
    let op = operation_id.into();
    let cap = CapabilityToken::issue_for_operation(
        secret,
        caller.clone(),
        ELEVATED_CAPABILITY_SCOPE,
        op.clone(),
        now_unix,
        ttl_secs.max(DEFAULT_CAPABILITY_TTL_SECS),
    );
    let req =
        build_request_with_capability(secret, caller, op, command, Some(cap), now_unix, ttl_secs);
    connect_and_call(endpoint, &req).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_and_verify() {
        let secret = BrokerSecret::generate();
        let cmd = ElevatedCommand {
            program: "whoami".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };
        let req = build_request(&secret, "daemon", "op1", cmd, 1_000, 60);
        assert!(req.capability.is_some());
        verify_request(&secret, &req, 1_010).unwrap();
        assert!(verify_request(&secret, &req, 2_000).is_err());
    }

    #[test]
    fn rejects_tamper_and_replay() {
        let secret = BrokerSecret::generate();
        let mut req = build_request(
            &secret,
            "daemon",
            "op1",
            ElevatedCommand {
                program: "id".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            100,
            50,
        );
        req.command.program = "evil".into();
        assert!(verify_request(&secret, &req, 110).is_err());

        let req = build_request(
            &secret,
            "daemon",
            "op1",
            ElevatedCommand {
                program: "id".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            100,
            50,
        );
        let mut cache = ReplayCache::new();
        cache.check_and_insert(&req).unwrap();
        assert!(cache.check_and_insert(&req).is_err());
    }

    #[test]
    fn capability_token_roundtrip_and_mismatch() {
        let secret = BrokerSecret::generate();
        let tok = CapabilityToken::issue_for_operation(
            &secret,
            "ownmeshd",
            ELEVATED_CAPABILITY_SCOPE,
            "op",
            1000,
            60,
        );
        tok.verify(&secret, 1010).unwrap();
        assert!(tok.verify(&secret, 2000).is_err());

        let mut bad = tok.clone();
        bad.principal = "other".into();
        assert!(bad.verify(&secret, 1010).is_err());

        let cmd = ElevatedCommand {
            program: "true".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };
        let req =
            build_request_with_capability(&secret, "ownmeshd", "op", cmd, Some(tok), 1000, 60);
        verify_request(&secret, &req, 1010).unwrap();

        let mut mismatched = req;
        mismatched.caller_principal = "evil".into();
        mismatched.mac = compute_mac(&secret, &mismatched);
        // capability principal != caller
        assert!(matches!(
            verify_request(&secret, &mismatched, 1010),
            Err(BrokerError::Unauthorized)
        ));
    }

    #[test]
    fn rejects_missing_capability() {
        let secret = BrokerSecret::generate();
        let mut req = build_request(
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
        req.capability = None;
        req.mac = compute_mac(&secret, &req);
        assert!(matches!(
            verify_request(&secret, &req, 1010),
            Err(BrokerError::InvalidToken)
        ));
    }

    #[test]
    fn rejects_scope_and_operation_mismatch() {
        let secret = BrokerSecret::generate();
        let cmd = ElevatedCommand {
            program: "true".into(),
            args: vec![],
            cwd: None,
            env: vec![],
        };

        let wrong_scope = CapabilityToken::issue_for_operation(
            &secret,
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
            verify_request(&secret, &req, 1010),
            Err(BrokerError::Unauthorized)
        ));

        let wrong_op = CapabilityToken::issue_for_operation(
            &secret,
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
            verify_request(&secret, &req, 1010),
            Err(BrokerError::Unauthorized)
        ));
    }

    #[test]
    fn malformed_requests_rejected() {
        let secret = BrokerSecret::generate();
        let mut req = build_request(
            &secret,
            "ownmeshd",
            "op",
            ElevatedCommand {
                program: "x".into(),
                args: vec![],
                cwd: None,
                env: vec![],
            },
            10,
            30,
        );
        req.protocol_version = 99;
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &req, 11).is_err());

        req.protocol_version = BROKER_PROTOCOL_VERSION;
        req.command.program = String::new();
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &req, 11).is_err());

        req.command.program = "x".repeat(5000);
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &req, 11).is_err());

        req.command.program = "ok".into();
        req.nonce = String::new();
        req.mac = compute_mac(&secret, &req);
        assert!(verify_request(&secret, &req, 11).is_err());
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
}
