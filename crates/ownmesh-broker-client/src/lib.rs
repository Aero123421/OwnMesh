//! `OwnMesh` client library for the privileged broker.
//!
//! Capability tokens, request signing, OS-local transport, and networkless protocol types.
//! The broker itself never opens non-loopback network listeners.

mod transport;

pub use transport::{
    broker_endpoint_display, connect_and_call, default_broker_endpoint, is_loopback_socket_addr,
    resolve_broker_endpoint, BrokerEndpoint, PeerCred, TransportKind,
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

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

/// Capability token bound to a caller principal (MAC over claims).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    pub token_id: String,
    pub principal: String,
    pub scope: String,
    pub issued_at_unix: i64,
    pub expires_at_unix: i64,
    /// hex-encoded MAC.
    pub mac: String,
}

impl CapabilityToken {
    /// Issue a new capability token for `principal`.
    #[must_use]
    pub fn issue(
        secret: &BrokerSecret,
        principal: impl Into<String>,
        scope: impl Into<String>,
        now_unix: i64,
        ttl_secs: i64,
    ) -> Self {
        let mut tok = Self {
            token_id: format!("cap_{}", Uuid::new_v4().simple()),
            principal: principal.into(),
            scope: scope.into(),
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + ttl_secs,
            mac: String::new(),
        };
        tok.mac = compute_capability_mac(secret, &tok);
        tok
    }

    /// Verify the MAC, expiry, and required identity fields.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Expired`] for an expired token,
    /// [`BrokerError::BadSignature`] for a MAC mismatch, or
    /// [`BrokerError::InvalidToken`] when required identity fields are empty.
    pub fn verify(&self, secret: &BrokerSecret, now_unix: i64) -> BrokerResult<()> {
        if now_unix > self.expires_at_unix {
            return Err(BrokerError::Expired);
        }
        let expected = compute_capability_mac(secret, self);
        if expected != self.mac {
            return Err(BrokerError::BadSignature);
        }
        if self.principal.trim().is_empty() || self.token_id.trim().is_empty() {
            return Err(BrokerError::InvalidToken);
        }
        Ok(())
    }
}

fn compute_capability_mac(secret: &BrokerSecret, tok: &CapabilityToken) -> String {
    let payload = format!(
        "cap|id={}|prin={}|scope={}|iat={}|exp={}",
        tok.token_id, tok.principal, tok.scope, tok.issued_at_unix, tok.expires_at_unix
    );
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
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
    /// Optional capability token (required in production paths).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityToken>,
    pub command: ElevatedCommand,
    /// hex-encoded MAC over canonical payload.
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

fn canonical_payload(req: &BrokerRequest) -> String {
    let cap = req
        .capability
        .as_ref()
        .map(|c| format!("{}:{}", c.token_id, c.mac))
        .unwrap_or_default();
    format!(
        "v={}|rid={}|oid={}|nonce={}|iat={}|exp={}|caller={}|cap={}|prog={}|args={}|cwd={}|env={}",
        req.protocol_version,
        req.request_id,
        req.operation_id,
        req.nonce,
        req.issued_at_unix,
        req.expires_at_unix,
        req.caller_principal,
        cap,
        req.command.program,
        serde_json::to_string(&req.command.args).unwrap_or_default(),
        req.command.cwd.clone().unwrap_or_default(),
        serde_json::to_string(&req.command.env).unwrap_or_default(),
    )
}

/// Compute MAC.
#[must_use]
pub fn compute_mac(secret: &BrokerSecret, req: &BrokerRequest) -> String {
    let mut h = Sha256::new();
    h.update(secret.as_bytes());
    h.update(canonical_payload(req).as_bytes());
    hex::encode(h.finalize())
}

/// Build a signed request (without capability token).
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

/// Build a signed request, optionally attaching a capability token.
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

/// Verify a request's MAC, expiry, protocol version, and optional capability.
///
/// This does not check a replay set.
///
/// # Errors
///
/// Returns an appropriate [`BrokerError`] if the request is expired, malformed,
/// signed incorrectly, uses an unsupported protocol, or has an invalid capability.
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
    if expected != req.mac {
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
    if let Some(cap) = &req.capability {
        cap.verify(secret, now_unix)?;
        if cap.principal != req.caller_principal {
            return Err(BrokerError::Unauthorized);
        }
    }
    Ok(())
}

/// Replay cache keyed by `nonce/request_id` with optional pruning by expiry.
#[derive(Debug, Default)]
pub struct ReplayCache {
    /// Key mapped to `expires_at_unix`.
    seen: HashMap<String, i64>,
}

impl ReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a request unless its request identifier and nonce were already seen.
    ///
    /// # Errors
    ///
    /// Returns [`BrokerError::Replay`] if the request is already cached.
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

/// Sign and send an elevated command.
///
/// # Errors
///
/// Returns a [`BrokerError`] if endpoint validation, connection, request writing,
/// response reading, or response deserialization fails.
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
    let cap = CapabilityToken::issue(
        secret,
        caller.clone(),
        "elevated.exec",
        now_unix,
        ttl_secs.max(DEFAULT_CAPABILITY_TTL_SECS),
    );
    let req = build_request_with_capability(
        secret,
        caller,
        operation_id,
        command,
        Some(cap),
        now_unix,
        ttl_secs,
    );
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
        let tok = CapabilityToken::issue(&secret, "ownmeshd", "elevated.exec", 1000, 60);
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
}
