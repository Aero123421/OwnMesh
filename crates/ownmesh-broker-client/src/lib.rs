//! OwnMesh client library for the privileged broker.
//!
//! Capability tokens, request signing, and networkless local protocol types.
//! The broker itself never opens network sockets.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
        // Simple entropy without extra deps: mix uuid + time.
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
    format!(
        "v={}|rid={}|oid={}|nonce={}|iat={}|exp={}|caller={}|prog={}|args={}|cwd={}|env={}",
        req.protocol_version,
        req.request_id,
        req.operation_id,
        req.nonce,
        req.issued_at_unix,
        req.expires_at_unix,
        req.caller_principal,
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

/// Build a signed request.
#[must_use]
pub fn build_request(
    secret: &BrokerSecret,
    caller_principal: impl Into<String>,
    operation_id: impl Into<String>,
    command: ElevatedCommand,
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
        command,
        mac: String::new(),
    };
    req.mac = compute_mac(secret, &req);
    req
}

/// Verify request MAC, expiry, protocol version. Does not check replay set.
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
    let expected = compute_mac(secret, req);
    if expected != req.mac {
        return Err(BrokerError::BadSignature);
    }
    // length guards
    if req.command.program.len() > 4096 || req.command.args.iter().any(|a| a.len() > 8192) {
        return Err(BrokerError::Protocol("command too large".into()));
    }
    Ok(())
}

/// Replay cache keyed by nonce/request_id.
#[derive(Debug, Default)]
pub struct ReplayCache {
    seen: std::collections::HashSet<String>,
}

impl ReplayCache {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn check_and_insert(&mut self, req: &BrokerRequest) -> BrokerResult<()> {
        let key = format!("{}:{}", req.request_id, req.nonce);
        if !self.seen.insert(key) {
            return Err(BrokerError::Replay);
        }
        Ok(())
    }
}

/// Default local endpoint name (pipe / socket basename).
pub const DEFAULT_BROKER_ENDPOINT: &str = "ownmesh-privileged";

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
}
