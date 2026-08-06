//! OwnMesh optional device-to-device transfer planning.
//!
//! Direct/LAN encrypted transfer only by default. Cloud relay (R2/TURN/S3)
//! is never used as an implicit fallback.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use thiserror::Error;

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

/// Transfer errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TransferError {
    #[error("no direct path available and relay is disabled")]
    NoDirectPathRelayDisabled,
    #[error("relay not configured")]
    RelayNotConfigured,
    #[error("consent required from {0}")]
    ConsentRequired(String),
    #[error("size limit exceeded")]
    SizeLimit,
    #[error("hash mismatch")]
    HashMismatch,
    #[error("invalid plan: {0}")]
    Invalid(String),
    #[error("io: {0}")]
    Io(String),
}

pub type TransferResult<T> = Result<T, TransferError>;

/// Transport kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    LocalLoopback,
    LanDirect,
    /// Explicit opt-in only — never auto-selected.
    CloudRelay,
}

/// Transfer configuration (defaults safe).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferConfig {
    /// When false (default), CloudRelay is never chosen.
    #[serde(default)]
    pub relay_enabled: bool,
    #[serde(default)]
    pub relay_endpoint: Option<String>,
    #[serde(default = "default_max_bytes")]
    pub max_bytes: u64,
}

fn default_max_bytes() -> u64 {
    5 * 1024 * 1024 * 1024
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            relay_enabled: false,
            relay_endpoint: None,
            max_bytes: default_max_bytes(),
        }
    }
}

/// Consent flags.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferConsent {
    pub sender_principal: String,
    pub receiver_principal: String,
    pub sender_ok: bool,
    pub receiver_ok: bool,
}

/// Transfer plan before bytes move.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransferPlan {
    pub id: String,
    pub source_path: String,
    pub dest_path: String,
    pub size_bytes: u64,
    pub sha256: String,
    pub transport: TransportKind,
    pub chunk_size: u64,
}

/// Planner inputs.
#[derive(Debug, Clone)]
pub struct PlanRequest {
    pub source: PathBuf,
    pub dest: PathBuf,
    pub direct_path_available: bool,
    pub lan_available: bool,
    pub consent: TransferConsent,
}

/// Build a plan or fail closed (no silent relay).
pub fn plan_transfer(cfg: &TransferConfig, req: &PlanRequest) -> TransferResult<TransferPlan> {
    if !req.consent.sender_ok || !req.consent.receiver_ok {
        let who = if !req.consent.sender_ok {
            req.consent.sender_principal.clone()
        } else {
            req.consent.receiver_principal.clone()
        };
        return Err(TransferError::ConsentRequired(who));
    }
    let meta = std::fs::metadata(&req.source).map_err(|e| TransferError::Io(e.to_string()))?;
    if !meta.is_file() {
        return Err(TransferError::Invalid("source must be a file".into()));
    }
    if meta.len() > cfg.max_bytes {
        return Err(TransferError::SizeLimit);
    }
    let sha = hash_file(&req.source)?;
    let transport = select_transport(cfg, req.direct_path_available, req.lan_available)?;
    Ok(TransferPlan {
        id: format!("xfer_{sha:.16}"),
        source_path: req.source.to_string_lossy().into_owned(),
        dest_path: req.dest.to_string_lossy().into_owned(),
        size_bytes: meta.len(),
        sha256: sha,
        transport,
        chunk_size: 1024 * 1024,
    })
}

fn select_transport(
    cfg: &TransferConfig,
    direct: bool,
    lan: bool,
) -> TransferResult<TransportKind> {
    if direct {
        return Ok(TransportKind::LocalLoopback);
    }
    if lan {
        return Ok(TransportKind::LanDirect);
    }
    // No direct path — must NOT fall back to cloud unless explicitly enabled+configured.
    if cfg.relay_enabled {
        if cfg.relay_endpoint.as_ref().is_some_and(|s| !s.is_empty()) {
            return Ok(TransportKind::CloudRelay);
        }
        return Err(TransferError::RelayNotConfigured);
    }
    Err(TransferError::NoDirectPathRelayDisabled)
}

/// Copy local file with hash verification (loopback path).
pub fn execute_local_copy(plan: &TransferPlan) -> TransferResult<()> {
    if plan.transport != TransportKind::LocalLoopback {
        return Err(TransferError::Invalid(
            "execute_local_copy only for LocalLoopback".into(),
        ));
    }
    let data = std::fs::read(&plan.source_path).map_err(|e| TransferError::Io(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&data);
    let actual = hex::encode(h.finalize());
    if actual != plan.sha256 {
        return Err(TransferError::HashMismatch);
    }
    if let Some(parent) = Path::new(&plan.dest_path).parent() {
        std::fs::create_dir_all(parent).map_err(|e| TransferError::Io(e.to_string()))?;
    }
    std::fs::write(&plan.dest_path, data).map_err(|e| TransferError::Io(e.to_string()))?;
    Ok(())
}

fn hash_file(path: &Path) -> TransferResult<String> {
    let data = std::fs::read(path).map_err(|e| TransferError::Io(e.to_string()))?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(hex::encode(h.finalize()))
}

/// True if a transport choice would require cloud relay addon.
#[must_use]
pub fn requires_relay(kind: TransportKind) -> bool {
    matches!(kind, TransportKind::CloudRelay)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn consent() -> TransferConsent {
        TransferConsent {
            sender_principal: "a".into(),
            receiver_principal: "b".into(),
            sender_ok: true,
            receiver_ok: true,
        }
    }

    #[test]
    fn no_direct_path_fails_without_relay() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("f.bin");
        std::fs::write(&src, b"data").unwrap();
        let cfg = TransferConfig::default();
        assert!(!cfg.relay_enabled);
        let err = plan_transfer(
            &cfg,
            &PlanRequest {
                source: src,
                dest: dir.path().join("out.bin"),
                direct_path_available: false,
                lan_available: false,
                consent: consent(),
            },
        )
        .unwrap_err();
        assert_eq!(err, TransferError::NoDirectPathRelayDisabled);
    }

    #[test]
    fn does_not_auto_fallback_to_unconfigured_relay() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("f.bin");
        std::fs::write(&src, b"data").unwrap();
        let cfg = TransferConfig {
            relay_enabled: true,
            relay_endpoint: None,
            max_bytes: 1_000_000,
        };
        let err = plan_transfer(
            &cfg,
            &PlanRequest {
                source: src,
                dest: dir.path().join("out.bin"),
                direct_path_available: false,
                lan_available: false,
                consent: consent(),
            },
        )
        .unwrap_err();
        assert_eq!(err, TransferError::RelayNotConfigured);
    }

    #[test]
    fn local_copy_ok() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("f.bin");
        let dst = dir.path().join("out.bin");
        std::fs::write(&src, b"hello").unwrap();
        let cfg = TransferConfig::default();
        let plan = plan_transfer(
            &cfg,
            &PlanRequest {
                source: src,
                dest: dst.clone(),
                direct_path_available: true,
                lan_available: false,
                consent: consent(),
            },
        )
        .unwrap();
        assert_eq!(plan.transport, TransportKind::LocalLoopback);
        execute_local_copy(&plan).unwrap();
        assert_eq!(std::fs::read(dst).unwrap(), b"hello");
    }
}
