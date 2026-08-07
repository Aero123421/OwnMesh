//! `OwnMesh` update channels, manifests, and verification.
//!
//! Telemetry and auto-phone-home are off by default.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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

/// Update errors.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpdateError {
    #[error("updates disabled")]
    Disabled,
    #[error("signature invalid")]
    BadSignature,
    #[error("checksum mismatch")]
    BadChecksum,
    #[error("channel unknown: {0}")]
    UnknownChannel(String),
    #[error("protocol incompatible: {0}")]
    ProtocolIncompatible(String),
}

pub type UpdateResult<T> = Result<T, UpdateError>;

/// Update mode — default off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    #[default]
    Off,
    Check,
    Notify,
    Download,
    Auto,
}

/// Release channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    Stable,
    Beta,
    Nightly,
}

/// Local update settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSettings {
    #[serde(default)]
    pub mode: UpdateMode,
    #[serde(default = "default_channel")]
    pub channel: UpdateChannel,
    /// `OwnMesh` project telemetry — must default false.
    #[serde(default)]
    pub telemetry_enabled: bool,
    #[serde(default)]
    pub crash_reports_opt_in: bool,
}

fn default_channel() -> UpdateChannel {
    UpdateChannel::Stable
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            mode: UpdateMode::Off,
            channel: UpdateChannel::Stable,
            telemetry_enabled: false,
            crash_reports_opt_in: false,
        }
    }
}

/// Remote manifest entry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateManifest {
    pub version: String,
    pub channel: UpdateChannel,
    pub url: String,
    pub sha256: String,
    /// hex-encoded signature over `version|url|sha256` (demo scheme).
    pub signature: String,
    pub min_protocol: u32,
    pub max_protocol: u32,
}

/// Verifies artifact bytes against a hexadecimal checksum.
///
/// # Errors
///
/// Returns [`UpdateError::BadChecksum`] when the computed checksum differs
/// from `expected_hex`.
pub fn verify_checksum(data: &[u8], expected_hex: &str) -> UpdateResult<()> {
    let mut h = Sha256::new();
    h.update(data);
    let actual = hex::encode(h.finalize());
    if actual != expected_hex {
        return Err(UpdateError::BadChecksum);
    }
    Ok(())
}

/// Demo signature: sha256(secret || payload). Production uses real signing keys (see ADR).
#[must_use]
pub fn sign_manifest_payload(secret: &[u8], manifest: &UpdateManifest) -> String {
    let payload = format!("{}|{}|{}", manifest.version, manifest.url, manifest.sha256);
    let mut h = Sha256::new();
    h.update(secret);
    h.update(payload.as_bytes());
    hex::encode(h.finalize())
}

/// Verifies the manifest's demo signature.
///
/// # Errors
///
/// Returns [`UpdateError::BadSignature`] when the signature does not match.
pub fn verify_signature(secret: &[u8], manifest: &UpdateManifest) -> UpdateResult<()> {
    let expected = sign_manifest_payload(secret, manifest);
    if expected != manifest.signature {
        return Err(UpdateError::BadSignature);
    }
    Ok(())
}

/// Checks whether a local protocol version is supported by the manifest.
///
/// # Errors
///
/// Returns [`UpdateError::ProtocolIncompatible`] when `local_protocol` is
/// outside the manifest's inclusive protocol range.
pub fn check_protocol(manifest: &UpdateManifest, local_protocol: u32) -> UpdateResult<()> {
    if local_protocol < manifest.min_protocol || local_protocol > manifest.max_protocol {
        return Err(UpdateError::ProtocolIncompatible(format!(
            "local={local_protocol} range={}..{}",
            manifest.min_protocol, manifest.max_protocol
        )));
    }
    Ok(())
}

/// Whether any network check is permitted under settings.
#[must_use]
pub fn network_check_allowed(settings: &UpdateSettings) -> bool {
    !matches!(settings.mode, UpdateMode::Off)
}

/// Privacy guarantees for tests.
#[must_use]
pub fn default_sends_nothing_to_vendor(settings: &UpdateSettings) -> bool {
    !settings.telemetry_enabled
        && !settings.crash_reports_opt_in
        && settings.mode == UpdateMode::Off
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_private() {
        let s = UpdateSettings::default();
        assert!(default_sends_nothing_to_vendor(&s));
        assert!(!network_check_allowed(&s));
    }

    #[test]
    fn signature_and_checksum() {
        let secret = b"test-secret";
        let data = b"artifact";
        let mut h = Sha256::new();
        h.update(data);
        let sha = hex::encode(h.finalize());
        let mut m = UpdateManifest {
            version: "1.0.0".into(),
            channel: UpdateChannel::Stable,
            url: "https://example.invalid/ownmesh".into(),
            sha256: sha,
            signature: String::new(),
            min_protocol: 1,
            max_protocol: 1,
        };
        m.signature = sign_manifest_payload(secret, &m);
        verify_signature(secret, &m).unwrap();
        verify_checksum(data, &m.sha256).unwrap();
        check_protocol(&m, 1).unwrap();
        assert!(check_protocol(&m, 2).is_err());
    }
}
