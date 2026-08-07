//! Isolated demo shared-secret signature scheme (tests / legacy only).
//!
//! **Not part of the production update API.** Production verification uses the
//! embedded minisign trust root over `SHA256SUMS` (see [`crate::trust`]).

use crate::checksum::sha256_hex;
use crate::error::{UpdateError, UpdateResult};
use crate::settings::UpdateChannel;
use serde::{Deserialize, Serialize};

/// Legacy demo manifest (kept for historical unit tests only).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DemoManifest {
    /// Version string.
    pub version: String,
    /// Channel.
    pub channel: UpdateChannel,
    /// Download URL.
    pub url: String,
    /// Hex SHA-256 of the artifact.
    pub sha256: String,
    /// Hex demo signature over `version|url|sha256`.
    pub signature: String,
    /// Minimum protocol major.
    pub min_protocol: u32,
    /// Maximum protocol major.
    pub max_protocol: u32,
}

/// Demo signature: `sha256(secret || payload)`. Do not use in production.
#[must_use]
pub fn sign_demo_manifest_payload(secret: &[u8], manifest: &DemoManifest) -> String {
    let payload = format!("{}|{}|{}", manifest.version, manifest.url, manifest.sha256);
    let mut data = secret.to_vec();
    data.extend_from_slice(payload.as_bytes());
    sha256_hex(&data)
}

/// Verify a demo signature.
///
/// # Errors
///
/// Returns [`UpdateError::BadSignature`] on mismatch.
pub fn verify_demo_signature(secret: &[u8], manifest: &DemoManifest) -> UpdateResult<()> {
    let expected = sign_demo_manifest_payload(secret, manifest);
    if expected != manifest.signature {
        return Err(UpdateError::BadSignature);
    }
    Ok(())
}
