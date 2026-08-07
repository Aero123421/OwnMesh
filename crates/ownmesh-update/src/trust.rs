//! Embedded minisign trust root for OwnMesh releases.

use crate::error::{UpdateError, UpdateResult};
use minisign_verify::{PublicKey, Signature};

/// Tracked OwnMesh minisign public key (docs/release-keys/minisign.pub).
///
/// Key ID (minisign comment form): `C596813EFB0946A4`
/// SHA-256 fingerprint of the decoded public-key blob:
/// `1450496b7af985f57466b4b5f0b9c985d6c3e96ed66ee2cebb4f5a94ba5775d9`
pub const EMBEDDED_MINISIGN_PUB: &str = include_str!("../../../docs/release-keys/minisign.pub");

/// Minisign key ID advertised in the public-key untrusted comment.
pub const MINISIGN_KEY_ID: &str = "C596813EFB0946A4";

/// SHA-256 fingerprint (hex) of the 42-byte decoded public key blob.
pub const MINISIGN_FINGERPRINT_SHA256: &str =
    "1450496b7af985f57466b4b5f0b9c985d6c3e96ed66ee2cebb4f5a94ba5775d9";

/// Trust root used to verify `SHA256SUMS.minisig`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustRoot {
    /// Full minisign public key file contents (comment + base64 line).
    pub public_key_file: String,
}

impl Default for TrustRoot {
    fn default() -> Self {
        Self {
            public_key_file: EMBEDDED_MINISIGN_PUB.to_owned(),
        }
    }
}

impl TrustRoot {
    /// Build a trust root from an arbitrary minisign public key file (tests / rotation drills).
    #[must_use]
    pub fn from_public_key_file(contents: impl Into<String>) -> Self {
        Self {
            public_key_file: contents.into(),
        }
    }

    /// Verify `signed_data` against a detached minisign signature.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::BadSignature`] when the key or signature is invalid.
    pub fn verify_detached(&self, signed_data: &[u8], signature: &str) -> UpdateResult<()> {
        let pk = PublicKey::from_base64(public_key_base64(&self.public_key_file)?)
            .map_err(|_| UpdateError::BadSignature)?;
        let sig = Signature::decode(signature).map_err(|_| UpdateError::BadSignature)?;
        pk.verify(signed_data, &sig, true)
            .map_err(|_| UpdateError::BadSignature)?;
        Ok(())
    }
}

fn public_key_base64(file: &str) -> UpdateResult<&str> {
    for line in file.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("untrusted comment:") {
            continue;
        }
        return Ok(trimmed);
    }
    Err(UpdateError::BadSignature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_key_parses() {
        let root = TrustRoot::default();
        assert!(public_key_base64(&root.public_key_file).is_ok());
        assert!(root.public_key_file.contains(MINISIGN_KEY_ID));
    }
}
