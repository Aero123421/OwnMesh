//! PKCE S256 helpers (RFC 7636).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use rand::RngCore;
use sha2::{Digest, Sha256};

/// PKCE code verifier + S256 challenge pair.
#[derive(Debug, Clone)]
pub struct PkcePair {
    /// High-entropy `code_verifier` (43–128 chars, unreserved).
    pub verifier: String,
    /// BASE64URL-ENCODE(SHA256(verifier)) without padding.
    pub challenge: String,
}

/// Generate a new PKCE S256 pair.
#[must_use]
pub fn generate_pkce() -> PkcePair {
    let mut raw = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut raw);
    let verifier = URL_SAFE_NO_PAD.encode(raw);
    let digest = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(digest);
    PkcePair {
        verifier,
        challenge,
    }
}

/// Generate an opaque OAuth `state` parameter.
#[must_use]
pub fn generate_state() -> String {
    let mut raw = [0_u8; 16];
    rand::thread_rng().fill_bytes(&mut raw);
    URL_SAFE_NO_PAD.encode(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_shape() {
        let p = generate_pkce();
        assert!(p.verifier.len() >= 43);
        assert!(!p.challenge.contains('='));
        assert!(!p.challenge.contains('+'));
        // Recompute challenge
        let digest = Sha256::digest(p.verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(digest);
        assert_eq!(p.challenge, expected);
    }
}
