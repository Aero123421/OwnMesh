//! Secret-bearing types that never print their contents.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Owned secret bytes that redacted on `Debug` / `Display`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes {
    inner: Vec<u8>,
}

impl SecretBytes {
    /// Wrap raw bytes.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    /// Borrow the secret bytes.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.inner
    }

    /// Consume and return the raw bytes (caller becomes responsible for zeroization).
    #[must_use]
    pub fn into_inner(mut self) -> Vec<u8> {
        let mut out = Vec::new();
        std::mem::swap(&mut out, &mut self.inner);
        out
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true when empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes([redacted]; len={})", self.inner.len())
    }
}

impl fmt::Display for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // Serialization of secrets is intentionally opaque.
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s.into_bytes()))
    }
}

/// Owned secret UTF-8 string that redacts on `Debug` / `Display`.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Wrap a secret string.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            inner: value.into(),
        }
    }

    /// Borrow the secret string.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.inner
    }

    /// Bytes view.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretString([redacted]; len={})", self.inner.len())
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretString {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

/// Purpose / namespace for stored secrets so credentials never collide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecretPurpose {
    /// Ed25519 device private key seed (32 bytes).
    DevicePrivateKey,
    /// Human OAuth refresh token.
    HumanRefreshToken,
    /// Legacy short-lived enrollment proof material (not the long-lived credential).
    DeviceEnrollmentProof,
    /// Long-lived device credential (issuer + device_id bound envelope).
    DeviceCredential,
}

impl SecretPurpose {
    /// Stable keychain account name.
    #[must_use]
    pub const fn account(self) -> &'static str {
        match self {
            Self::DevicePrivateKey => "device-private-key",
            Self::HumanRefreshToken => "human-refresh-token",
            Self::DeviceEnrollmentProof => "device-enrollment-proof",
            Self::DeviceCredential => "device-credential",
        }
    }

    /// Human description for diagnostics (never includes secret material).
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::DevicePrivateKey => "device signing private key",
            Self::HumanRefreshToken => "human OAuth refresh token",
            Self::DeviceEnrollmentProof => "device enrollment proof",
            Self::DeviceCredential => "device connect credential",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_redacts_debug_display_and_json() {
        let secret = SecretString::new("super-secret-refresh-token-value");
        let debug = format!("{secret:?}");
        let display = format!("{secret}");
        let json = serde_json::to_string(&secret).unwrap();
        assert!(!debug.contains("super-secret"));
        assert!(!display.contains("super-secret"));
        assert!(!json.contains("super-secret"));
        assert!(debug.contains("redacted") || debug.contains("REDACTED"));
        assert_eq!(secret.expose(), "super-secret-refresh-token-value");
    }

    #[test]
    fn secret_bytes_redacts() {
        let secret = SecretBytes::new(b"private-key-material".to_vec());
        assert!(!format!("{secret:?}").contains("private-key"));
        assert_eq!(format!("{secret}"), "[REDACTED]");
    }
}
