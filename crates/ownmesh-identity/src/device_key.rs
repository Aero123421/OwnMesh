//! Ed25519 device key generation and rotation.

use crate::error::{IdentityError, IdentityResult};
use crate::secret::{SecretBytes, SecretPurpose, SecretString};
use crate::store::SecretStore;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Public device identity material that is safe to log / upload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DevicePublicIdentity {
    /// Hex-encoded Ed25519 public key (32 bytes).
    pub public_key_hex: String,
    /// Short fingerprint (first 16 hex chars of SHA-256(public_key)).
    pub fingerprint: String,
}

/// Newly generated or loaded device key pair.
pub struct DeviceKeyPair {
    signing: SigningKey,
}

impl DeviceKeyPair {
    /// Generate a fresh device key.
    #[must_use]
    pub fn generate() -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        Self { signing }
    }

    /// Reconstruct from a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Invalid`] when the seed length is not 32.
    pub fn from_seed(seed: &[u8]) -> IdentityResult<Self> {
        if seed.len() != 32 {
            return Err(IdentityError::Invalid(format!(
                "device key seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(seed);
        Ok(Self {
            signing: SigningKey::from_bytes(&bytes),
        })
    }

    /// Raw 32-byte seed (secret).
    #[must_use]
    pub fn seed_bytes(&self) -> SecretBytes {
        SecretBytes::new(self.signing.to_bytes().to_vec())
    }

    /// Public identity.
    #[must_use]
    pub fn public_identity(&self) -> DevicePublicIdentity {
        let verifying = self.signing.verifying_key();
        let pk = verifying.to_bytes();
        let public_key_hex = hex_encode(&pk);
        let fingerprint = {
            let digest = Sha256::digest(pk);
            hex_encode(&digest)[..16].to_owned()
        };
        DevicePublicIdentity {
            public_key_hex,
            fingerprint,
        }
    }

    /// Sign a message.
    #[must_use]
    pub fn sign(&self, message: &[u8]) -> SecretBytes {
        let sig: Signature = self.signing.sign(message);
        SecretBytes::new(sig.to_bytes().to_vec())
    }

    /// Verify a signature with this key's public half.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::Crypto`] when verification fails.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> IdentityResult<()> {
        let verifying = self.signing.verifying_key();
        verify_with_public(&verifying, message, signature)
    }
}

impl std::fmt::Debug for DeviceKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let id = self.public_identity();
        f.debug_struct("DeviceKeyPair")
            .field("fingerprint", &id.fingerprint)
            .field("public_key_hex", &id.public_key_hex)
            .finish()
    }
}

fn verify_with_public(
    verifying: &VerifyingKey,
    message: &[u8],
    signature: &[u8],
) -> IdentityResult<()> {
    if signature.len() != 64 {
        return Err(IdentityError::Invalid(format!(
            "signature must be 64 bytes, got {}",
            signature.len()
        )));
    }
    let mut sig_bytes = [0_u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = Signature::from_bytes(&sig_bytes);
    verifying
        .verify(message, &sig)
        .map_err(|err| IdentityError::Crypto(format!("signature verification failed: {err}")))
}

/// Verify an Ed25519 signature using a hex-encoded public key and hex signature.
///
/// # Errors
///
/// Returns [`IdentityError::Invalid`] for malformed hex / lengths, or
/// [`IdentityError::Crypto`] when verification fails.
pub fn verify_from_public_key_hex(
    public_key_hex: &str,
    message: &[u8],
    signature_hex: &str,
) -> IdentityResult<()> {
    let pk_bytes = hex_decode(public_key_hex.trim())?;
    if pk_bytes.len() != 32 {
        return Err(IdentityError::Invalid(format!(
            "public key must be 32 bytes, got {}",
            pk_bytes.len()
        )));
    }
    let mut pk = [0_u8; 32];
    pk.copy_from_slice(&pk_bytes);
    let verifying = VerifyingKey::from_bytes(&pk).map_err(|err| {
        IdentityError::Invalid(format!("invalid ed25519 public key: {err}"))
    })?;
    let sig_bytes = hex_decode(signature_hex.trim())?;
    verify_with_public(&verifying, message, &sig_bytes)
}

/// Issuer + device bound device-connect credential (long-lived).
///
/// The plaintext credential is never included in `Debug` / `Display`.
#[derive(Clone)]
pub struct DeviceCredentialEnvelope {
    /// Control-plane issuer / base URL the credential was issued by.
    pub issuer: String,
    /// Device id the credential is bound to.
    pub device_id: String,
    credential: SecretString,
}

impl DeviceCredentialEnvelope {
    /// Borrow the raw device credential token.
    #[must_use]
    pub fn credential(&self) -> &SecretString {
        &self.credential
    }

    /// True when this envelope is bound to the given issuer + device_id.
    #[must_use]
    pub fn matches(&self, issuer: &str, device_id: &str) -> bool {
        normalize_issuer(&self.issuer) == normalize_issuer(issuer) && self.device_id == device_id
    }

    fn to_secret_bytes(&self) -> SecretBytes {
        // Stored only inside SecretStore backends (keychain / encrypted file).
        let payload = serde_json::json!({
            "v": 1,
            "issuer": self.issuer,
            "device_id": self.device_id,
            "credential": self.credential.expose(),
        });
        SecretBytes::new(payload.to_string().into_bytes())
    }

    fn from_secret_bytes(bytes: &SecretBytes) -> IdentityResult<Self> {
        let value: serde_json::Value = serde_json::from_slice(bytes.expose()).map_err(|err| {
            IdentityError::Invalid(format!("device credential envelope corrupt: {err}"))
        })?;
        let issuer = value
            .get("issuer")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let device_id = value
            .get("device_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        let credential = value
            .get("credential")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_owned();
        if issuer.is_empty() || device_id.is_empty() || credential.is_empty() {
            return Err(IdentityError::Invalid(
                "device credential envelope missing issuer, device_id, or credential".into(),
            ));
        }
        Ok(Self {
            issuer,
            device_id,
            credential: SecretString::new(credential),
        })
    }
}

impl std::fmt::Debug for DeviceCredentialEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCredentialEnvelope")
            .field("issuer", &self.issuer)
            .field("device_id", &self.device_id)
            .field("credential", &"[REDACTED]")
            .finish()
    }
}

impl std::fmt::Display for DeviceCredentialEnvelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "DeviceCredentialEnvelope(issuer={}, device_id={}, credential=[REDACTED])",
            self.issuer, self.device_id
        )
    }
}

/// Store a long-lived device credential bound to `issuer` + `device_id`.
///
/// Also clears any legacy [`SecretPurpose::DeviceEnrollmentProof`] entry so the
/// long-lived secret is not left under the wrong purpose.
///
/// # Errors
///
/// Returns store errors.
pub fn store_device_credential(
    store: &dyn SecretStore,
    issuer: &str,
    device_id: &str,
    credential: &SecretString,
) -> IdentityResult<()> {
    let issuer = normalize_issuer(issuer);
    if issuer.is_empty() || device_id.is_empty() || credential.expose().is_empty() {
        return Err(IdentityError::Invalid(
            "issuer, device_id, and credential are required".into(),
        ));
    }
    let envelope = DeviceCredentialEnvelope {
        issuer,
        device_id: device_id.to_owned(),
        credential: credential.clone(),
    };
    store.store(SecretPurpose::DeviceCredential, &envelope.to_secret_bytes())?;
    // Do not leave the long-lived credential under the legacy purpose.
    let _ = store.delete(SecretPurpose::DeviceEnrollmentProof);
    Ok(())
}

/// Load the stored device credential envelope, if any.
///
/// # Errors
///
/// Returns store / parse errors.
pub fn load_device_credential(
    store: &dyn SecretStore,
) -> IdentityResult<Option<DeviceCredentialEnvelope>> {
    match store.load(SecretPurpose::DeviceCredential)? {
        Some(bytes) => Ok(Some(DeviceCredentialEnvelope::from_secret_bytes(&bytes)?)),
        None => Ok(None),
    }
}

/// Load the credential token only when the stored envelope matches issuer + device_id.
///
/// # Errors
///
/// Returns store / parse errors. Mismatched bindings yield `Ok(None)`.
pub fn load_device_credential_for(
    store: &dyn SecretStore,
    issuer: &str,
    device_id: &str,
) -> IdentityResult<Option<SecretString>> {
    let Some(env) = load_device_credential(store)? else {
        return Ok(None);
    };
    if env.matches(issuer, device_id) {
        Ok(Some(env.credential))
    } else {
        Ok(None)
    }
}

/// Delete any stored device credential.
///
/// # Errors
///
/// Returns store errors.
pub fn delete_device_credential(store: &dyn SecretStore) -> IdentityResult<()> {
    store.delete(SecretPurpose::DeviceCredential)?;
    // Best-effort cleanup of legacy mis-stored long-lived material.
    let _ = store.delete(SecretPurpose::DeviceEnrollmentProof);
    Ok(())
}

fn normalize_issuer(issuer: &str) -> String {
    issuer.trim().trim_end_matches('/').to_owned()
}

/// Load the device key from `store`, generating one when absent.
///
/// # Errors
///
/// Returns store / crypto errors.
pub fn load_or_create_device_key(store: &dyn SecretStore) -> IdentityResult<DeviceKeyPair> {
    match store.load(SecretPurpose::DevicePrivateKey)? {
        Some(secret) => DeviceKeyPair::from_seed(secret.expose()),
        None => {
            let key = DeviceKeyPair::generate();
            store.store(SecretPurpose::DevicePrivateKey, &key.seed_bytes())?;
            Ok(key)
        }
    }
}

/// Rotate the device key, replacing the previous seed in `store`.
///
/// Returns `(new_key, old_public_identity)`.
///
/// # Errors
///
/// Returns store / crypto errors.
pub fn rotate_device_key(
    store: &dyn SecretStore,
) -> IdentityResult<(DeviceKeyPair, Option<DevicePublicIdentity>)> {
    let old_public = match store.load(SecretPurpose::DevicePrivateKey)? {
        Some(secret) => Some(DeviceKeyPair::from_seed(secret.expose())?.public_identity()),
        None => None,
    };
    let new_key = DeviceKeyPair::generate();
    store.store(SecretPurpose::DevicePrivateKey, &new_key.seed_bytes())?;
    Ok((new_key, old_public))
}

/// Store a human refresh token under its dedicated purpose.
///
/// # Errors
///
/// Returns store errors.
pub fn store_human_refresh_token(
    store: &dyn SecretStore,
    token: &SecretString,
) -> IdentityResult<()> {
    let bytes = SecretBytes::new(token.as_bytes().to_vec());
    store.store(SecretPurpose::HumanRefreshToken, &bytes)
}

/// Load a previously stored human refresh token.
///
/// # Errors
///
/// Returns store errors.
pub fn load_human_refresh_token(
    store: &dyn SecretStore,
) -> IdentityResult<Option<SecretString>> {
    Ok(store
        .load(SecretPurpose::HumanRefreshToken)?
        .map(|b| SecretString::new(String::from_utf8_lossy(b.expose()).into_owned())))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(input: &str) -> IdentityResult<Vec<u8>> {
    let s = input.trim();
    if !s.len().is_multiple_of(2) {
        return Err(IdentityError::Invalid(
            "hex string must have even length".into(),
        ));
    }
    if !s.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(IdentityError::Invalid(
            "hex string contains non-hex digits".into(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> IdentityResult<u8> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(IdentityError::Invalid("invalid hex digit".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemorySecretStore;

    #[test]
    fn generate_sign_verify() {
        let key = DeviceKeyPair::generate();
        let msg = b"ownmesh-device-challenge";
        let sig = key.sign(msg);
        key.verify(msg, sig.expose()).unwrap();
        assert!(!format!("{key:?}").contains("SigningKey"));
    }

    #[test]
    fn load_or_create_and_rotate() {
        let store = MemorySecretStore::default();
        let key1 = load_or_create_device_key(&store).unwrap();
        let key1b = load_or_create_device_key(&store).unwrap();
        assert_eq!(
            key1.public_identity().public_key_hex,
            key1b.public_identity().public_key_hex
        );
        let (key2, old) = rotate_device_key(&store).unwrap();
        assert_eq!(
            old.unwrap().public_key_hex,
            key1.public_identity().public_key_hex
        );
        assert_ne!(
            key1.public_identity().public_key_hex,
            key2.public_identity().public_key_hex
        );
    }

    #[test]
    fn verify_from_public_key_hex_accepts_valid_and_rejects_bad() {
        let key = DeviceKeyPair::generate();
        let msg = b"ownmesh-device-challenge:n:dev_1";
        let sig = key.sign(msg);
        let sig_hex = hex_encode(sig.expose());
        let pk = key.public_identity().public_key_hex;
        verify_from_public_key_hex(&pk, msg, &sig_hex).unwrap();
        assert!(verify_from_public_key_hex(&pk, b"tampered", &sig_hex).is_err());
        assert!(verify_from_public_key_hex(&pk, msg, &"00".repeat(64)).is_err());
    }

    #[test]
    fn device_credential_envelope_roundtrip_and_binding() {
        let store = MemorySecretStore::default();
        // Legacy purpose must not retain the long-lived credential.
        store
            .store(
                SecretPurpose::DeviceEnrollmentProof,
                &SecretBytes::new(b"legacy-dead".to_vec()),
            )
            .unwrap();
        let token = SecretString::new("dcred_test_token_value");
        store_device_credential(&store, "http://cp.example/", "dev_abc", &token).unwrap();
        assert!(store
            .load(SecretPurpose::DeviceEnrollmentProof)
            .unwrap()
            .is_none());

        let env = load_device_credential(&store).unwrap().unwrap();
        assert!(env.matches("http://cp.example", "dev_abc"));
        assert_eq!(env.credential().expose(), "dcred_test_token_value");
        assert!(!format!("{env:?}").contains("dcred_test_token_value"));
        assert!(!format!("{env}").contains("dcred_test_token_value"));

        let matched =
            load_device_credential_for(&store, "http://cp.example", "dev_abc").unwrap();
        assert_eq!(matched.unwrap().expose(), "dcred_test_token_value");
        assert!(load_device_credential_for(&store, "http://other", "dev_abc")
            .unwrap()
            .is_none());
        assert!(load_device_credential_for(&store, "http://cp.example", "dev_other")
            .unwrap()
            .is_none());

        delete_device_credential(&store).unwrap();
        assert!(load_device_credential(&store).unwrap().is_none());
    }
}
