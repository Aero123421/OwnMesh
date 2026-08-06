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

/// Load the device key from `store`, generating one when absent.
///
/// # Errors
///
/// Returns store / crypto errors.
pub fn load_or_create_device_key(store: &dyn SecretStore) -> IdentityResult<DeviceKeyPair> {
    if let Some(secret) = store.load(SecretPurpose::DevicePrivateKey)? {
        DeviceKeyPair::from_seed(secret.expose())
    } else {
        let key = DeviceKeyPair::generate();
        store.store(SecretPurpose::DevicePrivateKey, &key.seed_bytes())?;
        Ok(key)
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
pub fn load_human_refresh_token(store: &dyn SecretStore) -> IdentityResult<Option<SecretString>> {
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
}
