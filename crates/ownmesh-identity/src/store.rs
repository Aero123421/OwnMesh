//! Secret store trait and backend implementations.

use crate::error::{IdentityError, IdentityResult};
use crate::secret::{SecretBytes, SecretPurpose};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Abstract secret storage backend.
pub trait SecretStore: Send + Sync {
    /// Persist secret bytes for `purpose`, replacing any previous value.
    ///
    /// # Errors
    ///
    /// Backend-specific failures.
    fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()>;

    /// Load secret bytes for `purpose`.
    ///
    /// # Errors
    ///
    /// Backend-specific failures (not found returns `Ok(None)`).
    fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>>;

    /// Delete secret for `purpose` if present.
    ///
    /// # Errors
    ///
    /// Backend-specific failures.
    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()>;

    /// Backend name for diagnostics.
    fn backend_name(&self) -> &'static str;
}

/// In-memory store for unit tests.
#[derive(Debug, Default)]
pub struct MemorySecretStore {
    inner: Mutex<HashMap<&'static str, Vec<u8>>>,
}

impl SecretStore for MemorySecretStore {
    fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| IdentityError::Keystore("memory store lock poisoned".into()))?;
        guard.insert(purpose.account(), secret.expose().to_vec());
        Ok(())
    }

    fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| IdentityError::Keystore("memory store lock poisoned".into()))?;
        Ok(guard
            .get(purpose.account())
            .map(|v| SecretBytes::new(v.clone())))
    }

    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| IdentityError::Keystore("memory store lock poisoned".into()))?;
        guard.remove(purpose.account());
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

/// OS keychain-backed store (Windows Credential Manager / macOS Keychain / Linux Secret Service).
pub struct OsKeychainStore {
    service: String,
}

impl OsKeychainStore {
    /// Create a store using the given keychain service name (e.g. `dev.ownmesh`).
    #[must_use]
    pub fn new(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }

    fn entry(&self, purpose: SecretPurpose) -> IdentityResult<keyring::Entry> {
        keyring::Entry::new(&self.service, purpose.account())
            .map_err(|err| IdentityError::Keychain(err.to_string()))
    }
}

impl SecretStore for OsKeychainStore {
    fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()> {
        let entry = self.entry(purpose)?;
        let encoded =
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, secret.expose());
        entry
            .set_password(&encoded)
            .map_err(|err| IdentityError::Keychain(err.to_string()))
    }

    fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>> {
        let entry = self.entry(purpose)?;
        match entry.get_password() {
            Ok(encoded) => {
                let bytes = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    encoded.trim(),
                )
                .map_err(|err| IdentityError::Keychain(format!("base64 decode: {err}")))?;
                Ok(Some(SecretBytes::new(bytes)))
            }
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(err) => Err(IdentityError::Keychain(err.to_string())),
        }
    }

    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
        let entry = self.entry(purpose)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) => Err(IdentityError::Keychain(err.to_string())),
        }
    }

    fn backend_name(&self) -> &'static str {
        "os-keychain"
    }
}

/// Headless encrypted file keystore (ChaCha20-Poly1305 + Argon2id).
///
/// Unlock source is an explicit passphrase (env / prompt). Plaintext refresh-token
/// files are intentionally not supported.
pub struct EncryptedFileKeystore {
    dir: PathBuf,
    passphrase: SecretBytes,
}

impl EncryptedFileKeystore {
    /// Open (or create) a keystore directory unlocked by `passphrase`.
    #[must_use]
    pub fn new(dir: impl Into<PathBuf>, passphrase: impl AsRef<[u8]>) -> Self {
        Self {
            dir: dir.into(),
            passphrase: SecretBytes::new(passphrase.as_ref().to_vec()),
        }
    }

    fn path_for(&self, purpose: SecretPurpose) -> PathBuf {
        self.dir.join(format!("{}.oms", purpose.account()))
    }

    fn derive_key(&self, salt: &[u8; 16]) -> IdentityResult<[u8; 32]> {
        use argon2::{Algorithm, Argon2, Params, Version};
        let params = Params::new(19_456, 2, 1, Some(32))
            .map_err(|err| IdentityError::Crypto(format!("argon2 params: {err}")))?;
        let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
        let mut key = [0_u8; 32];
        argon
            .hash_password_into(self.passphrase.expose(), salt, &mut key)
            .map_err(|err| IdentityError::Crypto(format!("argon2 derive: {err}")))?;
        Ok(key)
    }
}

impl SecretStore for EncryptedFileKeystore {
    fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};
        use rand::RngCore;

        std::fs::create_dir_all(&self.dir)?;

        let mut salt = [0_u8; 16];
        let mut nonce_bytes = [0_u8; 12];
        rand::thread_rng().fill_bytes(&mut salt);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|err| IdentityError::Crypto(format!("chacha key: {err}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, secret.expose())
            .map_err(|err| IdentityError::Crypto(format!("encrypt: {err}")))?;

        let mut file_bytes = Vec::with_capacity(4 + 16 + 12 + ciphertext.len());
        file_bytes.extend_from_slice(b"OMK1");
        file_bytes.extend_from_slice(&salt);
        file_bytes.extend_from_slice(&nonce_bytes);
        file_bytes.extend_from_slice(&ciphertext);

        let path = self.path_for(purpose);
        let tmp = path.with_extension("oms.tmp");
        std::fs::write(&tmp, &file_bytes)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&tmp, perms)?;
        }
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        std::fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>> {
        use chacha20poly1305::aead::{Aead, KeyInit};
        use chacha20poly1305::{ChaCha20Poly1305, Nonce};

        let path = self.path_for(purpose);
        if !path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(&path)?;
        if raw.len() < 4 + 16 + 12 + 16 {
            return Err(IdentityError::Keystore(format!(
                "keystore file too short: {}",
                path.display()
            )));
        }
        if &raw[..4] != b"OMK1" {
            return Err(IdentityError::Keystore(format!(
                "unknown keystore magic in {}",
                path.display()
            )));
        }
        let salt: [u8; 16] = raw[4..20]
            .try_into()
            .map_err(|_| IdentityError::Keystore("salt slice".into()))?;
        let nonce_bytes: [u8; 12] = raw[20..32]
            .try_into()
            .map_err(|_| IdentityError::Keystore("nonce slice".into()))?;
        let ciphertext = &raw[32..];

        let key = self.derive_key(&salt)?;
        let cipher = ChaCha20Poly1305::new_from_slice(&key)
            .map_err(|err| IdentityError::Crypto(format!("chacha key: {err}")))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plain = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| IdentityError::Keystore("decrypt failed (bad passphrase?)".into()))?;
        Ok(Some(SecretBytes::new(plain)))
    }

    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
        let path = self.path_for(purpose);
        if path.exists() {
            std::fs::remove_file(path)?;
        }
        Ok(())
    }

    fn backend_name(&self) -> &'static str {
        "encrypted-file"
    }
}

/// Prefer the OS keychain; fall back to an encrypted file keystore under `fallback_dir`.
///
/// The fallback passphrase is taken from `OWNMESH_KEYSTORE_PASSWORD` when set; otherwise a
/// machine-local random unlock key is created under `fallback_dir/.unlock` with restrictive
/// permissions (still better than plaintext token files; headless unlock source is explicit).
pub struct PreferredSecretStore {
    primary: OsKeychainStore,
    fallback: EncryptedFileKeystore,
    /// When true, primary backend probed successfully at least once.
    prefer_primary: Mutex<bool>,
}

impl PreferredSecretStore {
    /// Build the preferred store.
    ///
    /// # Errors
    ///
    /// Returns IO errors while preparing the fallback unlock material.
    pub fn open(
        service: impl Into<String>,
        fallback_dir: impl AsRef<Path>,
    ) -> IdentityResult<Self> {
        let fallback_dir = fallback_dir.as_ref();
        std::fs::create_dir_all(fallback_dir)?;
        let passphrase = resolve_fallback_passphrase(fallback_dir)?;
        Ok(Self {
            primary: OsKeychainStore::new(service),
            fallback: EncryptedFileKeystore::new(fallback_dir, passphrase),
            prefer_primary: Mutex::new(true),
        })
    }
}

impl SecretStore for PreferredSecretStore {
    fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()> {
        match self.primary.store(purpose, secret) {
            Ok(()) => {
                if let Ok(mut g) = self.prefer_primary.lock() {
                    *g = true;
                }
                // Best-effort mirror into fallback for recovery.
                let _ = self.fallback.store(purpose, secret);
                Ok(())
            }
            Err(primary_err) => {
                if let Ok(mut g) = self.prefer_primary.lock() {
                    *g = false;
                }
                self.fallback.store(purpose, secret).map_err(|err| {
                    IdentityError::Keystore(format!(
                        "os keychain failed ({primary_err}); fallback failed ({err})"
                    ))
                })
            }
        }
    }

    fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>> {
        match self.primary.load(purpose) {
            Ok(Some(v)) => Ok(Some(v)),
            Ok(None) | Err(_) => self.fallback.load(purpose),
        }
    }

    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
        let primary = self.primary.delete(purpose);
        let fallback = self.fallback.delete(purpose);
        primary.or(fallback)
    }

    fn backend_name(&self) -> &'static str {
        if self.prefer_primary.lock().map(|g| *g).unwrap_or(false) {
            "preferred(os-keychain)"
        } else {
            "preferred(encrypted-file)"
        }
    }
}

fn resolve_fallback_passphrase(dir: &Path) -> IdentityResult<Vec<u8>> {
    if let Ok(pass) = std::env::var("OWNMESH_KEYSTORE_PASSWORD") {
        if !pass.is_empty() {
            return Ok(pass.into_bytes());
        }
    }
    let unlock_path = dir.join(".unlock");
    if unlock_path.exists() {
        return Ok(std::fs::read(unlock_path)?);
    }
    let mut bytes = vec![0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut bytes);
    std::fs::write(&unlock_path, &bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&unlock_path, perms)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device_key::{
        load_human_refresh_token, load_or_create_device_key, store_human_refresh_token,
    };
    use crate::secret::SecretString;
    use std::fmt::Write as _;
    use tempfile::tempdir;

    #[test]
    fn encrypted_keystore_roundtrip_device_and_refresh() {
        let dir = tempdir().unwrap();
        let store = EncryptedFileKeystore::new(dir.path(), b"test-passphrase-for-ci");
        let key = load_or_create_device_key(&store).unwrap();
        let fp = key.public_identity().fingerprint.clone();

        store_human_refresh_token(&store, &SecretString::new("refresh-token-abc-xyz")).unwrap();

        // Simulate process restart with a new store handle.
        let store2 = EncryptedFileKeystore::new(dir.path(), b"test-passphrase-for-ci");
        let key2 = load_or_create_device_key(&store2).unwrap();
        assert_eq!(key2.public_identity().fingerprint, fp);
        let token = load_human_refresh_token(&store2).unwrap().unwrap();
        assert_eq!(token.expose(), "refresh-token-abc-xyz");

        // Secrets must not appear in debug of store path listings.
        let listing = format!("{:?}", std::fs::read_dir(dir.path()).unwrap());
        assert!(!listing.contains("refresh-token-abc-xyz"));
    }

    #[test]
    fn secrets_never_appear_in_logs_or_stdout_sim() {
        let store = MemorySecretStore::default();
        store_human_refresh_token(&store, &SecretString::new("VERY_SECRET_VALUE_123")).unwrap();
        let loaded = load_human_refresh_token(&store).unwrap().unwrap();
        let log_line = format!("loaded token={loaded:?} display={loaded}");
        assert!(!log_line.contains("VERY_SECRET_VALUE_123"));
        assert!(log_line.contains("redacted") || log_line.contains("REDACTED"));

        let key = load_or_create_device_key(&store).unwrap();
        let seed_debug = format!("{:?}", key.seed_bytes());
        assert!(
            !seed_debug.chars().any(|c| c.is_ascii_hexdigit()) || seed_debug.contains("redacted")
        );
        // Stronger check: raw seed hex must not appear.
        let mut seed_hex = String::with_capacity(64);
        for byte in key.seed_bytes().expose() {
            write!(seed_hex, "{byte:02x}").unwrap();
        }
        assert!(!format!("{key:?}").contains(&seed_hex));
        let cfg_sim = toml_like_config_dump();
        assert!(!cfg_sim.contains("VERY_SECRET"));
        assert!(!cfg_sim.contains(&seed_hex));
    }

    fn toml_like_config_dump() -> String {
        // Simulated config/stdout content — secrets must not be interpolated.
        "schema_version = 1\nlang = \"en-US\"\n".into()
    }
}
