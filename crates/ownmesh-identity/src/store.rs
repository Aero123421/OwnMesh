//! Secret store trait and backend implementations.

use crate::error::{IdentityError, IdentityResult};
use crate::secret::{SecretBytes, SecretPurpose};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Apply owner-only permissions to secret material before it is committed.
#[cfg_attr(not(unix), allow(clippy::unnecessary_wraps))]
fn restrict_secret_file(file: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    {
        let _ = file;
    }
    Ok(())
}

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
        // The shared primitive applies permissions before writing, syncs the
        // encrypted bytes, and atomically replaces without pre-deleting `path`.
        ownmesh_persist::write_atomically_with(&path, &file_bytes, restrict_secret_file)?;
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

/// Prefer a primary backend (typically the OS keychain); fall back to a secondary store.
///
/// Production default is OS keychain + encrypted file keystore under `fallback_dir`.
/// The fallback passphrase is taken from `OWNMESH_KEYSTORE_PASSWORD` when set; otherwise a
/// machine-local random unlock key is created under `fallback_dir/.unlock` with restrictive
/// permissions (still better than plaintext token files; headless unlock source is explicit).
///
/// When primary `store` succeeds, the secret is **not** mirrored into the fallback backend.
/// `delete` evaluates both backends and surfaces real errors from either side
/// (`NoEntry`-equivalent success is handled inside each backend).
pub struct PreferredSecretStore<P = OsKeychainStore, F = EncryptedFileKeystore> {
    primary: P,
    fallback: F,
    /// When true, primary backend probed successfully at least once.
    prefer_primary: Mutex<bool>,
}

/// Known secret purposes scanned during legacy mirror cleanup.
const LEGACY_MIRROR_CLEANUP_PURPOSES: &[SecretPurpose] = &[
    SecretPurpose::DevicePrivateKey,
    SecretPurpose::HumanRefreshToken,
    SecretPurpose::DeviceEnrollmentProof,
];

impl PreferredSecretStore<OsKeychainStore, EncryptedFileKeystore> {
    /// Build the preferred store with OS keychain primary and encrypted-file fallback.
    ///
    /// Runs [`Self::cleanup_legacy_fallback_mirrors`] so old dual-write mirror copies left in
    /// the fallback backend are removed when primary is authoritative for the same secret.
    ///
    /// # Errors
    ///
    /// Returns IO errors while preparing the fallback unlock material, or cleanup errors
    /// when primary/fallback cannot be verified or a confirmed mirror delete fails.
    pub fn open(
        service: impl Into<String>,
        fallback_dir: impl AsRef<Path>,
    ) -> IdentityResult<Self> {
        let fallback_dir = fallback_dir.as_ref();
        std::fs::create_dir_all(fallback_dir)?;
        let passphrase = resolve_fallback_passphrase(fallback_dir)?;
        let store = Self::from_backends(
            OsKeychainStore::new(service),
            EncryptedFileKeystore::new(fallback_dir, passphrase),
        );
        store.cleanup_legacy_fallback_mirrors()?;
        Ok(store)
    }
}

impl<P, F> PreferredSecretStore<P, F> {
    /// Construct from explicit backends (used by production `open` and unit tests).
    ///
    /// Does **not** run legacy mirror cleanup; call
    /// [`Self::cleanup_legacy_fallback_mirrors`] explicitly when backends implement
    /// [`SecretStore`], or use [`Self::open`] for the production path.
    #[must_use]
    pub fn from_backends(primary: P, fallback: F) -> Self {
        Self {
            primary,
            fallback,
            prefer_primary: Mutex::new(true),
        }
    }
}

impl<P: SecretStore, F: SecretStore> PreferredSecretStore<P, F> {
    /// Delete legacy fallback mirror copies when primary holds the identical secret.
    ///
    /// Idempotent migration helper for older builds that mirrored successful primary
    /// writes into the fallback backend. Safety rules:
    ///
    /// - Delete fallback **only** when primary `load` succeeds with `Some` and the
    ///   bytes are identical to the fallback entry (confirmed mirror).
    /// - If primary has no entry, keep fallback (it may be the only copy).
    /// - If secrets differ, keep fallback (not a mirror of primary).
    /// - If primary `load` fails, **do not** delete fallback and return an error
    ///   (never remove secrets while primary is unverified).
    /// - Fallback `load` / confirmed-mirror `delete` failures are returned, never
    ///   swallowed (no silent cleanup that could hide secret-loss risk).
    ///
    /// # Errors
    ///
    /// Primary/fallback load failures, or delete failure after a confirmed mirror match.
    pub fn cleanup_legacy_fallback_mirrors(&self) -> IdentityResult<()> {
        for &purpose in LEGACY_MIRROR_CLEANUP_PURPOSES {
            let primary_secret = match self.primary.load(purpose) {
                Ok(value) => value,
                Err(err) => {
                    return Err(IdentityError::Keystore(format!(
                        "legacy mirror cleanup: primary load failed for {}: {err}; fallback entry retained",
                        purpose.account()
                    )));
                }
            };
            let Some(primary_secret) = primary_secret else {
                // Primary missing — fallback may be the sole copy; never delete.
                continue;
            };

            let fallback_secret = match self.fallback.load(purpose) {
                Ok(value) => value,
                Err(err) => {
                    return Err(IdentityError::Keystore(format!(
                        "legacy mirror cleanup: fallback load failed for {}: {err}",
                        purpose.account()
                    )));
                }
            };
            let Some(fallback_secret) = fallback_secret else {
                continue;
            };

            if primary_secret.expose() != fallback_secret.expose() {
                // Distinct material — not a legacy mirror of primary.
                continue;
            }

            // Primary is authoritative and bytes match: safe to drop the mirror copy.
            self.fallback.delete(purpose).map_err(|err| {
                IdentityError::Keystore(format!(
                    "legacy mirror cleanup: fallback delete failed for {}: {err}",
                    purpose.account()
                ))
            })?;
        }
        Ok(())
    }
}

/// Combine delete outcomes from both backends.
///
/// `NoEntry`/missing is already normalized to `Ok(())` by each backend. Any remaining
/// `Err` is a real failure and must not be swallowed when the other side succeeds.
fn combine_delete_results(
    primary: IdentityResult<()>,
    fallback: IdentityResult<()>,
) -> IdentityResult<()> {
    match (primary, fallback) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary_err), Ok(())) => Err(IdentityError::Keystore(format!(
            "primary delete failed ({primary_err}); fallback ok"
        ))),
        (Ok(()), Err(fallback_err)) => Err(IdentityError::Keystore(format!(
            "fallback delete failed ({fallback_err}); primary ok"
        ))),
        (Err(primary_err), Err(fallback_err)) => Err(IdentityError::Keystore(format!(
            "delete failed on both backends: primary ({primary_err}); fallback ({fallback_err})"
        ))),
    }
}

impl<P: SecretStore, F: SecretStore> SecretStore for PreferredSecretStore<P, F> {
    fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()> {
        match self.primary.store(purpose, secret) {
            Ok(()) => {
                if let Ok(mut g) = self.prefer_primary.lock() {
                    *g = true;
                }
                // Primary success is authoritative — do not mirror into fallback.
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
            Ok(None) => self.fallback.load(purpose),
            Err(_) => self.fallback.load(purpose),
        }
    }

    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
        let primary = self.primary.delete(purpose);
        let fallback = self.fallback.delete(purpose);
        combine_delete_results(primary, fallback)
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
    resolve_file_fallback_passphrase(dir)
}

fn resolve_file_fallback_passphrase(dir: &Path) -> IdentityResult<Vec<u8>> {
    let unlock_path = dir.join(".unlock");
    match std::fs::read(&unlock_path) {
        Ok(bytes) => return validate_unlock_data(bytes, &unlock_path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => return Err(err.into()),
    }

    let mut candidate = vec![0_u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut candidate);
    match ownmesh_persist::create_once_with(&unlock_path, &candidate, restrict_secret_file)? {
        ownmesh_persist::CreateOnce::Created => Ok(candidate),
        ownmesh_persist::CreateOnce::AlreadyExists => {
            validate_unlock_data(std::fs::read(&unlock_path)?, &unlock_path)
        }
    }
}

fn validate_unlock_data(bytes: Vec<u8>, path: &Path) -> IdentityResult<Vec<u8>> {
    if bytes.len() != 32 {
        return Err(IdentityError::Invalid(format!(
            "fallback unlock data at {} must be exactly 32 bytes (found {})",
            path.display(),
            bytes.len()
        )));
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier};
    use tempfile::tempdir;

    /// Test double: optional forced failures on store/load/delete; otherwise memory-backed.
    struct ControllableStore {
        inner: MemorySecretStore,
        fail_store: AtomicBool,
        fail_load: AtomicBool,
        fail_delete: AtomicBool,
        name: &'static str,
    }

    impl ControllableStore {
        fn ok(name: &'static str) -> Self {
            Self {
                inner: MemorySecretStore::default(),
                fail_store: AtomicBool::new(false),
                fail_load: AtomicBool::new(false),
                fail_delete: AtomicBool::new(false),
                name,
            }
        }

        fn with_fail_store(name: &'static str) -> Self {
            let s = Self::ok(name);
            s.fail_store.store(true, Ordering::SeqCst);
            s
        }

        fn with_fail_load(name: &'static str) -> Self {
            let s = Self::ok(name);
            s.fail_load.store(true, Ordering::SeqCst);
            s
        }

        fn with_fail_delete(name: &'static str) -> Self {
            let s = Self::ok(name);
            s.fail_delete.store(true, Ordering::SeqCst);
            s
        }
    }

    impl SecretStore for ControllableStore {
        fn store(&self, purpose: SecretPurpose, secret: &SecretBytes) -> IdentityResult<()> {
            if self.fail_store.load(Ordering::SeqCst) {
                return Err(IdentityError::Keystore(format!(
                    "{} store forced failure",
                    self.name
                )));
            }
            self.inner.store(purpose, secret)
        }

        fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>> {
            if self.fail_load.load(Ordering::SeqCst) {
                return Err(IdentityError::Keystore(format!(
                    "{} load forced failure",
                    self.name
                )));
            }
            self.inner.load(purpose)
        }

        fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
            if self.fail_delete.load(Ordering::SeqCst) {
                return Err(IdentityError::Keystore(format!(
                    "{} delete forced failure",
                    self.name
                )));
            }
            self.inner.delete(purpose)
        }

        fn backend_name(&self) -> &'static str {
            self.name
        }
    }

    #[test]
    fn preferred_store_does_not_mirror_to_fallback_when_primary_succeeds() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"primary-only-secret".to_vec());

        store
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .expect("primary store should succeed");

        let from_primary = store
            .load(SecretPurpose::HumanRefreshToken)
            .expect("load")
            .expect("secret present via primary");
        assert_eq!(from_primary.expose(), b"primary-only-secret");

        // Direct inspection of the fallback backend: must remain empty (no mirror).
        let fallback_direct = store
            .fallback
            .load(SecretPurpose::HumanRefreshToken)
            .unwrap();
        assert!(
            fallback_direct.is_none(),
            "fallback must not receive a mirror copy when primary store succeeds"
        );
        let primary_direct = store
            .primary
            .load(SecretPurpose::HumanRefreshToken)
            .unwrap();
        assert!(primary_direct.is_some());
    }

    #[test]
    fn preferred_store_uses_fallback_when_primary_store_fails() {
        let primary = ControllableStore::with_fail_store("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"fallback-path-secret".to_vec());

        store
            .store(SecretPurpose::DevicePrivateKey, &secret)
            .expect("fallback store should succeed when primary fails");

        assert!(store
            .primary
            .load(SecretPurpose::DevicePrivateKey)
            .unwrap()
            .is_none());
        let fb = store
            .fallback
            .load(SecretPurpose::DevicePrivateKey)
            .unwrap()
            .expect("fallback holds secret");
        assert_eq!(fb.expose(), b"fallback-path-secret");
        let loaded = store
            .load(SecretPurpose::DevicePrivateKey)
            .unwrap()
            .expect("preferred load reads fallback");
        assert_eq!(loaded.expose(), b"fallback-path-secret");
    }

    #[test]
    fn preferred_delete_propagates_fallback_error_when_primary_ok() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::with_fail_delete("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let err = store
            .delete(SecretPurpose::HumanRefreshToken)
            .expect_err("fallback delete error must surface");
        let msg = err.to_string();
        assert!(
            msg.contains("fallback") && msg.contains("delete forced failure"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn preferred_delete_propagates_primary_error_when_fallback_ok() {
        let primary = ControllableStore::with_fail_delete("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let err = store
            .delete(SecretPurpose::DevicePrivateKey)
            .expect_err("primary delete error must surface");
        let msg = err.to_string();
        assert!(
            msg.contains("primary") && msg.contains("delete forced failure"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn preferred_delete_aggregates_when_both_fail() {
        let primary = ControllableStore::with_fail_delete("primary");
        let fallback = ControllableStore::with_fail_delete("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let err = store
            .delete(SecretPurpose::HumanRefreshToken)
            .expect_err("both delete errors must aggregate");
        let msg = err.to_string();
        assert!(
            msg.contains("both backends") && msg.contains("primary") && msg.contains("fallback"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn preferred_delete_ok_when_both_backends_succeed() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"to-delete".to_vec());
        // Seed via fallback path only by writing both directly.
        store
            .primary
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();
        store
            .fallback
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();

        store
            .delete(SecretPurpose::HumanRefreshToken)
            .expect("delete should succeed on both");
        assert!(store
            .primary
            .load(SecretPurpose::HumanRefreshToken)
            .unwrap()
            .is_none());
        assert!(store
            .fallback
            .load(SecretPurpose::HumanRefreshToken)
            .unwrap()
            .is_none());
    }

    #[test]
    fn combine_delete_results_no_entry_equivalent_is_ok() {
        // Backends map NoEntry to Ok(()); combine must treat dual Ok as success.
        assert!(combine_delete_results(Ok(()), Ok(())).is_ok());
    }

    #[test]
    fn cleanup_removes_identical_legacy_mirror_from_fallback() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"mirrored-secret-bytes".to_vec());

        // Simulate pre-fix dual-write: identical copy in both backends.
        store
            .primary
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();
        store
            .fallback
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();

        store
            .cleanup_legacy_fallback_mirrors()
            .expect("cleanup should remove confirmed mirror");

        assert!(
            store
                .primary
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .is_some(),
            "primary must retain the authoritative secret"
        );
        assert!(
            store
                .fallback
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .is_none(),
            "identical legacy mirror must be deleted from fallback"
        );

        // Idempotent: second pass is a no-op success.
        store
            .cleanup_legacy_fallback_mirrors()
            .expect("cleanup must be idempotent");
    }

    #[test]
    fn cleanup_keeps_non_identical_fallback_secret() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);

        store
            .primary
            .store(
                SecretPurpose::DevicePrivateKey,
                &SecretBytes::new(b"primary-material".to_vec()),
            )
            .unwrap();
        store
            .fallback
            .store(
                SecretPurpose::DevicePrivateKey,
                &SecretBytes::new(b"different-fallback-only".to_vec()),
            )
            .unwrap();

        store
            .cleanup_legacy_fallback_mirrors()
            .expect("non-mirror cleanup should succeed without deletes");

        let fb = store
            .fallback
            .load(SecretPurpose::DevicePrivateKey)
            .unwrap()
            .expect("distinct fallback secret must be retained");
        assert_eq!(fb.expose(), b"different-fallback-only");
    }

    #[test]
    fn cleanup_keeps_fallback_when_primary_missing() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);

        store
            .fallback
            .store(
                SecretPurpose::DeviceEnrollmentProof,
                &SecretBytes::new(b"fallback-only-copy".to_vec()),
            )
            .unwrap();

        store
            .cleanup_legacy_fallback_mirrors()
            .expect("missing primary must not fail cleanup");

        let fb = store
            .fallback
            .load(SecretPurpose::DeviceEnrollmentProof)
            .unwrap()
            .expect("fallback-only secret must not be deleted");
        assert_eq!(fb.expose(), b"fallback-only-copy");
        assert!(store
            .primary
            .load(SecretPurpose::DeviceEnrollmentProof)
            .unwrap()
            .is_none());
    }

    #[test]
    fn cleanup_errors_and_retains_fallback_when_primary_load_fails() {
        let primary = ControllableStore::with_fail_load("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"must-not-be-deleted".to_vec());

        // Seed fallback directly; primary load will fail so cleanup must not delete.
        store
            .fallback
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();

        let err = store
            .cleanup_legacy_fallback_mirrors()
            .expect_err("primary load failure must surface");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy mirror cleanup")
                && msg.contains("primary load failed")
                && msg.contains("fallback entry retained"),
            "unexpected error: {msg}"
        );
        let fb = store
            .fallback
            .load(SecretPurpose::HumanRefreshToken)
            .unwrap()
            .expect("fallback must be retained when primary is unverified");
        assert_eq!(fb.expose(), b"must-not-be-deleted");
    }

    #[test]
    fn cleanup_errors_when_fallback_load_fails_after_primary_hit() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::with_fail_load("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"primary-authoritative".to_vec());

        store
            .primary
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();
        // Fallback has a value in inner store but load is forced to fail.
        store
            .fallback
            .inner
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();

        let err = store
            .cleanup_legacy_fallback_mirrors()
            .expect_err("fallback load failure must surface");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy mirror cleanup") && msg.contains("fallback load failed"),
            "unexpected error: {msg}"
        );
        // Direct inner check: cleanup must not have deleted despite forced load fail.
        assert!(
            store
                .fallback
                .inner
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .is_some(),
            "fallback entry must remain when load could not be verified"
        );
    }

    #[test]
    fn cleanup_errors_when_confirmed_mirror_delete_fails() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::with_fail_delete("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"identical-mirror".to_vec());

        store
            .primary
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();
        // Bypass fail_delete by writing through inner via store (delete fails, store ok).
        store
            .fallback
            .store(SecretPurpose::HumanRefreshToken, &secret)
            .unwrap();

        let err = store
            .cleanup_legacy_fallback_mirrors()
            .expect_err("fallback delete failure must not be swallowed");
        let msg = err.to_string();
        assert!(
            msg.contains("legacy mirror cleanup") && msg.contains("fallback delete failed"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn cleanup_with_encrypted_file_backends_removes_only_mirrors() {
        let dir = tempdir().unwrap();
        let primary_dir = dir.path().join("primary");
        let fallback_dir = dir.path().join("fallback");
        let pass = b"cleanup-migration-pass";

        let store = PreferredSecretStore::from_backends(
            EncryptedFileKeystore::new(&primary_dir, pass),
            EncryptedFileKeystore::new(&fallback_dir, pass),
        );

        let mirror = SecretBytes::new(b"same-on-both-sides".to_vec());
        let fallback_only = SecretBytes::new(b"only-in-fallback".to_vec());
        let distinct = SecretBytes::new(b"primary-v2".to_vec());
        let distinct_fb = SecretBytes::new(b"fallback-old".to_vec());

        // Mirror pair (should be cleaned from fallback).
        store
            .primary
            .store(SecretPurpose::HumanRefreshToken, &mirror)
            .unwrap();
        store
            .fallback
            .store(SecretPurpose::HumanRefreshToken, &mirror)
            .unwrap();
        // Primary missing (fallback-only kept).
        store
            .fallback
            .store(SecretPurpose::DeviceEnrollmentProof, &fallback_only)
            .unwrap();
        // Non-identical pair (both kept).
        store
            .primary
            .store(SecretPurpose::DevicePrivateKey, &distinct)
            .unwrap();
        store
            .fallback
            .store(SecretPurpose::DevicePrivateKey, &distinct_fb)
            .unwrap();

        store
            .cleanup_legacy_fallback_mirrors()
            .expect("file-backed cleanup");

        assert!(store
            .fallback
            .load(SecretPurpose::HumanRefreshToken)
            .unwrap()
            .is_none());
        assert_eq!(
            store
                .fallback
                .load(SecretPurpose::DeviceEnrollmentProof)
                .unwrap()
                .unwrap()
                .expose(),
            b"only-in-fallback"
        );
        assert_eq!(
            store
                .fallback
                .load(SecretPurpose::DevicePrivateKey)
                .unwrap()
                .unwrap()
                .expose(),
            b"fallback-old"
        );
        // Preferred load still sees primary values where present.
        assert_eq!(
            store
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .unwrap()
                .expose(),
            b"same-on-both-sides"
        );
    }

    #[test]
    fn fallback_unlock_creation_is_create_once_under_concurrency() {
        const THREADS: usize = 16;
        let dir = tempdir().unwrap();
        let root = Arc::new(dir.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(THREADS));

        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                let root = Arc::clone(&root);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    resolve_file_fallback_passphrase(&root)
                })
            })
            .collect();

        let resolved: Vec<Vec<u8>> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().unwrap())
            .collect();
        assert!(resolved.iter().all(|bytes| bytes == &resolved[0]));
        assert_eq!(resolved[0].len(), 32);
        assert_eq!(std::fs::read(root.join(".unlock")).unwrap(), resolved[0]);
    }

    #[test]
    fn malformed_existing_fallback_unlock_data_is_rejected_without_replacement() {
        let dir = tempdir().unwrap();
        let unlock = dir.path().join(".unlock");
        let malformed = vec![7_u8; 31];
        std::fs::write(&unlock, &malformed).unwrap();

        let err = resolve_file_fallback_passphrase(dir.path())
            .expect_err("malformed unlock data must not be accepted");
        assert!(matches!(err, IdentityError::Invalid(_)));
        assert_eq!(std::fs::read(unlock).unwrap(), malformed);
    }

    #[cfg(unix)]
    #[test]
    fn encrypted_keystore_commits_owner_only_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let store = EncryptedFileKeystore::new(dir.path(), b"test-passphrase-for-ci");
        let purpose = SecretPurpose::HumanRefreshToken;
        store
            .store(purpose, &SecretBytes::new(b"secret".to_vec()))
            .unwrap();

        let mode = std::fs::metadata(store.path_for(purpose))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[cfg(windows)]
    #[test]
    fn encrypted_keystore_failed_replace_preserves_old_secret() {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt;

        let dir = tempdir().unwrap();
        let store = EncryptedFileKeystore::new(dir.path(), b"test-passphrase-for-ci");
        let purpose = SecretPurpose::HumanRefreshToken;
        store
            .store(purpose, &SecretBytes::new(b"stable-old-secret".to_vec()))
            .unwrap();

        let path = store.path_for(purpose);
        let guard = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(&path)
            .expect("exclusive destination lock");
        store
            .store(purpose, &SecretBytes::new(b"new-secret".to_vec()))
            .expect_err("atomic replacement must fail while destination is locked");
        drop(guard);

        let loaded = store.load(purpose).unwrap().expect("old secret remains");
        assert_eq!(loaded.expose(), b"stable-old-secret");
    }

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
        let seed_hex = key
            .seed_bytes()
            .expose()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
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
