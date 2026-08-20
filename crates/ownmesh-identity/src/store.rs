//! Secret store trait and backend implementations.

use crate::error::{IdentityError, IdentityResult};
use crate::secret::{SecretBytes, SecretPurpose};
use serde::{Deserialize, Serialize};
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
///
/// Fallback policy is always [`PreferredStoreFallbackPolicy::PrimaryPreferredEncryptedFileFallback`].
/// Legacy mirror cleanup failures do **not** make [`Self::open`] fail; the store is returned in a
/// degraded state with residual/report observability instead.
pub struct PreferredSecretStore<P = OsKeychainStore, F = EncryptedFileKeystore> {
    primary: P,
    fallback: F,
    /// When true, primary backend probed successfully at least once.
    prefer_primary: Mutex<bool>,
    /// Outcome of the last legacy-mirror cleanup attempt (if any).
    cleanup_report: Mutex<LegacyMirrorCleanupReport>,
    /// Production-only location for non-secret doctor provenance metadata.
    diagnostic_path: Option<PathBuf>,
    /// Production fallback directory; used only for file-name presence counts.
    fallback_dir: Option<PathBuf>,
}

/// Explicit policy for how [`PreferredSecretStore`] uses the encrypted-file fallback.
///
/// This is not a security boundary against other processes running as the same OS user:
/// file-backed secrets remain readable by any process with the same uid/DAC rights.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferredStoreFallbackPolicy {
    /// Prefer the primary backend (OS keychain). On primary `store` failure, write to the
    /// encrypted-file fallback unlocked by `OWNMESH_KEYSTORE_PASSWORD` or `fallback_dir/.unlock`.
    /// Successful primary writes are never mirrored. Legacy dual-write mirrors are removed only
    /// when primary holds identical bytes. Cleanup failure warns and marks the store degraded
    /// without blocking open; residual fallback secrets remain observable via report APIs.
    PrimaryPreferredEncryptedFileFallback,
}

impl PreferredStoreFallbackPolicy {
    /// Stable diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PrimaryPreferredEncryptedFileFallback => {
                "primary_preferred_encrypted_file_fallback"
            }
        }
    }
}

impl std::fmt::Display for PreferredStoreFallbackPolicy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a secret still exists in the fallback backend after (or without) cleanup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResidualFallbackKind {
    /// Primary has no entry; fallback may be the only copy (intentionally retained).
    FallbackOnly,
    /// Primary and fallback hold different material (not a confirmed mirror).
    DivergentFromPrimary,
    /// Bytes match primary (confirmed mirror) but the fallback copy is still present.
    ConfirmedMirrorPresent,
    /// Primary could not be verified; fallback was not deleted.
    PrimaryUnverified { detail: String },
    /// Fallback entry exists but could not be read/decrypted for classification.
    FallbackUnreadable { detail: String },
}

/// Observable residual secret presence in the fallback backend (no secret bytes exposed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidualFallbackSecret {
    /// [`SecretPurpose::account`] label.
    pub purpose_account: &'static str,
    /// Classification of the residual entry.
    pub kind: ResidualFallbackKind,
}

/// Outcome of a legacy mirror cleanup pass.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LegacyMirrorCleanupReport {
    /// Whether cleanup was attempted.
    pub attempted: bool,
    /// Confirmed mirrors successfully removed in this pass.
    pub removed_mirrors: usize,
    /// True when cleanup hit a verification/delete failure and stopped early.
    pub degraded: bool,
    /// Human-readable cleanup failure (no secret material), when `degraded`.
    pub error: Option<String>,
}

/// Non-secret credential-store provenance persisted for read-only doctor runs.
/// No credential bytes, keychain account values, or backend error bodies are stored.
pub const CREDENTIAL_STORE_DIAGNOSTIC_FILE: &str = "credential-store-report.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CredentialStoreDiagnosticSnapshot {
    pub schema_version: u32,
    pub backend_name: String,
    pub fallback_policy: String,
    pub degraded: bool,
    pub residual_fallback_entries: usize,
    pub cleanup_degraded: bool,
}

/// Snapshot of preferred-store health, policy, and residual fallback presence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreferredSecretStoreReport {
    /// Active backend selection label (same as [`SecretStore::backend_name`]).
    pub backend_name: &'static str,
    /// Explicit fallback policy in effect.
    pub fallback_policy: PreferredStoreFallbackPolicy,
    /// True when cleanup failed or a residual mirror cannot be safely verified/removed.
    pub degraded: bool,
    /// Last cleanup attempt outcome.
    pub cleanup: LegacyMirrorCleanupReport,
    /// Fallback secrets still present (classified; no secret bytes).
    pub residual_fallback_secrets: Vec<ResidualFallbackSecret>,
}

/// Known secret purposes scanned during legacy mirror cleanup / residual detection.
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
    /// Cleanup failures do **not** fail `open`: a tracing warning is emitted, the store is
    /// marked degraded, and residual fallback secrets remain observable via
    /// [`Self::report`] / [`Self::residual_fallback_secrets`]. Callers can still use the store.
    ///
    /// # Errors
    ///
    /// Returns IO errors while preparing the fallback unlock material only. Legacy mirror
    /// cleanup errors are converted into degraded state + warning, not `Err`.
    pub fn open(
        service: impl Into<String>,
        fallback_dir: impl AsRef<Path>,
    ) -> IdentityResult<Self> {
        let fallback_dir = fallback_dir.as_ref();
        std::fs::create_dir_all(fallback_dir)?;
        let passphrase = resolve_fallback_passphrase(fallback_dir)?;
        let mut store = Self::from_backends(
            OsKeychainStore::new(service),
            EncryptedFileKeystore::new(fallback_dir, passphrase),
        );
        store.diagnostic_path = Some(fallback_dir.join(CREDENTIAL_STORE_DIAGNOSTIC_FILE));
        store.fallback_dir = Some(fallback_dir.to_path_buf());
        let policy = store.fallback_policy();
        if let Err(err) = store.cleanup_legacy_fallback_mirrors() {
            // Safety-preserving cleanup failed (primary unverified / delete failed, etc.).
            // Do not block startup: warn and keep serving with explicit fallback policy.
            let residual_count = store.residual_fallback_secrets().len();
            tracing::warn!(
                error = %err,
                fallback_policy = %policy,
                residual_count,
                "legacy fallback mirror cleanup failed; continuing with degraded preferred secret store; residual fallback secrets may remain"
            );
        }
        store.persist_diagnostic_snapshot_best_effort();
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
            cleanup_report: Mutex::new(LegacyMirrorCleanupReport::default()),
            diagnostic_path: None,
            fallback_dir: None,
        }
    }

    /// Explicit fallback policy for this store (always the production policy today).
    #[must_use]
    pub const fn fallback_policy(&self) -> PreferredStoreFallbackPolicy {
        PreferredStoreFallbackPolicy::PrimaryPreferredEncryptedFileFallback
    }
}

impl<P: SecretStore, F: SecretStore> PreferredSecretStore<P, F> {
    /// True when cleanup failed or a residual mirror cannot be safely verified/removed.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        let cleanup_degraded = self
            .cleanup_report
            .lock()
            .map(|g| g.degraded)
            .unwrap_or(true);
        if cleanup_degraded {
            return true;
        }
        self.residual_fallback_secrets()
            .iter()
            .any(|residual| residual_kind_is_degraded(&residual.kind))
    }

    /// Last legacy-mirror cleanup report (cloned snapshot).
    #[must_use]
    pub fn cleanup_report(&self) -> LegacyMirrorCleanupReport {
        match self.cleanup_report.lock() {
            Ok(guard) => guard.clone(),
            Err(_) => LegacyMirrorCleanupReport {
                attempted: true,
                removed_mirrors: 0,
                degraded: true,
                error: Some("cleanup report lock poisoned".into()),
            },
        }
    }

    /// Detect secrets still present in the fallback backend (read-only; never deletes).
    ///
    /// Does not expose secret bytes — only purpose labels and residual classification.
    #[must_use]
    pub fn residual_fallback_secrets(&self) -> Vec<ResidualFallbackSecret> {
        let mut out = Vec::new();
        for &purpose in LEGACY_MIRROR_CLEANUP_PURPOSES {
            let fallback_secret = match self.fallback.load(purpose) {
                Ok(Some(secret)) => secret,
                Ok(None) => continue,
                Err(err) => {
                    out.push(ResidualFallbackSecret {
                        purpose_account: purpose.account(),
                        kind: ResidualFallbackKind::FallbackUnreadable {
                            detail: err.to_string(),
                        },
                    });
                    continue;
                }
            };
            // `fallback_secret` held only for byte comparison; never logged.
            let kind = match self.primary.load(purpose) {
                Ok(None) => ResidualFallbackKind::FallbackOnly,
                Ok(Some(primary_secret)) => {
                    if primary_secret.expose() == fallback_secret.expose() {
                        ResidualFallbackKind::ConfirmedMirrorPresent
                    } else {
                        ResidualFallbackKind::DivergentFromPrimary
                    }
                }
                Err(err) => ResidualFallbackKind::PrimaryUnverified {
                    detail: err.to_string(),
                },
            };
            out.push(ResidualFallbackSecret {
                purpose_account: purpose.account(),
                kind,
            });
        }
        out
    }

    /// Non-secret snapshot consumed by `ownmesh doctor` without keychain reads.
    #[must_use]
    pub fn diagnostic_snapshot(&self) -> CredentialStoreDiagnosticSnapshot {
        let cleanup = self.cleanup_report();
        let residual_fallback_entries = self
            .fallback_dir
            .as_ref()
            .map(|dir| {
                [
                    SecretPurpose::DevicePrivateKey,
                    SecretPurpose::HumanRefreshToken,
                    SecretPurpose::DeviceEnrollmentProof,
                    SecretPurpose::DeviceCredential,
                ]
                .into_iter()
                .filter(|purpose| dir.join(format!("{}.oms", purpose.account())).is_file())
                .count()
            })
            .unwrap_or(0);
        CredentialStoreDiagnosticSnapshot {
            schema_version: 1,
            backend_name: self.backend_name().to_string(),
            fallback_policy: self.fallback_policy().as_str().to_string(),
            degraded: cleanup.degraded,
            residual_fallback_entries,
            cleanup_degraded: cleanup.degraded,
        }
    }

    fn persist_diagnostic_snapshot_best_effort(&self) {
        let Some(path) = &self.diagnostic_path else {
            return;
        };
        let snapshot = self.diagnostic_snapshot();
        let Ok(bytes) = serde_json::to_vec_pretty(&snapshot) else {
            return;
        };
        if let Err(error) = ownmesh_persist::write_atomically(path, &bytes) {
            tracing::warn!(
                error = %error,
                "failed to persist non-secret credential-store diagnostic metadata"
            );
        }
    }

    /// Observability snapshot: policy, degraded flag, cleanup outcome, residual fallback secrets.
    #[must_use]
    pub fn report(&self) -> PreferredSecretStoreReport {
        let cleanup = self.cleanup_report();
        let residual_fallback_secrets = self.residual_fallback_secrets();
        let degraded = cleanup.degraded
            || residual_fallback_secrets
                .iter()
                .any(|residual| residual_kind_is_degraded(&residual.kind));
        PreferredSecretStoreReport {
            backend_name: self.backend_name(),
            fallback_policy: self.fallback_policy(),
            degraded,
            cleanup,
            residual_fallback_secrets,
        }
    }

    /// Delete legacy fallback mirror copies when primary holds the identical secret.
    ///
    /// Idempotent migration helper for older builds that mirrored successful primary
    /// writes into the fallback backend. Safety rules:
    ///
    /// - Probe the fallback first. If it has no entry, cleanup for that purpose is complete
    ///   without querying primary (important when the primary is unavailable headlessly).
    /// - Delete fallback **only** when primary `load` succeeds with `Some` and the
    ///   bytes are identical to the fallback entry (confirmed mirror).
    /// - If primary has no entry, keep fallback (it may be the only copy).
    /// - If secrets differ, keep fallback (not a mirror of primary).
    /// - If primary `load` fails, **do not** delete fallback and return an error
    ///   (never remove secrets while primary is unverified).
    /// - Fallback `load` / confirmed-mirror `delete` failures are returned, never
    ///   swallowed (no silent cleanup that could hide secret-loss risk).
    ///
    /// On failure the cleanup report is marked `degraded` before the error is returned so
    /// [`Self::open`] can continue startup with warning + residual observability.
    ///
    /// # Errors
    ///
    /// Primary/fallback load failures, or delete failure after a confirmed mirror match.
    pub fn cleanup_legacy_fallback_mirrors(&self) -> IdentityResult<()> {
        let mut removed_mirrors = 0_usize;
        for &purpose in LEGACY_MIRROR_CLEANUP_PURPOSES {
            let fallback_secret = match self.fallback.load(purpose) {
                Ok(value) => value,
                Err(err) => {
                    let err = IdentityError::Keystore(format!(
                        "legacy mirror cleanup: fallback load failed for {}: {err}",
                        purpose.account()
                    ));
                    self.record_cleanup_failure(removed_mirrors, &err);
                    return Err(err);
                }
            };
            let Some(fallback_secret) = fallback_secret else {
                // No fallback entry means there is no mirror to classify or remove. Do not
                // probe primary: it may be unavailable in the headless environments that use
                // this fallback.
                continue;
            };

            let primary_secret = match self.primary.load(purpose) {
                Ok(value) => value,
                Err(err) => {
                    let err = IdentityError::Keystore(format!(
                        "legacy mirror cleanup: primary load failed for {}: {err}; fallback entry retained",
                        purpose.account()
                    ));
                    self.record_cleanup_failure(removed_mirrors, &err);
                    return Err(err);
                }
            };
            let Some(primary_secret) = primary_secret else {
                // Primary missing — fallback may be the sole copy; never delete.
                continue;
            };

            if primary_secret.expose() != fallback_secret.expose() {
                // Distinct material — not a legacy mirror of primary.
                continue;
            }

            // Primary is authoritative and bytes match: safe to drop the mirror copy.
            if let Err(err) = self.fallback.delete(purpose) {
                let err = IdentityError::Keystore(format!(
                    "legacy mirror cleanup: fallback delete failed for {}: {err}",
                    purpose.account()
                ));
                self.record_cleanup_failure(removed_mirrors, &err);
                return Err(err);
            }
            removed_mirrors = removed_mirrors.saturating_add(1);
        }
        self.record_cleanup_success(removed_mirrors);
        Ok(())
    }

    fn record_cleanup_success(&self, removed_mirrors: usize) {
        if let Ok(mut guard) = self.cleanup_report.lock() {
            *guard = LegacyMirrorCleanupReport {
                attempted: true,
                removed_mirrors,
                degraded: false,
                error: None,
            };
        }
    }

    fn record_cleanup_failure(&self, removed_mirrors: usize, err: &IdentityError) {
        if let Ok(mut guard) = self.cleanup_report.lock() {
            *guard = LegacyMirrorCleanupReport {
                attempted: true,
                removed_mirrors,
                degraded: true,
                error: Some(err.to_string()),
            };
        }
    }
}

fn residual_kind_is_degraded(kind: &ResidualFallbackKind) -> bool {
    matches!(
        kind,
        ResidualFallbackKind::ConfirmedMirrorPresent
            | ResidualFallbackKind::PrimaryUnverified { .. }
            | ResidualFallbackKind::FallbackUnreadable { .. }
    )
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
        let result = match self.primary.store(purpose, secret) {
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
        };
        self.persist_diagnostic_snapshot_best_effort();
        result
    }

    fn load(&self, purpose: SecretPurpose) -> IdentityResult<Option<SecretBytes>> {
        let result = match self.primary.load(purpose) {
            Ok(Some(v)) => {
                if let Ok(mut g) = self.prefer_primary.lock() {
                    *g = true;
                }
                Ok(Some(v))
            }
            Ok(None) => {
                let fallback = self.fallback.load(purpose);
                if matches!(fallback, Ok(Some(_))) {
                    if let Ok(mut g) = self.prefer_primary.lock() {
                        *g = false;
                    }
                }
                fallback
            }
            Err(_) => {
                if let Ok(mut g) = self.prefer_primary.lock() {
                    *g = false;
                }
                self.fallback.load(purpose)
            }
        };
        self.persist_diagnostic_snapshot_best_effort();
        result
    }

    fn delete(&self, purpose: SecretPurpose) -> IdentityResult<()> {
        let primary = self.primary.delete(purpose);
        let fallback = self.fallback.delete(purpose);
        let result = combine_delete_results(primary, fallback);
        self.persist_diagnostic_snapshot_best_effort();
        result
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
    use std::process::Command;
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

    /// Keyring test backend that behaves like an unavailable headless primary: reads and writes
    /// fail, while deleting a missing credential has normal `NoEntry` semantics.
    #[derive(Debug)]
    struct HeadlessCredential;

    impl keyring::credential::CredentialApi for HeadlessCredential {
        fn set_secret(&self, _secret: &[u8]) -> keyring::Result<()> {
            Err(keyring::Error::Invalid(
                "keychain".into(),
                "unavailable in headless test".into(),
            ))
        }

        fn get_secret(&self) -> keyring::Result<Vec<u8>> {
            Err(keyring::Error::Invalid(
                "keychain".into(),
                "unavailable in headless test".into(),
            ))
        }

        fn delete_credential(&self) -> keyring::Result<()> {
            Err(keyring::Error::NoEntry)
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct HeadlessCredentialBuilder;

    impl keyring::credential::CredentialBuilderApi for HeadlessCredentialBuilder {
        fn build(
            &self,
            _target: Option<&str>,
            _service: &str,
            _user: &str,
        ) -> keyring::Result<Box<keyring::Credential>> {
            Ok(Box::new(HeadlessCredential))
        }

        fn as_any(&self) -> &dyn std::any::Any {
            self
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
    fn cleanup_skips_unavailable_primary_when_fallback_is_absent() {
        let store = PreferredSecretStore::from_backends(
            ControllableStore::with_fail_load("primary"),
            ControllableStore::ok("fallback"),
        );

        store
            .cleanup_legacy_fallback_mirrors()
            .expect("absent fallback entries must not require a primary probe");

        let report = store.report();
        assert!(report.cleanup.attempted);
        assert!(!report.cleanup.degraded);
        assert!(report.cleanup.error.is_none());
        assert!(!report.degraded);
        assert!(report.residual_fallback_secrets.is_empty());
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
        assert!(store.is_degraded(), "cleanup failure must mark degraded");
        let report = store.report();
        assert!(report.degraded);
        assert!(report.cleanup.degraded);
        assert!(report
            .cleanup
            .error
            .as_ref()
            .is_some_and(|e| e.contains("primary load failed")));
        assert!(
            report.residual_fallback_secrets.iter().any(|r| {
                r.purpose_account == SecretPurpose::HumanRefreshToken.account()
                    && matches!(r.kind, ResidualFallbackKind::PrimaryUnverified { .. })
            }),
            "residual API must detect unverified fallback secret: {:?}",
            report.residual_fallback_secrets
        );
    }

    #[test]
    fn cleanup_errors_when_fallback_probe_fails() {
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
            .fold(String::new(), |mut acc, b| {
                use std::fmt::Write;
                let _ = write!(acc, "{b:02x}");
                acc
            });
        assert!(!format!("{key:?}").contains(&seed_hex));
        let cfg_sim = toml_like_config_dump();
        assert!(!cfg_sim.contains("VERY_SECRET"));
        assert!(!cfg_sim.contains(&seed_hex));
    }

    fn toml_like_config_dump() -> String {
        // Simulated config/stdout content — secrets must not be interpolated.
        "schema_version = 1\nlang = \"en-US\"\n".into()
    }

    #[test]
    fn residual_api_detects_fallback_only_and_divergent_secrets() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);

        store
            .fallback
            .store(
                SecretPurpose::DeviceEnrollmentProof,
                &SecretBytes::new(b"fallback-only-residual".to_vec()),
            )
            .unwrap();
        store
            .primary
            .store(
                SecretPurpose::DevicePrivateKey,
                &SecretBytes::new(b"primary-v2".to_vec()),
            )
            .unwrap();
        store
            .fallback
            .store(
                SecretPurpose::DevicePrivateKey,
                &SecretBytes::new(b"fallback-old-residual".to_vec()),
            )
            .unwrap();

        store
            .cleanup_legacy_fallback_mirrors()
            .expect("intentional residuals must not fail cleanup");

        let residuals = store.residual_fallback_secrets();
        assert!(
            residuals.iter().any(|r| {
                r.purpose_account == SecretPurpose::DeviceEnrollmentProof.account()
                    && matches!(r.kind, ResidualFallbackKind::FallbackOnly)
            }),
            "fallback-only residual must be detectable: {residuals:?}"
        );
        assert!(
            residuals.iter().any(|r| {
                r.purpose_account == SecretPurpose::DevicePrivateKey.account()
                    && matches!(r.kind, ResidualFallbackKind::DivergentFromPrimary)
            }),
            "divergent residual must be detectable: {residuals:?}"
        );
        // Intentional non-mirror residuals do not by themselves mark degraded.
        assert!(!store.is_degraded());
        let report = store.report();
        assert_eq!(
            report.fallback_policy,
            PreferredStoreFallbackPolicy::PrimaryPreferredEncryptedFileFallback
        );
        assert!(!report.degraded);
        assert!(report.cleanup.attempted);
        assert!(!report.cleanup.degraded);
    }

    #[test]
    fn report_is_degraded_for_unverified_or_unreadable_residuals() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        store
            .fallback
            .store(
                SecretPurpose::HumanRefreshToken,
                &SecretBytes::new(b"residual".to_vec()),
            )
            .unwrap();
        store.cleanup_legacy_fallback_mirrors().unwrap();
        store.primary.fail_load.store(true, Ordering::SeqCst);

        let report = store.report();
        assert!(!report.cleanup.degraded);
        assert!(report.degraded);
        assert!(report.residual_fallback_secrets.iter().any(|residual| {
            matches!(
                residual.kind,
                ResidualFallbackKind::PrimaryUnverified { .. }
            )
        }));
        assert!(store.is_degraded());

        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        store
            .fallback
            .store(
                SecretPurpose::HumanRefreshToken,
                &SecretBytes::new(b"unreadable-residual".to_vec()),
            )
            .unwrap();
        store.cleanup_legacy_fallback_mirrors().unwrap();
        store.fallback.fail_load.store(true, Ordering::SeqCst);

        let report = store.report();
        assert!(!report.cleanup.degraded);
        assert!(report.degraded);
        assert!(report.residual_fallback_secrets.iter().any(|residual| {
            matches!(
                residual.kind,
                ResidualFallbackKind::FallbackUnreadable { .. }
            )
        }));
        assert!(store.is_degraded());
    }

    #[test]
    fn residual_api_detects_unremoved_confirmed_mirror_after_delete_failure() {
        let primary = ControllableStore::ok("primary");
        let fallback = ControllableStore::with_fail_delete("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);
        let secret = SecretBytes::new(b"identical-mirror-residual".to_vec());

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
            .expect_err("confirmed mirror delete failure must surface");

        assert!(store.is_degraded());
        let residuals = store.residual_fallback_secrets();
        assert!(
            residuals.iter().any(|r| {
                r.purpose_account == SecretPurpose::HumanRefreshToken.account()
                    && matches!(r.kind, ResidualFallbackKind::ConfirmedMirrorPresent)
            }),
            "unremoved confirmed mirror must be residual-detectable: {residuals:?}"
        );
        // Safety: fallback secret must still exist (delete failed, never force-removed).
        assert_eq!(
            store
                .fallback
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .unwrap()
                .expose(),
            b"identical-mirror-residual"
        );
    }

    #[test]
    fn cleanup_failure_leaves_usable_store_in_degraded_state_like_open_policy() {
        // Mirrors PreferredSecretStore::open behaviour: cleanup Err must not prevent use.
        // Primary load fails during cleanup; primary store also fails so later writes use fallback.
        let primary = ControllableStore::ok("primary");
        primary.fail_load.store(true, Ordering::SeqCst);
        primary.fail_store.store(true, Ordering::SeqCst);
        let fallback = ControllableStore::ok("fallback");
        let store = PreferredSecretStore::from_backends(primary, fallback);

        store
            .fallback
            .store(
                SecretPurpose::HumanRefreshToken,
                &SecretBytes::new(b"preexisting-fallback".to_vec()),
            )
            .unwrap();

        let cleanup_err = store
            .cleanup_legacy_fallback_mirrors()
            .expect_err("primary load fail");
        // open() would warn + return Ok(store) here rather than propagating cleanup_err.
        assert!(cleanup_err.to_string().contains("legacy mirror cleanup"));
        assert!(store.is_degraded());
        assert_eq!(
            store.fallback_policy(),
            PreferredStoreFallbackPolicy::PrimaryPreferredEncryptedFileFallback
        );

        // Store remains usable via fallback path despite degraded cleanup state.
        let secret = SecretBytes::new(b"post-degraded-write".to_vec());
        store
            .store(SecretPurpose::DevicePrivateKey, &secret)
            .expect("degraded store must still accept writes via fallback");
        let loaded = store
            .load(SecretPurpose::DevicePrivateKey)
            .unwrap()
            .expect("load via fallback");
        assert_eq!(loaded.expose(), b"post-degraded-write");
        store
            .delete(SecretPurpose::DevicePrivateKey)
            .expect("delete still works");
    }

    #[test]
    fn preferred_open_headless_unlock_production_roundtrip() {
        const CHILD_MARKER: &str = "OWNMESH_IDENTITY_HEADLESS_OPEN_CHILD";
        const FALLBACK_DIR_ENV: &str = "OWNMESH_IDENTITY_HEADLESS_FALLBACK_DIR";

        if std::env::var_os(CHILD_MARKER).is_some() {
            // This isolated child is the only test in its process, so replacing keyring's global
            // builder cannot interfere with parallel tests. Its parent also removes the password
            // environment variable, selecting the production `.unlock` path without mutating the
            // parent test process environment.
            keyring::set_default_credential_builder(Box::new(HeadlessCredentialBuilder));
            let fallback_dir = PathBuf::from(
                std::env::var_os(FALLBACK_DIR_ENV).expect("child fallback directory"),
            );
            let service = "dev.ownmesh.test.production-headless";
            let secret = SecretBytes::new(b"headless-production-roundtrip".to_vec());

            let store = PreferredSecretStore::open(service, &fallback_dir)
                .expect("fresh production open must not probe unavailable primary");
            assert!(fallback_dir.join(".unlock").is_file());
            assert_eq!(
                std::fs::read(fallback_dir.join(".unlock")).unwrap().len(),
                32
            );
            let initial_report = store.report();
            assert!(initial_report.cleanup.attempted);
            assert!(!initial_report.cleanup.degraded);
            assert!(!initial_report.degraded);
            assert!(initial_report.residual_fallback_secrets.is_empty());

            store
                .store(SecretPurpose::HumanRefreshToken, &secret)
                .expect("unavailable primary must fall back to encrypted file");
            assert_eq!(store.backend_name(), "preferred(encrypted-file)");
            assert!(fallback_dir
                .join(format!(
                    "{}.oms",
                    SecretPurpose::HumanRefreshToken.account()
                ))
                .is_file());
            drop(store);

            let restarted = PreferredSecretStore::open(service, &fallback_dir)
                .expect("cleanup failure on restart must remain nonfatal");
            let restart_report = restarted.report();
            assert!(restart_report.cleanup.degraded);
            assert!(restart_report.degraded);
            assert!(restart_report
                .cleanup
                .error
                .as_ref()
                .is_some_and(|error| error.contains("primary load failed")));
            assert!(restart_report
                .residual_fallback_secrets
                .iter()
                .any(|residual| {
                    residual.purpose_account == SecretPurpose::HumanRefreshToken.account()
                        && matches!(
                            residual.kind,
                            ResidualFallbackKind::PrimaryUnverified { .. }
                        )
                }));

            let loaded = restarted
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .expect("restart must load from `.unlock`-encrypted fallback");
            assert_eq!(loaded.expose(), secret.expose());
            restarted
                .delete(SecretPurpose::HumanRefreshToken)
                .expect("headless delete");
            assert!(restarted
                .load(SecretPurpose::HumanRefreshToken)
                .unwrap()
                .is_none());
            return;
        }

        let dir = tempdir().unwrap();
        let fallback_dir = dir.path().join("keystore");
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .arg("--exact")
            .arg("store::tests::preferred_open_headless_unlock_production_roundtrip")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .env(FALLBACK_DIR_ENV, &fallback_dir)
            .env_remove("OWNMESH_KEYSTORE_PASSWORD")
            .output()
            .expect("run isolated headless production-path test");
        assert!(
            output.status.success(),
            "headless production-path child failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
