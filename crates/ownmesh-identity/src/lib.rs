//! `OwnMesh` device identity, keychain, and credential storage.
//!
//! Device private keys and human refresh tokens are stored by purpose in an OS keychain
//! when available, with an encrypted on-disk keystore fallback for headless environments.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod device_key;
mod error;
mod secret;
mod store;

pub use device_key::{
    delete_device_credential, load_device_credential, load_device_credential_for,
    load_human_refresh_token, load_or_create_device_key, rotate_device_key,
    store_device_credential, store_human_refresh_token, verify_from_public_key_hex,
    DeviceCredentialEnvelope, DeviceKeyPair, DevicePublicIdentity,
};
pub use error::{IdentityError, IdentityResult};
pub use secret::{SecretBytes, SecretPurpose, SecretString};
pub use store::{
    CredentialStoreDiagnosticSnapshot, EncryptedFileKeystore, LegacyMirrorCleanupReport,
    MemorySecretStore, OsKeychainStore, PreferredSecretStore, PreferredSecretStoreReport,
    PreferredStoreFallbackPolicy, ResidualFallbackKind, ResidualFallbackSecret, SecretStore,
    CREDENTIAL_STORE_DIAGNOSTIC_FILE,
};

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

/// Default keychain service name.
pub const DEFAULT_KEYCHAIN_SERVICE: &str = "dev.ownmesh";

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn crate_metadata_is_stable() {
        assert_eq!(crate_name(), "ownmesh-identity");
        assert!(!crate_version().is_empty());
    }

    #[test]
    fn preferred_store_persists_across_restart_without_fallback_mirror() {
        // Use durable file backends so this test does not depend on a working OS keychain.
        // When primary store succeeds, fallback must not receive a mirror copy (req 8).
        let dir = tempdir().unwrap();
        let primary_dir = dir.path().join("primary");
        let fallback_dir = dir.path().join("fallback");
        let pass = b"test-passphrase-for-preferred-ci";

        let store = PreferredSecretStore::from_backends(
            EncryptedFileKeystore::new(&primary_dir, pass),
            EncryptedFileKeystore::new(&fallback_dir, pass),
        );
        let key = load_or_create_device_key(&store).unwrap();
        store_human_refresh_token(&store, &SecretString::new("rt_test_value_do_not_log")).unwrap();
        let fp = key.public_identity().fingerprint;

        // No mirror: fallback directory must not contain purpose `.oms` files.
        let fallback_entries = std::fs::read_dir(&fallback_dir)
            .map(|rd| {
                rd.filter_map(Result::ok)
                    .filter(|e| {
                        e.path()
                            .extension()
                            .and_then(|x| x.to_str())
                            .is_some_and(|ext| ext == "oms")
                    })
                    .count()
            })
            .unwrap_or(0);
        assert_eq!(
            fallback_entries, 0,
            "primary success must not mirror secrets into fallback"
        );

        drop(store);

        let store2 = PreferredSecretStore::from_backends(
            EncryptedFileKeystore::new(&primary_dir, pass),
            EncryptedFileKeystore::new(&fallback_dir, pass),
        );
        let key2 = load_or_create_device_key(&store2).unwrap();
        assert_eq!(key2.public_identity().fingerprint, fp);
        let token = load_human_refresh_token(&store2).unwrap().unwrap();
        assert_eq!(token.expose(), "rt_test_value_do_not_log");
        assert!(!format!("{token:?}").contains("rt_test_value"));

        store2
            .delete(SecretPurpose::DevicePrivateKey)
            .expect("delete device key");
        store2
            .delete(SecretPurpose::HumanRefreshToken)
            .expect("delete refresh token");
        let _ = DEFAULT_KEYCHAIN_SERVICE;
    }
}
