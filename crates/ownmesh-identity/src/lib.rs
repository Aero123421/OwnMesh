//! OwnMesh device identity, keychain, and credential storage.
//!
//! Device private keys and human refresh tokens are stored by purpose in an OS keychain
//! when available, with an encrypted on-disk keystore fallback for headless environments.

#![forbid(unsafe_code)]
#![allow(
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
    load_human_refresh_token, load_or_create_device_key, rotate_device_key,
    store_human_refresh_token, DeviceKeyPair, DevicePublicIdentity,
};
pub use error::{IdentityError, IdentityResult};
pub use secret::{SecretBytes, SecretPurpose, SecretString};
pub use store::{
    EncryptedFileKeystore, MemorySecretStore, OsKeychainStore, PreferredSecretStore, SecretStore,
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
    fn preferred_store_persists_across_restart() {
        let dir = tempdir().unwrap();
        let service = format!(
            "dev.ownmesh.test.{}",
            dir.path()
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("x")
        );
        let store = PreferredSecretStore::open(&service, dir.path()).unwrap();
        let key = load_or_create_device_key(&store).unwrap();
        store_human_refresh_token(&store, &SecretString::new("rt_test_value_do_not_log")).unwrap();
        let fp = key.public_identity().fingerprint;

        drop(store);
        let store2 = PreferredSecretStore::open(&service, dir.path()).unwrap();
        let key2 = load_or_create_device_key(&store2).unwrap();
        assert_eq!(key2.public_identity().fingerprint, fp);
        let token = load_human_refresh_token(&store2).unwrap().unwrap();
        assert_eq!(token.expose(), "rt_test_value_do_not_log");
        assert!(!format!("{token:?}").contains("rt_test_value"));

        // Best-effort cleanup so developer keychains are not polluted.
        let _ = store2.delete(SecretPurpose::DevicePrivateKey);
        let _ = store2.delete(SecretPurpose::HumanRefreshToken);
        let _ = service; // keep service name tied to the temp dir lifetime
        let _ = DEFAULT_KEYCHAIN_SERVICE;
    }
}
