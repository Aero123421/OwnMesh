//! Provision/clean an isolated debug keychain entry for the E1 workerd smoke.
//!
//! This example never prints credential or private-key material. The service
//! name must use the loopback-test namespace consumed only by debug ownmeshd.

use ownmesh_identity::{
    delete_device_credential, load_device_credential_for, load_or_create_device_key,
    store_device_credential, PreferredSecretStore, SecretPurpose, SecretStore, SecretString,
};
use std::path::PathBuf;

fn main() -> Result<(), String> {
    let action = std::env::args().nth(1).unwrap_or_default();
    let service = required_env("OWNMESH_LOOPBACK_TEST_KEYCHAIN_SERVICE")?;
    if !service.starts_with("dev.ownmesh.loopback-test.") {
        return Err("loopback test service must use dev.ownmesh.loopback-test.*".into());
    }
    let keystore_dir = PathBuf::from(required_env("OWNMESH_E1_TEST_KEYSTORE_DIR")?);
    let store = PreferredSecretStore::open(service, keystore_dir)
        .map_err(|error| format!("open isolated test store: {error}"))?;

    match action.as_str() {
        "provision" => {
            let issuer = required_env("OWNMESH_E1_TEST_ISSUER")?;
            let device_id = required_env("OWNMESH_E1_TEST_DEVICE_ID")?;
            let credential = SecretString::new(required_env("OWNMESH_E1_TEST_CREDENTIAL")?);
            let key = load_or_create_device_key(&store)
                .map_err(|error| format!("create isolated device key: {error}"))?;
            store_device_credential(&store, &issuer, &device_id, &credential)
                .map_err(|error| format!("store isolated device credential: {error}"))?;
            println!("{}", key.public_identity().public_key_hex);
            Ok(())
        }
        "cleanup" => {
            delete_device_credential(&store)
                .map_err(|error| format!("delete isolated device credential: {error}"))?;
            store
                .delete(SecretPurpose::DevicePrivateKey)
                .map_err(|error| format!("delete isolated device key: {error}"))?;
            Ok(())
        }
        "verify" => {
            let issuer = required_env("OWNMESH_E1_TEST_ISSUER")?;
            let device_id = required_env("OWNMESH_E1_TEST_DEVICE_ID")?;
            if load_device_credential_for(&store, &issuer, &device_id)
                .map_err(|error| format!("load isolated device credential: {error}"))?
                .is_none()
            {
                return Err("isolated device credential is absent or misbound".into());
            }
            println!("present");
            Ok(())
        }
        _ => Err("expected action: provision | verify | cleanup".into()),
    }
}

fn required_env(name: &str) -> Result<String, String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{name} is required"))
}
