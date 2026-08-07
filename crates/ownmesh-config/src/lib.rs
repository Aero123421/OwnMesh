//! `OwnMesh` configuration loading, paths, and migration.
//!
//! Secrets never belong in `config.toml`. Device keys and refresh tokens live in
//! `ownmesh-identity` keychain backends.

#![forbid(unsafe_code)]
#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod error;
mod paths;
mod schema;
mod store;

pub use error::{ConfigError, ConfigResult};
pub use paths::OwnMeshPaths;
pub use schema::{
    validate_control_plane_base_url, InstanceConfig, OwnMeshConfig, PolicyFile, TelemetryConfig,
    UpdateConfig, CONFIG_SCHEMA_VERSION,
};
pub use store::{
    appears_secret_free, atomic_write, load_config, load_policy, save_config, save_policy,
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn crate_metadata_is_stable() {
        assert_eq!(crate_name(), "ownmesh-config");
        assert!(!crate_version().is_empty());
    }

    #[test]
    fn end_to_end_config_lifecycle() {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        let cfg = load_config(&paths).unwrap();
        assert_eq!(cfg.schema_version, CONFIG_SCHEMA_VERSION);
        let text = std::fs::read_to_string(paths.config_file()).unwrap();
        assert!(appears_secret_free(&text));
        let policy = load_policy(&paths).unwrap();
        assert_eq!(policy.schema_version, 1);
    }
}
