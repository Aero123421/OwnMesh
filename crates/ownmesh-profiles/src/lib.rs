//! OwnMesh official and custom CLI profile definitions.
//!
//! Chapter 0 skeleton — nine official profiles arrive later.

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

    #[test]
    fn crate_metadata_is_stable() {
        assert_eq!(crate_name(), "ownmesh-profiles");
        assert!(!crate_version().is_empty());
    }
}
