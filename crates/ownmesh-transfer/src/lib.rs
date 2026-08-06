//! OwnMesh optional device-to-device transfer planning.
//!
//! Chapter 0 skeleton — P2P transfer flows arrive later.

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
        assert_eq!(crate_name(), "ownmesh-transfer");
        assert!(!crate_version().is_empty());
    }
}
