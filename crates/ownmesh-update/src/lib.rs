//! OwnMesh signed update channels, verification, and atomic install.
//!
//! Production trust model:
//! 1. Official GitHub Release metadata only
//! 2. OS/arch asset selection
//! 3. `SHA256SUMS.minisig` (embedded minisign public key) → `SHA256SUMS` → archive
//! 4. Semver downgrade refusal, protocol compatibility, size/time/host fail-closed
//!
//! Telemetry and automatic network checks are **off by default**.
//!
//! The legacy shared-secret demo signature lives in [`demo`] and is **not** used
//! by production CLI paths.

#![allow(
    clippy::doc_markdown,
    clippy::format_push_string,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::too_many_lines
)]

mod archive;
mod checksum;
pub mod demo;
mod engine;
mod error;
mod github;
mod install;
mod limits;
mod platform;
mod redaction;
mod semver_util;
mod settings;
mod transport;
mod trust;
mod verify;

pub use archive::extract_required_binaries;
pub use checksum::{parse_sha256sums, sha256_hex, verify_checksum};
pub use engine::{CheckReport, UpdateEngine};
pub use error::{UpdateError, UpdateResult};
pub use github::{ReleaseMeta, SelectedRelease, DEFAULT_REPOSITORY};
pub use install::{
    apply_binaries, current_install_dir, finalize_apply, finalize_interrupted_commit,
    interrupted_apply_pending, is_homebrew_install, recover_interrupted_apply, rollback_apply,
    verify_applied_binaries, ApplyReport,
};
pub use limits::{
    ALLOWED_DOC_FILES, DOWNLOAD_TIMEOUT_SECS, MAX_ARCHIVE_BYTES, MAX_ARCHIVE_ENTRIES,
    MAX_CHECKSUMS_BYTES, MAX_ENTRY_UNCOMPRESSED_BYTES, MAX_METADATA_BYTES, MAX_SIGNATURE_BYTES,
    MAX_TOTAL_UNCOMPRESSED_BYTES, METADATA_TIMEOUT_SECS,
};
pub use platform::{
    binary_file_name, binary_file_name_for, select_platform_asset, select_platform_asset_for,
    ArchiveKind, PlatformAsset, REQUIRED_BINARIES,
};
pub use redaction::{looks_secret, redact_json, redact_url};
pub use semver_util::{is_newer, parse_version, refuse_downgrade, strip_v_prefix};
pub use settings::{
    default_sends_nothing_to_vendor, network_check_allowed, UpdateChannel, UpdateMode,
    UpdateSettings,
};
pub use transport::{
    host_allowed, validate_url_host, FetchKind, FetchRequest, FetchResponse, HttpTransport,
    MapTransport, ALLOWED_HOSTS,
};
pub use trust::{TrustRoot, EMBEDDED_MINISIGN_PUB, MINISIGN_FINGERPRINT_SHA256, MINISIGN_KEY_ID};
pub use verify::{download_and_verify, VerifiedArtifacts};

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

/// Checks whether a local protocol major is supported by release meta.
///
/// # Errors
///
/// Returns [`UpdateError::ProtocolIncompatible`] outside the inclusive range.
pub fn check_protocol(meta: &ReleaseMeta, local_protocol: u32) -> UpdateResult<()> {
    meta.check_protocol(local_protocol)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::demo::{sign_demo_manifest_payload, verify_demo_signature, DemoManifest};

    #[test]
    fn defaults_are_private() {
        let s = UpdateSettings::default();
        assert!(default_sends_nothing_to_vendor(&s));
        assert!(!network_check_allowed(&s));
    }

    #[test]
    fn demo_signature_isolated_from_production_api() {
        let secret = b"test-secret";
        let data = b"artifact";
        let sha = sha256_hex(data);
        let mut m = DemoManifest {
            version: "1.0.0".into(),
            channel: UpdateChannel::Stable,
            url: "https://example.invalid/ownmesh".into(),
            sha256: sha,
            signature: String::new(),
            min_protocol: 1,
            max_protocol: 1,
        };
        m.signature = sign_demo_manifest_payload(secret, &m);
        verify_demo_signature(secret, &m).unwrap();
        verify_checksum(data, &m.sha256).unwrap();
    }

    #[test]
    fn platform_linux_x64() {
        let asset = select_platform_asset_for("linux", "x86_64").unwrap();
        assert_eq!(asset.asset_name, "ownmesh-linux-x64.tar.gz");
    }

    #[test]
    fn host_policy_fail_closed() {
        assert!(host_allowed("github.com"));
        assert!(host_allowed("objects.githubusercontent.com"));
        assert!(!host_allowed("evil.example"));
        assert!(validate_url_host("https://evil.example/a").is_err());
        assert!(validate_url_host("http://github.com/a").is_err());
    }

    #[test]
    fn downgrade_refused() {
        assert!(refuse_downgrade("1.1.0", "1.0.9").is_err());
        assert!(refuse_downgrade("1.1.0", "1.1.0").is_ok());
        assert!(refuse_downgrade("1.1.0", "1.2.0").is_ok());
    }
}
