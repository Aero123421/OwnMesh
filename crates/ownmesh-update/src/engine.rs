//! High-level check / download / apply orchestration.

use crate::archive::extract_required_binaries;
use crate::error::{UpdateError, UpdateResult};
use crate::github::{select_release, ReleaseMeta, SelectedRelease, DEFAULT_REPOSITORY};
use crate::install::{apply_binaries, current_install_dir, is_homebrew_install, ApplyReport};
use crate::platform::{select_platform_asset, select_platform_asset_for, PlatformAsset};
use crate::semver_util::{is_newer, refuse_downgrade};
use crate::settings::{UpdateChannel, UpdateSettings};
use crate::transport::HttpTransport;
use crate::trust::TrustRoot;
use crate::verify::{download_and_verify, VerifiedArtifacts};
use serde::Serialize;
use std::path::PathBuf;

/// Outcome of `update check`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CheckReport {
    /// Currently installed version.
    pub current_version: String,
    /// Newest available version on the channel (if any).
    pub available_version: Option<String>,
    /// Selected channel.
    pub channel: String,
    /// Platform asset name that would be downloaded.
    pub asset_name: Option<String>,
    /// True when an upgrade is available.
    pub update_available: bool,
    /// Tag name on GitHub.
    pub tag_name: Option<String>,
}

/// Engine configuration.
#[derive(Debug, Clone)]
pub struct UpdateEngine {
    /// GitHub `owner/name`.
    pub repository: String,
    /// Trust root (embedded production key by default).
    pub trust: TrustRoot,
    /// Local device protocol major.
    pub local_protocol: u32,
    /// Installed package version (`CARGO_PKG_VERSION`).
    pub current_version: String,
    /// Optional install directory override (tests).
    pub install_dir_override: Option<PathBuf>,
    /// Optional platform override (tests) as `(os, arch)`.
    pub platform_override: Option<(String, String)>,
}

impl Default for UpdateEngine {
    fn default() -> Self {
        Self {
            repository: DEFAULT_REPOSITORY.to_owned(),
            trust: TrustRoot::default(),
            local_protocol: ReleaseMeta::LOCAL_PROTOCOL_MAJOR,
            current_version: env!("CARGO_PKG_VERSION").to_owned(),
            install_dir_override: None,
            platform_override: None,
        }
    }
}

impl UpdateEngine {
    /// Resolve the platform asset for this engine.
    ///
    /// # Errors
    ///
    /// Returns unsupported platform errors.
    pub fn platform_asset(&self) -> UpdateResult<PlatformAsset> {
        match &self.platform_override {
            Some((os, arch)) => select_platform_asset_for(os, arch),
            None => select_platform_asset(),
        }
    }

    /// Check for a newer release without downloading the archive.
    ///
    /// Explicit CLI checks are always allowed (user-initiated). Background
    /// callers must pass settings with a non-`off` mode.
    ///
    /// # Errors
    ///
    /// Returns selection / network / policy errors.
    pub fn check(
        &self,
        transport: &dyn HttpTransport,
        channel: UpdateChannel,
        require_network_mode: Option<&UpdateSettings>,
    ) -> UpdateResult<CheckReport> {
        if let Some(settings) = require_network_mode {
            if !crate::settings::network_check_allowed(settings) {
                return Err(UpdateError::Disabled);
            }
        }
        let asset = self.platform_asset()?;
        let release = select_release(transport, &self.repository, channel, &asset)?;
        refuse_downgrade(&self.current_version, &release.version)?;
        let newer = is_newer(&self.current_version, &release.version)?;
        Ok(CheckReport {
            current_version: self.current_version.clone(),
            available_version: Some(release.version.clone()),
            channel: channel.as_str().to_owned(),
            asset_name: Some(release.asset_name),
            update_available: newer,
            tag_name: Some(release.tag_name),
        })
    }

    /// Download and fully verify the newest release on `channel`.
    ///
    /// # Errors
    ///
    /// Returns verification / downgrade / transport errors.
    pub fn download(
        &self,
        transport: &dyn HttpTransport,
        channel: UpdateChannel,
    ) -> UpdateResult<VerifiedArtifacts> {
        let asset = self.platform_asset()?;
        let release = select_release(transport, &self.repository, channel, &asset)?;
        refuse_downgrade(&self.current_version, &release.version)?;
        if !is_newer(&self.current_version, &release.version)? {
            return Err(UpdateError::AlreadyCurrent(self.current_version.clone()));
        }
        download_and_verify(transport, &self.trust, &release, self.local_protocol)
    }

    /// Download (if needed via provided artifacts) and apply into the install dir.
    ///
    /// # Errors
    ///
    /// Returns install / homebrew / verification errors.
    pub fn apply_verified(&self, artifacts: &VerifiedArtifacts) -> UpdateResult<ApplyReport> {
        refuse_downgrade(&self.current_version, &artifacts.release.version)?;
        let install_dir = match &self.install_dir_override {
            Some(dir) => dir.clone(),
            None => current_install_dir()?,
        };
        if is_homebrew_install(&install_dir) {
            return Err(UpdateError::HomebrewManaged);
        }
        let (os, _) = self.platform_override.clone().unwrap_or_else(|| {
            (
                std::env::consts::OS.to_owned(),
                std::env::consts::ARCH.to_owned(),
            )
        });
        let asset = self.platform_asset()?;
        let binaries = extract_required_binaries(&artifacts.archive_bytes, asset.kind, &os)?;
        apply_binaries(&install_dir, &binaries, &artifacts.release.version)
    }

    /// End-to-end download + verify + apply.
    ///
    /// # Errors
    ///
    /// Returns any staged failure.
    pub fn download_and_apply(
        &self,
        transport: &dyn HttpTransport,
        channel: UpdateChannel,
    ) -> UpdateResult<ApplyReport> {
        let artifacts = self.download(transport, channel)?;
        self.apply_verified(&artifacts)
    }

    /// Re-select a release (test helper / diagnostics).
    ///
    /// # Errors
    ///
    /// Returns selection errors.
    pub fn select(
        &self,
        transport: &dyn HttpTransport,
        channel: UpdateChannel,
    ) -> UpdateResult<SelectedRelease> {
        let asset = self.platform_asset()?;
        select_release(transport, &self.repository, channel, &asset)
    }
}
