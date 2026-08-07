//! Official GitHub Release metadata client (fail-closed).

use crate::error::{UpdateError, UpdateResult};
use crate::platform::PlatformAsset;
use crate::redaction::redact_url;
use crate::semver_util::{parse_version, strip_v_prefix};
use crate::settings::UpdateChannel;
use crate::transport::{validate_url_host, FetchKind, FetchRequest, HttpTransport};
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;

/// Default GitHub repository (`owner/name`).
pub const DEFAULT_REPOSITORY: &str = "Aero123421/OwnMesh";

/// Release-meta JSON shipped beside portable archives (covered by SHA256SUMS).
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
pub struct ReleaseMeta {
    /// Schema version for this file.
    pub schema_version: u32,
    /// Semver without required `v` prefix.
    pub version: String,
    /// Channel label (`stable` / `beta`).
    pub channel: String,
    /// Minimum supported device protocol major.
    pub min_protocol: u32,
    /// Maximum supported device protocol major.
    pub max_protocol: u32,
}

impl ReleaseMeta {
    /// Current local device protocol major (`ownmesh.device/1.x` → 1).
    pub const LOCAL_PROTOCOL_MAJOR: u32 = 1;

    /// Validate protocol compatibility against the local major.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::ProtocolIncompatible`] outside the inclusive range.
    pub fn check_protocol(&self, local_protocol: u32) -> UpdateResult<()> {
        if local_protocol < self.min_protocol || local_protocol > self.max_protocol {
            return Err(UpdateError::ProtocolIncompatible(format!(
                "local={local_protocol} range={}..{}",
                self.min_protocol, self.max_protocol
            )));
        }
        Ok(())
    }
}

/// A selected GitHub release and the platform asset URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedRelease {
    /// Tag name (`v1.1.0`).
    pub tag_name: String,
    /// Semver without `v`.
    pub version: String,
    /// Whether GitHub marked the release as prerelease.
    pub prerelease: bool,
    /// Platform asset file name.
    pub asset_name: String,
    /// Browser download URL for the archive.
    pub asset_url: String,
    /// Browser download URL for `SHA256SUMS`.
    pub sha256sums_url: String,
    /// Browser download URL for `SHA256SUMS.minisig`.
    pub sha256sums_sig_url: String,
    /// Browser download URL for `ownmesh-release-meta.json`.
    pub release_meta_url: String,
}

#[derive(Debug, Deserialize)]
struct GhRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GhAsset>,
}

#[derive(Debug, Deserialize)]
struct GhAsset {
    name: String,
    #[allow(dead_code)]
    size: u64,
    browser_download_url: String,
}

/// Fetch and select a release for `channel` + `asset`.
///
/// # Errors
///
/// Returns metadata / selection failures.
pub fn select_release(
    transport: &dyn HttpTransport,
    repository: &str,
    channel: UpdateChannel,
    asset: &PlatformAsset,
) -> UpdateResult<SelectedRelease> {
    validate_repository(repository)?;
    let release = match channel {
        UpdateChannel::Stable => fetch_latest_stable(transport, repository)?,
        UpdateChannel::Beta => fetch_latest_beta(transport, repository)?,
    };
    materialize_selection(release, asset)
}

fn validate_repository(repository: &str) -> UpdateResult<()> {
    let mut parts = repository.split('/');
    let owner = parts.next().unwrap_or("");
    let name = parts.next().unwrap_or("");
    if parts.next().is_some()
        || owner.is_empty()
        || name.is_empty()
        || !owner
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        return Err(UpdateError::InvalidArgument(format!(
            "invalid repository '{repository}'"
        )));
    }
    Ok(())
}

fn fetch_latest_stable(transport: &dyn HttpTransport, repository: &str) -> UpdateResult<GhRelease> {
    let url = format!("https://api.github.com/repos/{repository}/releases/latest");
    let body = get_json(transport, &url)?;
    let release: GhRelease = serde_json::from_slice(&body)
        .map_err(|err| UpdateError::MissingMetadata(format!("latest release JSON: {err}")))?;
    if release.draft {
        return Err(UpdateError::MissingMetadata(
            "latest release is a draft".into(),
        ));
    }
    if release.prerelease {
        return Err(UpdateError::MissingMetadata(
            "latest release is a prerelease; stable channel requires a full release".into(),
        ));
    }
    Ok(release)
}

fn fetch_latest_beta(transport: &dyn HttpTransport, repository: &str) -> UpdateResult<GhRelease> {
    let url = format!("https://api.github.com/repos/{repository}/releases?per_page=30");
    let body = get_json(transport, &url)?;
    let releases: Vec<GhRelease> = serde_json::from_slice(&body)
        .map_err(|err| UpdateError::MissingMetadata(format!("releases JSON: {err}")))?;
    let mut best: Option<GhRelease> = None;
    let mut best_version = None;
    for release in releases {
        if release.draft {
            continue;
        }
        // Prefer prereleases for beta; still accept full releases when newer.
        let Ok(version) = parse_version(&release.tag_name) else {
            continue;
        };
        let take = match &best_version {
            None => true,
            Some(prev) => version > *prev,
        };
        if take {
            best_version = Some(version);
            best = Some(release);
        }
    }
    best.ok_or_else(|| UpdateError::MissingMetadata("no beta/stable release found".into()))
}

fn get_json(transport: &dyn HttpTransport, url: &str) -> UpdateResult<Vec<u8>> {
    validate_url_host(url)?;
    let mut headers = BTreeMap::new();
    headers.insert("accept".into(), "application/vnd.github+json".into());
    headers.insert("user-agent".into(), "ownmesh-update".into());
    let response = transport.fetch(&FetchRequest {
        url: url.to_owned(),
        kind: FetchKind::Metadata,
        headers,
    })?;
    // Ensure body is object/array JSON without retaining secrets in errors.
    let _: Value = serde_json::from_slice(&response.body).map_err(|err| {
        UpdateError::MissingMetadata(format!(
            "invalid JSON from {}: {err}",
            redact_url(&response.final_url)
        ))
    })?;
    Ok(response.body)
}

fn materialize_selection(
    release: GhRelease,
    asset: &PlatformAsset,
) -> UpdateResult<SelectedRelease> {
    let version = strip_v_prefix(&release.tag_name).to_owned();
    parse_version(&version)?;
    let mut by_name = BTreeMap::new();
    for a in release.assets {
        validate_url_host(&a.browser_download_url)?;
        by_name.insert(a.name.clone(), a);
    }
    let require = |name: &str| -> UpdateResult<&GhAsset> {
        by_name
            .get(name)
            .ok_or_else(|| UpdateError::MissingMetadata(format!("release asset missing: {name}")))
    };
    let archive = require(&asset.asset_name)?;
    let sums = require("SHA256SUMS")?;
    let sig = require("SHA256SUMS.minisig")?;
    let meta = require("ownmesh-release-meta.json")?;
    Ok(SelectedRelease {
        tag_name: release.tag_name,
        version,
        prerelease: release.prerelease,
        asset_name: archive.name.clone(),
        asset_url: archive.browser_download_url.clone(),
        sha256sums_url: sums.browser_download_url.clone(),
        sha256sums_sig_url: sig.browser_download_url.clone(),
        release_meta_url: meta.browser_download_url.clone(),
    })
}
