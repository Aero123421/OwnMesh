//! Verification order: minisig → SHA256SUMS → archive (+ release meta).

use crate::checksum::{parse_sha256sums, verify_checksum};
use crate::error::{UpdateError, UpdateResult};
use crate::github::{ReleaseMeta, SelectedRelease};
use crate::transport::{FetchKind, FetchRequest, HttpTransport};
use crate::trust::TrustRoot;
use std::collections::BTreeMap;

/// Fully verified download set ready for extraction / apply.
#[derive(Debug, Clone)]
pub struct VerifiedArtifacts {
    /// Release selection metadata.
    pub release: SelectedRelease,
    /// Parsed and protocol-checked release meta.
    pub meta: ReleaseMeta,
    /// Raw archive bytes.
    pub archive_bytes: Vec<u8>,
    /// Verified checksum map (asset → digest).
    pub checksums: BTreeMap<String, String>,
}

/// Download and verify artifacts for a previously selected release.
///
/// Order is mandatory and fail-closed:
/// 1. `SHA256SUMS.minisig` against the trust root
/// 2. `SHA256SUMS` digest list
/// 3. archive (+ release-meta) bytes against `SHA256SUMS`
///
/// # Errors
///
/// Returns signature, checksum, transport, or metadata errors.
pub fn download_and_verify(
    transport: &dyn HttpTransport,
    trust: &TrustRoot,
    release: &SelectedRelease,
    local_protocol: u32,
) -> UpdateResult<VerifiedArtifacts> {
    let sig = fetch(transport, &release.sha256sums_sig_url, FetchKind::Signature)?;
    let sums = fetch(transport, &release.sha256sums_url, FetchKind::Checksums)?;
    let sig_text = std::str::from_utf8(&sig).map_err(|_| UpdateError::BadSignature)?;
    trust.verify_detached(&sums, sig_text)?;

    let checksums = parse_sha256sums(
        std::str::from_utf8(&sums)
            .map_err(|_| UpdateError::MissingMetadata("SHA256SUMS is not valid UTF-8".into()))?,
    )?;

    let archive_digest = checksums.get(&release.asset_name).ok_or_else(|| {
        UpdateError::MissingMetadata(format!(
            "SHA256SUMS missing entry for {}",
            release.asset_name
        ))
    })?;
    let meta_digest = checksums.get("ownmesh-release-meta.json").ok_or_else(|| {
        UpdateError::MissingMetadata("SHA256SUMS missing ownmesh-release-meta.json".into())
    })?;

    let meta_bytes = fetch(transport, &release.release_meta_url, FetchKind::ReleaseMeta)?;
    verify_checksum(&meta_bytes, meta_digest)?;
    let meta: ReleaseMeta = serde_json::from_slice(&meta_bytes)
        .map_err(|err| UpdateError::MissingMetadata(format!("ownmesh-release-meta.json: {err}")))?;
    if meta.schema_version != 1 {
        return Err(UpdateError::MissingMetadata(format!(
            "unsupported release-meta schema_version {}",
            meta.schema_version
        )));
    }
    if crate::semver_util::strip_v_prefix(&meta.version) != release.version {
        return Err(UpdateError::MissingMetadata(format!(
            "release-meta version {} does not match tag {}",
            meta.version, release.version
        )));
    }
    meta.check_protocol(local_protocol)?;

    let archive_bytes = fetch(transport, &release.asset_url, FetchKind::Archive)?;
    verify_checksum(&archive_bytes, archive_digest)?;

    Ok(VerifiedArtifacts {
        release: release.clone(),
        meta,
        archive_bytes,
        checksums,
    })
}

fn fetch(transport: &dyn HttpTransport, url: &str, kind: FetchKind) -> UpdateResult<Vec<u8>> {
    let response = transport.fetch(&FetchRequest {
        url: url.to_owned(),
        kind,
        headers: BTreeMap::new(),
    })?;
    Ok(response.body)
}
