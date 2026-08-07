//! Semver helpers (downgrade refusal, tag normalization).

use crate::error::{UpdateError, UpdateResult};
use semver::Version;

/// Strip a leading `v` from a tag / version string.
#[must_use]
pub fn strip_v_prefix(raw: &str) -> &str {
    raw.strip_prefix('v').unwrap_or(raw)
}

/// Parse a release version / tag into a [`Version`].
///
/// # Errors
///
/// Returns [`UpdateError::InvalidArgument`] when the version is not valid semver.
pub fn parse_version(raw: &str) -> UpdateResult<Version> {
    Version::parse(strip_v_prefix(raw.trim()))
        .map_err(|err| UpdateError::InvalidArgument(format!("invalid semver '{raw}': {err}")))
}

/// Refuse target versions that are strictly older than the installed version.
///
/// # Errors
///
/// Returns [`UpdateError::DowngradeRefused`] when `target < current`.
pub fn refuse_downgrade(current: &str, target: &str) -> UpdateResult<()> {
    let current_v = parse_version(current)?;
    let target_v = parse_version(target)?;
    if target_v < current_v {
        return Err(UpdateError::DowngradeRefused(format!(
            "current={current_v} target={target_v}"
        )));
    }
    Ok(())
}

/// True when target is newer than current.
///
/// # Errors
///
/// Returns parse errors from either side.
pub fn is_newer(current: &str, target: &str) -> UpdateResult<bool> {
    let current_v = parse_version(current)?;
    let target_v = parse_version(target)?;
    Ok(target_v > current_v)
}
