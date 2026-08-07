//! Local update preferences.

use crate::error::{UpdateError, UpdateResult};
use serde::{Deserialize, Serialize};

/// Update mode — default off (no background network).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateMode {
    /// No automatic network activity.
    #[default]
    Off,
    /// Background check only.
    Check,
    /// Check and notify the user.
    Notify,
    /// Download when an update is available.
    Download,
    /// Download and apply automatically.
    Auto,
}

impl UpdateMode {
    /// Parse a config string.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::InvalidArgument`] for unknown values.
    pub fn parse(raw: &str) -> UpdateResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "check" => Ok(Self::Check),
            "notify" => Ok(Self::Notify),
            "download" => Ok(Self::Download),
            "auto" => Ok(Self::Auto),
            other => Err(UpdateError::InvalidArgument(format!(
                "unknown update mode '{other}'"
            ))),
        }
    }

    /// Config / JSON wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Check => "check",
            Self::Notify => "notify",
            Self::Download => "download",
            Self::Auto => "auto",
        }
    }
}

/// Release channel used for GitHub Release selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UpdateChannel {
    /// Latest non-prerelease GitHub Release.
    #[default]
    Stable,
    /// Latest release including prereleases (beta tags preferred when present).
    Beta,
}

impl UpdateChannel {
    /// Parse a channel name. Production network updates accept `stable` and `beta` only.
    ///
    /// # Errors
    ///
    /// Returns [`UpdateError::UnknownChannel`] for unsupported names (including `nightly`).
    pub fn parse(raw: &str) -> UpdateResult<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "stable" => Ok(Self::Stable),
            "beta" => Ok(Self::Beta),
            other => Err(UpdateError::UnknownChannel(other.to_owned())),
        }
    }

    /// Config / JSON wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Beta => "beta",
        }
    }
}

/// Local update settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpdateSettings {
    /// Update mode (default off).
    #[serde(default)]
    pub mode: UpdateMode,
    /// Preferred channel (default stable).
    #[serde(default)]
    pub channel: UpdateChannel,
    /// OwnMesh project telemetry — must default false.
    #[serde(default)]
    pub telemetry_enabled: bool,
    /// Crash reports — must default false.
    #[serde(default)]
    pub crash_reports_opt_in: bool,
}

impl Default for UpdateSettings {
    fn default() -> Self {
        Self {
            mode: UpdateMode::Off,
            channel: UpdateChannel::Stable,
            telemetry_enabled: false,
            crash_reports_opt_in: false,
        }
    }
}

/// Whether background / automatic network checks are permitted under settings.
#[must_use]
pub fn network_check_allowed(settings: &UpdateSettings) -> bool {
    !matches!(settings.mode, UpdateMode::Off)
}

/// Privacy guarantees for defaults tests.
#[must_use]
pub fn default_sends_nothing_to_vendor(settings: &UpdateSettings) -> bool {
    !settings.telemetry_enabled
        && !settings.crash_reports_opt_in
        && settings.mode == UpdateMode::Off
}
