//! Typed configuration schema and validation.

use crate::error::{ConfigError, ConfigResult};
use serde::{Deserialize, Serialize};

/// Current on-disk schema version for `config.toml`.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Top-level OwnMesh configuration file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnMeshConfig {
    /// Schema version used for migrations.
    pub schema_version: u32,
    /// Active control-plane instance id / alias.
    #[serde(default)]
    pub active_instance: Option<String>,
    /// Default UI / CLI language tag (`en-US`, `ja-JP`, …).
    #[serde(default = "default_lang")]
    pub lang: String,
    /// Update channel preference.
    #[serde(default)]
    pub update: UpdateConfig,
    /// Telemetry preferences (all off by default).
    #[serde(default)]
    pub telemetry: TelemetryConfig,
    /// Named control-plane instances.
    #[serde(default)]
    pub instances: Vec<InstanceConfig>,
}

impl Default for OwnMeshConfig {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            active_instance: None,
            lang: default_lang(),
            update: UpdateConfig::default(),
            telemetry: TelemetryConfig::default(),
            instances: Vec::new(),
        }
    }
}

impl OwnMeshConfig {
    /// Validate semantic constraints.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::Validation`] on illegal values.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.schema_version == 0 {
            return Err(ConfigError::Validation {
                message: "schema_version must be >= 1".into(),
            });
        }
        if self.lang.trim().is_empty() {
            return Err(ConfigError::Validation {
                message: "lang must not be empty".into(),
            });
        }
        if let Some(active) = &self.active_instance {
            if !self.instances.iter().any(|i| &i.id == active) && !self.instances.is_empty() {
                return Err(ConfigError::Validation {
                    message: format!("active_instance `{active}` is not defined in instances"),
                });
            }
        }
        for inst in &self.instances {
            inst.validate()?;
        }
        self.update.validate()?;
        // Secrets must never appear as fields on this struct — enforced by type design.
        Ok(())
    }
}

fn default_lang() -> String {
    "en-US".into()
}

/// Update subsystem preferences.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateConfig {
    /// Update mode: off | check | notify | download | auto.
    #[serde(default = "default_update_mode")]
    pub mode: String,
    /// Channel: stable | beta | nightly.
    #[serde(default = "default_update_channel")]
    pub channel: String,
}

impl Default for UpdateConfig {
    fn default() -> Self {
        Self {
            mode: default_update_mode(),
            channel: default_update_channel(),
        }
    }
}

impl UpdateConfig {
    fn validate(&self) -> ConfigResult<()> {
        match self.mode.as_str() {
            "off" | "check" | "notify" | "download" | "auto" => {}
            other => {
                return Err(ConfigError::Validation {
                    message: format!("unknown update.mode: {other}"),
                });
            }
        }
        match self.channel.as_str() {
            "stable" | "beta" | "nightly" => {}
            other => {
                return Err(ConfigError::Validation {
                    message: format!("unknown update.channel: {other}"),
                });
            }
        }
        Ok(())
    }
}

fn default_update_mode() -> String {
    "notify".into()
}

fn default_update_channel() -> String {
    "stable".into()
}

/// Telemetry toggles — all default off per specification §25.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryConfig {
    /// Project telemetry upload.
    #[serde(default)]
    pub project: bool,
    /// Crash report upload.
    #[serde(default)]
    pub crash_upload: bool,
    /// Usage analytics.
    #[serde(default)]
    pub usage_analytics: bool,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            project: false,
            crash_upload: false,
            usage_analytics: false,
        }
    }
}

/// A configured control-plane instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstanceConfig {
    /// Local alias / id.
    pub id: String,
    /// Base URL of the control plane (https://…).
    pub base_url: String,
    /// Optional display name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
}

impl InstanceConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Validation {
                message: "instance.id must not be empty".into(),
            });
        }
        validate_instance_base_url(&self.id, &self.base_url)?;
        // Guard against accidental secret embedding in URL userinfo for config dumps.
        if self.base_url.contains('@') && self.base_url.contains("token") {
            return Err(ConfigError::Validation {
                message: "instance base_url must not embed credentials".into(),
            });
        }
        Ok(())
    }
}

/// Validate a control-plane base URL / issuer.
///
/// `https://` is always accepted. `http://` is accepted only for loopback hosts
/// (`127.0.0.0/8`, `::1`, `localhost`) so local mock servers keep working while
/// non-loopback cleartext issuers are fail-closed.
///
/// Returns the trimmed URL (no trailing `/`) on success.
pub fn validate_control_plane_base_url(base_url: &str) -> ConfigResult<String> {
    validate_instance_base_url("<issuer>", base_url)?;
    Ok(base_url.trim().trim_end_matches('/').to_owned())
}

fn validate_instance_base_url(id: &str, base_url: &str) -> ConfigResult<()> {
    let raw = base_url.trim().trim_end_matches('/');
    if raw.is_empty() {
        return Err(ConfigError::Validation {
            message: format!("instance `{id}` base_url must not be empty"),
        });
    }

    if let Some(rest) = raw.strip_prefix("https://") {
        if host_from_authority(rest).is_empty() {
            return Err(ConfigError::Validation {
                message: format!("instance `{id}` base_url must include a host"),
            });
        }
        return Ok(());
    }

    if let Some(rest) = raw.strip_prefix("http://") {
        let host = host_from_authority(rest);
        if host.is_empty() {
            return Err(ConfigError::Validation {
                message: format!("instance `{id}` base_url must include a host"),
            });
        }
        if is_loopback_host(host) {
            return Ok(());
        }
        return Err(ConfigError::Validation {
            message: format!(
                "instance `{id}` base_url refuses non-loopback http:// (`{raw}`); use https:// or a loopback host (127.0.0.1, ::1, localhost)"
            ),
        });
    }

    Err(ConfigError::Validation {
        message: format!(
            "instance `{id}` base_url must start with https:// (or http:// on loopback only)"
        ),
    })
}

/// Extract host from the authority+path portion after `scheme://`.
fn host_from_authority(after_scheme: &str) -> &str {
    let authority = after_scheme.split(['/', '?', '#']).next().unwrap_or("");
    // Drop userinfo if present.
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, hostport)| hostport);
    if let Some(inner) = authority.strip_prefix('[') {
        // IPv6 literal: [2001:db8::1]:443
        return inner.split(']').next().unwrap_or("");
    }
    authority.split(':').next().unwrap_or("")
}

fn is_loopback_host(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    match host.parse::<std::net::IpAddr>() {
        Ok(ip) => ip.is_loopback(),
        Err(_) => false,
    }
}

/// Minimal policy file schema (full evaluator arrives in later chapters).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyFile {
    /// Schema version.
    pub schema_version: u32,
    /// Selected preset name when using a built-in preset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            preset: Some("recommended".into()),
        }
    }
}

impl PolicyFile {
    /// Validate policy file basics.
    ///
    /// # Errors
    ///
    /// Returns validation errors for illegal values.
    pub fn validate(&self) -> ConfigResult<()> {
        if self.schema_version == 0 {
            return Err(ConfigError::Validation {
                message: "policy schema_version must be >= 1".into(),
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        let cfg = OwnMeshConfig::default();
        cfg.validate().unwrap();
        assert_eq!(cfg.schema_version, CONFIG_SCHEMA_VERSION);
        assert!(!cfg.telemetry.project);
    }

    #[test]
    fn rejects_bad_update_mode() {
        let mut cfg = OwnMeshConfig::default();
        cfg.update.mode = "explode".into();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_toml_has_no_secret_fields() {
        let cfg = OwnMeshConfig::default();
        let text = toml::to_string_pretty(&cfg).unwrap();
        for needle in ["refresh_token", "private_key", "client_secret", "password"] {
            assert!(
                !text.to_ascii_lowercase().contains(needle),
                "config dump unexpectedly contains {needle}: {text}"
            );
        }
    }

    #[test]
    fn instance_allows_loopback_http_and_https() {
        for url in [
            "http://127.0.0.1:9",
            "http://127.0.0.1",
            "http://[::1]:8080",
            "http://localhost:8750",
            "https://example.test",
        ] {
            let inst = InstanceConfig {
                id: "local".into(),
                base_url: url.into(),
                display_name: None,
            };
            inst.validate()
                .unwrap_or_else(|e| panic!("expected {url} ok, got {e}"));
        }
    }

    #[test]
    fn instance_rejects_non_loopback_http() {
        let inst = InstanceConfig {
            id: "remote".into(),
            base_url: "http://example.test".into(),
            display_name: None,
        };
        let err = inst.validate().expect_err("non-loopback http must fail");
        let msg = err.to_string();
        assert!(
            msg.contains("non-loopback"),
            "expected explicit non-loopback error, got: {msg}"
        );
    }
}
