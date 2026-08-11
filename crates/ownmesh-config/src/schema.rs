//! Typed configuration schema and validation.

use crate::error::{ConfigError, ConfigResult};
use ownmesh_policy::PolicyRule;
use serde::{Deserialize, Serialize};

/// Current on-disk schema version for `config.toml`.
pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// Top-level `OwnMesh` configuration file.
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
    /// Local service IPC socket privilege boundary (Unix path/owner/group/mode/uids).
    #[serde(default)]
    pub service_socket: ServiceSocketConfig,
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
            service_socket: ServiceSocketConfig::default(),
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
        self.service_socket.validate()?;
        // Secrets must never appear as fields on this struct — enforced by type design.
        Ok(())
    }
}

/// Local daemon service socket privilege boundary.
///
/// On Unix, `ownmeshd` binds a domain socket at `path` (or the default runtime path),
/// applies `owner`/`group`/`mode`, and only accepts peers whose OS uid is in
/// `allowed_uids` (empty ⇒ process effective uid only). ACL application failures
/// are fail-closed (daemon refuses to serve).
///
/// World-accessible modes (`*o+rwx`) are rejected. Never use `0o666`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ServiceSocketConfig {
    /// Absolute or runtime-relative socket path override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Owner uid as decimal string (e.g. `"1000"`). Username resolution is not required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// Group gid as decimal string (e.g. `"1000"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Octal mode string without prefix (`"600"`, `"660"`). Default `600` when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    /// Peer uids permitted after `SO_PEERCRED`. Empty ⇒ daemon euid only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_uids: Vec<u32>,
}

impl ServiceSocketConfig {
    fn validate(&self) -> ConfigResult<()> {
        if let Some(mode_s) = &self.mode {
            let mode = parse_mode_octal(mode_s).map_err(|message| ConfigError::Validation {
                message: format!("service_socket.mode: {message}"),
            })?;
            // Forbid any access for "other" (never 0666 / world-readable).
            if mode & 0o007 != 0 {
                return Err(ConfigError::Validation {
                    message: format!(
                        "service_socket.mode `{mode_s}` grants access to other; refused (fail-closed)"
                    ),
                });
            }
            // Group bits require an explicit group.
            if mode & 0o070 != 0 && self.group.is_none() {
                return Err(ConfigError::Validation {
                    message:
                        "service_socket.mode grants group access but service_socket.group is unset"
                            .into(),
                });
            }
        }
        if let Some(owner) = &self.owner {
            parse_id_token(owner, "owner").map_err(|message| ConfigError::Validation {
                message: format!("service_socket.owner: {message}"),
            })?;
        }
        if let Some(group) = &self.group {
            parse_id_token(group, "group").map_err(|message| ConfigError::Validation {
                message: format!("service_socket.group: {message}"),
            })?;
        }
        if let Some(path) = &self.path {
            if path.trim().is_empty() {
                return Err(ConfigError::Validation {
                    message: "service_socket.path must not be empty when set".into(),
                });
            }
        }
        Ok(())
    }

    /// Parsed owner uid, if configured.
    #[must_use]
    pub fn owner_uid(&self) -> Option<u32> {
        self.owner
            .as_deref()
            .and_then(|s| parse_id_token(s, "owner").ok())
    }

    /// Parsed group gid, if configured.
    #[must_use]
    pub fn group_gid(&self) -> Option<u32> {
        self.group
            .as_deref()
            .and_then(|s| parse_id_token(s, "group").ok())
    }

    /// Parsed mode bits (default `0o600`).
    #[must_use]
    pub fn mode_bits(&self) -> u32 {
        self.mode
            .as_deref()
            .and_then(|s| parse_mode_octal(s).ok())
            .unwrap_or(0o600)
    }
}

fn parse_mode_octal(raw: &str) -> Result<u32, String> {
    // Accept "600", "0600", "0o600".
    let cleaned = raw.trim();
    let digits = cleaned
        .strip_prefix("0o")
        .or_else(|| cleaned.strip_prefix("0O"))
        .unwrap_or(cleaned);
    // Keep a single leading zero so bare "0" still parses; strip only decorative
    // multi-digit octal prefixes like "0600" → parse as octal digits including 0.
    u32::from_str_radix(digits, 8)
        .map_err(|e| format!("invalid octal mode `{raw}`: {e}"))
        .and_then(|m| {
            if m > 0o777 {
                Err(format!("mode `{raw}` out of range"))
            } else {
                Ok(m)
            }
        })
}

fn parse_id_token(raw: &str, label: &str) -> Result<u32, String> {
    let t = raw.trim();
    if t.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    t.parse::<u32>()
        .map_err(|_| format!("{label} must be a decimal uid/gid, got `{raw}`"))
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
    // Network off by default (specification §14 / privacy defaults).
    "off".into()
}

fn default_update_channel() -> String {
    "stable".into()
}

/// Telemetry toggles — all default off per specification §25.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
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

/// Canonical instance-id syntax shared by every writer and validator.
///
/// This is the single source of truth. `setup`, `instance add/use`, `config
/// edit`, and `config validate` all route through it, so no command can write
/// an id that another command later refuses.
pub const INSTANCE_ID_SYNTAX: &str = "[A-Za-z0-9][A-Za-z0-9._-]{0,63}";

/// Whether `value` is a legal control-plane instance id.
#[must_use]
pub fn valid_instance_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value != "."
        && value != ".."
        && value
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

impl InstanceConfig {
    fn validate(&self) -> ConfigResult<()> {
        if self.id.trim().is_empty() {
            return Err(ConfigError::Validation {
                message: "instance.id must not be empty".into(),
            });
        }
        if !valid_instance_id(&self.id) {
            return Err(ConfigError::Validation {
                message: format!("instance.id must match {INSTANCE_ID_SYNTAX}"),
            });
        }
        let _normalized = validate_control_plane_base_url(&self.base_url).map_err(|err| {
            // Re-scope generic issuer errors to the instance id without echoing secrets.
            match err {
                ConfigError::Validation { message } => ConfigError::Validation {
                    message: message.replace("`<issuer>`", &format!("`{id}`", id = self.id)),
                },
                other => other,
            }
        })?;
        Ok(())
    }
}

/// Redact a control-plane URL for logs, doctor, setup errors, and JSON surfaces.
///
/// Strips userinfo, query, and fragment. Invalid / secret-looking values collapse to
/// `[REDACTED]` so unsafe config cannot leak credentials through diagnostics.
#[must_use]
pub fn redact_control_plane_url(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.chars().any(char::is_control) {
        return "[REDACTED]".into();
    }
    let Ok(mut url) = url::Url::parse(trimmed) else {
        let lower = trimmed.to_ascii_lowercase();
        if lower.contains('@')
            || lower.contains("token")
            || lower.contains("password")
            || lower.contains("secret")
            || lower.contains('%')
        {
            return "[REDACTED]".into();
        }
        return trimmed.to_owned();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    let mut out = url.to_string();
    if out.ends_with('/') && url.path() == "/" {
        out.pop();
    }
    out
}

/// Validate a control-plane base URL / issuer with strict [`url::Url`] parsing.
///
/// Rules (shared by flag / JSON / config load):
/// - Parse with `url::Url` (rejects whitespace control chars and malformed input).
/// - `https://` is accepted for any host.
/// - `http://` is accepted **only** for loopback hosts (`127.0.0.0/8`, `::1`, `localhost`)
///   so local mock servers keep working while non-loopback cleartext is fail-closed.
/// - Reject userinfo, query, fragment, and ASCII control characters.
/// - Require a non-empty host.
///
/// Returns the normalized URL (no trailing `/` on the origin path) on success.
/// Error messages never echo credential-bearing input — only redacted forms.
pub fn validate_control_plane_base_url(base_url: &str) -> ConfigResult<String> {
    let raw = base_url.trim();
    if raw.is_empty() {
        return Err(ConfigError::Validation {
            message: "instance `<issuer>` base_url must not be empty".into(),
        });
    }
    if raw.chars().any(char::is_control) {
        return Err(ConfigError::Validation {
            message: format!(
                "instance `<issuer>` base_url contains control characters ({})",
                redact_control_plane_url(raw)
            ),
        });
    }

    let url = url::Url::parse(raw).map_err(|err| ConfigError::Validation {
        message: format!(
            "instance `<issuer>` base_url is not a valid URL ({}): {err}",
            redact_control_plane_url(raw)
        ),
    })?;

    match url.scheme() {
        "https" => {}
        "http" => {
            let host = url.host_str().unwrap_or("");
            if !is_loopback_host(host) {
                return Err(ConfigError::Validation {
                    message: format!(
                        "instance `<issuer>` base_url refuses non-loopback http:// ({}); use https:// or a loopback host (127.0.0.1, ::1, localhost)",
                        redact_control_plane_url(raw)
                    ),
                });
            }
        }
        other => {
            return Err(ConfigError::Validation {
                message: format!(
                    "instance `<issuer>` base_url must start with https:// (or http:// on loopback only); got scheme `{other}` ({})",
                    redact_control_plane_url(raw)
                ),
            });
        }
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(ConfigError::Validation {
            message: format!(
                "instance `<issuer>` base_url must not embed userinfo/credentials ({})",
                redact_control_plane_url(raw)
            ),
        });
    }
    if url.query().is_some() {
        return Err(ConfigError::Validation {
            message: format!(
                "instance `<issuer>` base_url must not include a query string ({})",
                redact_control_plane_url(raw)
            ),
        });
    }
    if url.fragment().is_some() {
        return Err(ConfigError::Validation {
            message: format!(
                "instance `<issuer>` base_url must not include a fragment ({})",
                redact_control_plane_url(raw)
            ),
        });
    }
    if url.host_str().is_none_or(str::is_empty) {
        return Err(ConfigError::Validation {
            message: "instance `<issuer>` base_url must include a host".into(),
        });
    }

    let mut normalized = url.to_string();
    if normalized.ends_with('/') && url.path() == "/" {
        normalized.pop();
    } else if normalized.ends_with('/') && normalized.matches('/').count() > 2 {
        // Drop a lone trailing slash after a non-root path (base URL convention).
        normalized.pop();
    }
    Ok(normalized)
}

fn is_loopback_host(host: &str) -> bool {
    // `url::Url::host_str` may yield bracketed IPv6 (`[::1]`) depending on version.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
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
    /// When deliberately enabled during local setup, an authenticated and
    /// exact-bound remote MCP invocation is the user's requested action.  This
    /// is not (and must never be represented as) a ChatGPT attestation.
    #[serde(default)]
    pub delegate_remote_mcp: bool,
    /// Bounded user-authored rules. Built-in preset rules are reconstructed by
    /// the daemon and these rules are appended as an explicit local overlay.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<PolicyRule>,
}

impl Default for PolicyFile {
    fn default() -> Self {
        Self {
            schema_version: 1,
            preset: Some("recommended".into()),
            delegate_remote_mcp: false,
            rules: Vec::new(),
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
        let preset = self
            .preset
            .as_deref()
            .unwrap_or("recommended")
            .to_ascii_lowercase()
            .replace('-', "_");
        if preset == "full_access" && !self.rules.is_empty() {
            return Err(ConfigError::Validation {
                message: "full_access policy cannot contain custom rules".into(),
            });
        }
        validate_policy_rules(&self.rules)?;
        Ok(())
    }
}

fn validate_policy_rules(rules: &[PolicyRule]) -> ConfigResult<()> {
    const MAX_RULES: usize = 64;
    if rules.len() > MAX_RULES {
        return Err(ConfigError::Validation {
            message: format!("policy rules exceed {MAX_RULES} entry limit"),
        });
    }
    let mut ids = std::collections::HashSet::with_capacity(rules.len());
    for rule in rules {
        let id = rule.id.trim();
        if id.is_empty()
            || id.len() > 64
            || !id.starts_with("rule_")
            || !id
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        {
            return Err(ConfigError::Validation {
                message: format!(
                    "invalid policy rule id: {:?} (expected rule_..., max 64)",
                    rule.id
                ),
            });
        }
        if !ids.insert(id) {
            return Err(ConfigError::Validation {
                message: format!("duplicate policy rule id: {id}"),
            });
        }
        if !(-1_000..=1_000).contains(&rule.priority) {
            return Err(ConfigError::Validation {
                message: format!("policy rule {id} priority must be between -1000 and 1000"),
            });
        }
        validate_policy_token(id, "capability", &rule.capability, 64, true)?;
        if let Some(kind) = rule.when_kind.as_deref() {
            validate_policy_token(id, "when_kind", kind, 32, false)?;
        }
        for (field, value, max) in [
            ("path_prefix", rule.path_prefix.as_deref(), 1_024_usize),
            ("program_equals", rule.program_equals.as_deref(), 512_usize),
            ("description", rule.description.as_deref(), 512_usize),
        ] {
            if let Some(value) = value {
                if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
                    return Err(ConfigError::Validation {
                        message: format!(
                            "policy rule {id} {field} must be non-empty, control-free, and at most {max} bytes"
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn validate_policy_token(
    id: &str,
    field: &str,
    value: &str,
    max: usize,
    wildcard: bool,
) -> ConfigResult<()> {
    let valid_wildcard = wildcard
        && (value == "*"
            || value
                .strip_suffix(".*")
                .is_some_and(|prefix| !prefix.is_empty() && !prefix.contains('*')));
    let plain = !value.contains('*');
    if value.is_empty()
        || value.len() > max
        || !(plain || valid_wildcard)
        || !value.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-' | '*')
        })
    {
        return Err(ConfigError::Validation {
            message: format!("policy rule {id} has invalid {field}"),
        });
    }
    Ok(())
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
    fn full_access_rejects_hidden_custom_rules() {
        let policy = PolicyFile {
            schema_version: 1,
            preset: Some("full_access".into()),
            delegate_remote_mcp: false,
            rules: vec![PolicyRule {
                id: "rule_hidden_ask".into(),
                decision: ownmesh_policy::Decision::Ask,
                priority: 1,
                capability: "filesystem.write".into(),
                when_elevated: None,
                when_kind: None,
                path_prefix: None,
                program_equals: None,
                description: None,
            }],
        };
        let error = policy
            .validate()
            .expect_err("hidden Full Access rule must fail");
        assert!(error.to_string().contains("full_access"));
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
        assert!(
            !msg.contains("example.test") || msg.contains("http://example.test"),
            "message may include redacted host form: {msg}"
        );
    }

    #[test]
    fn rejects_userinfo_query_fragment_and_control_chars() {
        for bad in [
            "https://user:s3cret@cp.example.test",
            "https://USER:TokenValue@cp.example.test/path",
            "https://cp.example.test?access_token=abc",
            "https://cp.example.test#frag",
            "https://cp.example.test/path?x=1#y",
            "https://cp.example.test/\npath",
            "http://user:pw@127.0.0.1:9",
        ] {
            let err =
                validate_control_plane_base_url(bad).expect_err(&format!("must reject {bad}"));
            let msg = err.to_string();
            assert!(
                !msg.to_ascii_lowercase().contains("s3cret"),
                "secret leaked in error: {msg}"
            );
            assert!(
                !msg.contains("TokenValue") && !msg.contains("access_token=abc"),
                "credential leaked in error: {msg}"
            );
            let redacted = redact_control_plane_url(bad);
            assert!(
                !redacted.to_ascii_lowercase().contains("s3cret"),
                "redact leaked secret: {redacted}"
            );
            assert!(
                !redacted.contains("user:"),
                "userinfo not stripped: {redacted}"
            );
            assert!(!redacted.contains('?'), "query not stripped: {redacted}");
            assert!(!redacted.contains('#'), "fragment not stripped: {redacted}");
        }
    }

    #[test]
    fn mixed_case_userinfo_is_rejected_and_redacted() {
        let bad = "https://AdMiN:P@ssW0rd@Example.TEST/base";
        let err = validate_control_plane_base_url(bad).expect_err("userinfo");
        let msg = err.to_string();
        assert!(!msg.contains("P@ssW0rd"));
        assert!(!msg.contains("AdMiN"));
        let red = redact_control_plane_url(bad);
        assert!(!red.contains("P@ssW0rd"));
        assert!(
            !red.contains('@')
                || red.starts_with("https://example.test")
                || red == "[REDACTED]"
                || red.contains("example.test")
        );
    }

    #[test]
    fn service_socket_rejects_world_mode() {
        let mut cfg = OwnMeshConfig::default();
        cfg.service_socket.mode = Some("666".into());
        let err = cfg.validate().expect_err("0666 refused");
        assert!(
            err.to_string().contains("other") || err.to_string().contains("mode"),
            "{err}"
        );
    }

    #[test]
    fn service_socket_accepts_owner_group_mode() {
        let mut cfg = OwnMeshConfig::default();
        cfg.service_socket.owner = Some("1000".into());
        cfg.service_socket.group = Some("1000".into());
        cfg.service_socket.mode = Some("660".into());
        cfg.service_socket.allowed_uids = vec![1000, 1001];
        cfg.validate().unwrap();
        assert_eq!(cfg.service_socket.mode_bits(), 0o660);
        assert_eq!(cfg.service_socket.owner_uid(), Some(1000));
    }
}
