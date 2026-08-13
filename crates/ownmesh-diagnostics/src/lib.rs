//! `OwnMesh` doctor, support bundles, and local diagnostics.
//!
//! Support bundles are previewed and redacted before any export. Nothing is
//! sent to `OwnMesh` operators unless the user explicitly exports a bundle.
//! Doctor checks are pure functions over gathered observations — network I/O
//! and filesystem access belong to the CLI layer.

#![allow(
    clippy::assigning_clones,
    clippy::doc_markdown,
    clippy::if_not_else,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::struct_excessive_bools,
    clippy::too_many_lines
)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

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

/// Diagnostics errors.
#[derive(Debug, Error)]
pub enum DiagError {
    #[error("{0}")]
    Msg(String),
}

pub type DiagResult<T> = Result<T, DiagError>;

/// Severity of a doctor check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// Healthy.
    Pass,
    /// Non-fatal issue or missing optional component.
    Warn,
    /// Blocking problem.
    Fail,
}

impl CheckStatus {
    /// Stable short label used in text and JSON.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
        }
    }

    /// Map to the public healthy/warn/error vocabulary.
    #[must_use]
    pub const fn severity_label(self) -> &'static str {
        match self {
            Self::Pass => "healthy",
            Self::Warn => "warn",
            Self::Fail => "error",
        }
    }
}

/// One doctor row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
    /// Optional structured detail that must never contain secret values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// Credential availability, when this check describes credential state.
    /// This is metadata only; no credential value is ever included.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<CredentialState>,
}

impl DoctorCheck {
    #[must_use]
    pub fn pass(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Pass,
            message: message.into(),
            detail: None,
            state: None,
        }
    }

    #[must_use]
    pub fn warn(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Warn,
            message: message.into(),
            detail: None,
            state: None,
        }
    }

    #[must_use]
    pub fn fail(id: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            status: CheckStatus::Fail,
            message: message.into(),
            detail: None,
            state: None,
        }
    }

    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn with_credential_state(mut self, state: CredentialState) -> Self {
        self.state = Some(state);
        self
    }
}

/// Overall doctor outcome for exit-code mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorOutcome {
    Healthy,
    Warn,
    Error,
}

impl DoctorOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warn => "warn",
            Self::Error => "error",
        }
    }
}

/// Full doctor report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: u32,
    pub version: String,
    pub outcome: DoctorOutcome,
    pub checks: Vec<DoctorCheck>,
    /// True when no check is `Fail` (warnings still yield `ok = true`).
    pub ok: bool,
}

impl DoctorReport {
    /// Build a report from ordered checks.
    #[must_use]
    pub fn from_checks(version: impl Into<String>, checks: Vec<DoctorCheck>) -> Self {
        let has_fail = checks.iter().any(|c| c.status == CheckStatus::Fail);
        let has_warn = checks.iter().any(|c| c.status == CheckStatus::Warn);
        let outcome = if has_fail {
            DoctorOutcome::Error
        } else if has_warn {
            DoctorOutcome::Warn
        } else {
            DoctorOutcome::Healthy
        };
        Self {
            schema_version: 1,
            version: version.into(),
            outcome,
            ok: !has_fail,
            checks,
        }
    }
}

/// Observation of binary / PATH state (values only, never secrets).
#[derive(Debug, Clone, Default)]
pub struct BinaryObservation {
    pub cli_version: String,
    pub cli_path: Option<String>,
    pub cli_on_path: bool,
    pub daemon_path: Option<String>,
    pub daemon_on_path: bool,
}

/// Config file observation (no secret material).
#[derive(Debug, Clone, Default)]
pub struct ConfigObservation {
    pub path: Option<String>,
    pub present: bool,
    pub readable: bool,
    pub parse_ok: bool,
    pub validate_ok: bool,
    pub permissions_ok: bool,
    pub message: Option<String>,
}

/// Truthful availability of a secret without reading its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialState {
    /// Non-secret metadata establishes that the credential was stored.
    Present,
    /// It is required for the configured mode and non-secret metadata establishes it is absent.
    Missing,
    /// A file/keychain-backed credential may exist, but read-only diagnostics cannot prove it.
    #[default]
    Unknown,
    /// The active local mode does not require this credential.
    NotRequiredForCurrentMode,
}

/// Credential availability metadata only — never include token/key material.
#[derive(Debug, Clone, Default)]
pub struct CredentialObservation {
    /// Compatibility presence flag for integrations that have only a positive observation.
    pub human_refresh_present: bool,
    /// Compatibility presence flag for integrations that have only a positive observation.
    pub device_key_present: bool,
    /// Compatibility presence flag for integrations that have only a positive observation.
    pub device_credential_present: bool,
    pub human_refresh_state: CredentialState,
    pub device_key_state: CredentialState,
    pub device_credential_state: CredentialState,
    pub auth_session_present: bool,
    pub enrolled_device_id_present: bool,
}

/// Daemon IPC observation.
#[derive(Debug, Clone, Default)]
pub struct DaemonObservation {
    pub endpoint: Option<String>,
    pub reachable: bool,
    /// Observed only from a successful local IPC `daemon.status` response.
    pub pid: Option<u32>,
    pub message: Option<String>,
}

/// Control-plane observation (URL may be shown; no tokens).
#[derive(Debug, Clone, Default)]
pub struct ControlPlaneObservation {
    pub configured: bool,
    pub url: Option<String>,
    /// Whether a network probe was attempted.
    pub probed: bool,
    pub reachable: Option<bool>,
    pub http_status: Option<u16>,
    pub message: Option<String>,
}

/// Policy / privacy / update defaults observation.
#[derive(Debug, Clone, Default)]
pub struct PrivacyPolicyObservation {
    pub policy_present: bool,
    pub policy_preset: Option<String>,
    pub policy_valid: bool,
    pub telemetry_project: bool,
    pub telemetry_crash_upload: bool,
    pub telemetry_usage_analytics: bool,
    pub relay_enabled: bool,
    pub update_mode: Option<String>,
    pub update_channel: Option<String>,
    pub update_network_off: bool,
}

/// User-level service observation (not privileged broker).
#[derive(Debug, Clone, Default)]
pub struct ServiceObservation {
    pub platform: String,
    pub supported: bool,
    pub installed: bool,
    pub running: Option<bool>,
    pub unit_path: Option<String>,
    pub message: Option<String>,
}

/// Full set of doctor inputs gathered by the CLI (read-only observations).
#[derive(Debug, Clone, Default)]
pub struct DoctorInput {
    pub binary: BinaryObservation,
    pub config: ConfigObservation,
    pub credentials: CredentialObservation,
    pub daemon: DaemonObservation,
    pub control_plane: ControlPlaneObservation,
    pub privacy_policy: PrivacyPolicyObservation,
    pub service: ServiceObservation,
}

/// True for built-in presets that deny `command.run` / `session.open`.
///
/// Mirrors the `ws-deny-*` / `rec-deny-*` rules in
/// `ownmesh_policy::preset_document`. Kept as a name check so diagnostics stay
/// free of a policy-engine dependency; the policy crate owns the real decision
/// and a conformance test pins the two together.
#[must_use]
pub fn preset_denies_command_execution(preset: &str) -> bool {
    matches!(
        preset
            .trim()
            .to_ascii_lowercase()
            .replace('-', "_")
            .as_str(),
        "workspace_only" | "recommended"
    )
}

/// Run structured doctor checks from gathered observations (no I/O).
#[must_use]
pub fn run_doctor(input: &DoctorInput) -> DoctorReport {
    let mut checks = Vec::new();

    // Binary / version / PATH
    if input.binary.cli_version.is_empty() {
        checks.push(DoctorCheck::fail(
            "binary.version",
            "CLI version unavailable",
        ));
    } else {
        checks.push(
            DoctorCheck::pass(
                "binary.version",
                format!("ownmesh {}", input.binary.cli_version),
            )
            .with_detail(input.binary.cli_path.clone().unwrap_or_default()),
        );
    }
    if input.binary.cli_on_path || input.binary.cli_path.is_some() {
        checks.push(DoctorCheck::pass(
            "binary.path",
            if input.binary.cli_on_path {
                "ownmesh resolvable on PATH"
            } else {
                "ownmesh path known (not necessarily on PATH)"
            },
        ));
    } else {
        checks.push(DoctorCheck::warn(
            "binary.path",
            "ownmesh path could not be resolved",
        ));
    }
    if input.binary.daemon_path.is_some() {
        checks.push(
            DoctorCheck::pass("binary.daemon", "ownmeshd executable located")
                .with_detail(input.binary.daemon_path.clone().unwrap_or_default()),
        );
    } else {
        checks.push(DoctorCheck::warn(
            "binary.daemon",
            "ownmeshd executable not found beside CLI or on PATH",
        ));
    }

    // Config parse + permissions
    if !input.config.present {
        checks.push(DoctorCheck::warn(
            "config.present",
            "config.toml not found (run `ownmesh setup`)",
        ));
    } else if !input.config.readable {
        checks.push(
            DoctorCheck::fail("config.readable", "config.toml exists but is unreadable")
                .with_detail(input.config.path.clone().unwrap_or_default()),
        );
    } else if !input.config.parse_ok {
        checks.push(
            DoctorCheck::fail(
                "config.parse",
                input
                    .config
                    .message
                    .clone()
                    .unwrap_or_else(|| "config.toml failed to parse".into()),
            )
            .with_detail(input.config.path.clone().unwrap_or_default()),
        );
    } else if !input.config.validate_ok {
        checks.push(DoctorCheck::fail(
            "config.validate",
            input
                .config
                .message
                .clone()
                .unwrap_or_else(|| "config.toml failed validation".into()),
        ));
    } else {
        checks.push(
            DoctorCheck::pass("config", "config.toml readable and valid")
                .with_detail(input.config.path.clone().unwrap_or_default()),
        );
    }
    if input.config.present {
        if input.config.permissions_ok {
            checks.push(DoctorCheck::pass(
                "config.permissions",
                "config path permissions acceptable",
            ));
        } else {
            checks.push(DoctorCheck::warn(
                "config.permissions",
                input
                    .config
                    .message
                    .clone()
                    .unwrap_or_else(|| "config path permissions look loose".into()),
            ));
        }
    }

    // Credential availability (values never appear). Do not equate the absence
    // of a file-backed fallback with absence from an OS keychain.
    checks.push(credential_check(
        "credential.human",
        observed_credential_state(
            input.credentials.human_refresh_present,
            input.credentials.human_refresh_state,
        ),
        "human refresh credential",
        Some("run `ownmesh login`"),
    ));
    checks.push(credential_check(
        "credential.device_key",
        observed_credential_state(
            input.credentials.device_key_present,
            input.credentials.device_key_state,
        ),
        "device key material",
        Some("run `ownmesh device enroll`"),
    ));
    checks.push(credential_check(
        "credential.device_connect",
        observed_credential_state(
            input.credentials.device_credential_present,
            input.credentials.device_credential_state,
        ),
        "device connect credential",
        Some("run `ownmesh device enroll`"),
    ));
    if input.credentials.enrolled_device_id_present {
        checks.push(DoctorCheck::pass(
            "enrollment",
            "local enrollment metadata present",
        ));
    } else {
        checks.push(DoctorCheck::warn(
            "enrollment",
            "no enrolled device id in local session metadata",
        ));
    }

    // Daemon IPC
    if input.daemon.reachable {
        checks.push(
            DoctorCheck::pass("daemon.ipc", "daemon reachable via local IPC")
                .with_detail(input.daemon.endpoint.clone().unwrap_or_default()),
        );
    } else {
        checks.push(
            DoctorCheck::warn(
                "daemon.ipc",
                input
                    .daemon
                    .message
                    .clone()
                    .unwrap_or_else(|| "daemon not reachable via local IPC".into()),
            )
            .with_detail(input.daemon.endpoint.clone().unwrap_or_default()),
        );
    }

    // Control plane
    if !input.control_plane.configured {
        checks.push(DoctorCheck::warn(
            "control_plane.config",
            "control plane URL not configured",
        ));
    } else {
        checks.push(
            DoctorCheck::pass("control_plane.config", "control plane URL configured")
                .with_detail(input.control_plane.url.clone().unwrap_or_default()),
        );
        if input.control_plane.probed {
            match input.control_plane.reachable {
                Some(true) => checks.push(
                    DoctorCheck::pass(
                        "control_plane.health",
                        format!(
                            "control plane /health ok{}",
                            input
                                .control_plane
                                .http_status
                                .map(|s| format!(" (HTTP {s})"))
                                .unwrap_or_default()
                        ),
                    )
                    .with_detail(input.control_plane.url.clone().unwrap_or_default()),
                ),
                // A failed opt-in probe must be observable through the process
                // exit status. The default doctor run does not probe at all.
                Some(false) => checks.push(DoctorCheck::fail(
                    "control_plane.health",
                    input
                        .control_plane
                        .message
                        .clone()
                        .unwrap_or_else(|| "control plane /health failed".into()),
                )),
                None => checks.push(DoctorCheck::warn(
                    "control_plane.health",
                    input
                        .control_plane
                        .message
                        .clone()
                        .unwrap_or_else(|| "control plane health not determined".into()),
                )),
            }
        } else {
            checks.push(DoctorCheck::pass(
                "control_plane.health",
                "network probe skipped (pass --check-network to probe /health)",
            ));
        }
    }

    // Policy
    if input.privacy_policy.policy_present && input.privacy_policy.policy_valid {
        checks.push(DoctorCheck::pass(
            "policy",
            format!(
                "policy valid (preset={})",
                input
                    .privacy_policy
                    .policy_preset
                    .as_deref()
                    .unwrap_or("unset")
            ),
        ));
    } else if input.privacy_policy.policy_present {
        checks.push(DoctorCheck::fail(
            "policy",
            "policy.toml present but invalid",
        ));
    } else {
        checks.push(DoctorCheck::warn("policy", "policy.toml not found"));
    }

    // Capability consequence of the selected preset.
    //
    // `workspace_only` and `recommended` deny command execution and interactive
    // sessions until OS process confinement exists. That is the single most
    // surprising thing about a default install — remote tools connect fine and
    // then every exec is denied — so state it in the read-only report instead of
    // leaving the user to infer it from a policy decision at call time.
    if input.privacy_policy.policy_valid {
        if let Some(preset) = input.privacy_policy.policy_preset.as_deref() {
            if preset_denies_command_execution(preset) {
                checks.push(DoctorCheck::warn(
                    "policy.command_execution",
                    format!(
                        "preset `{preset}` denies command.run and session.open \
                         (no OS process confinement yet); run \
                         `ownmesh policy preset full_user_access` to enable them"
                    ),
                ));
            } else {
                checks.push(DoctorCheck::pass(
                    "policy.command_execution",
                    format!("preset `{preset}` permits command.run and session.open"),
                ));
            }
        }
    }

    // Privacy defaults
    let telemetry_on = input.privacy_policy.telemetry_project
        || input.privacy_policy.telemetry_crash_upload
        || input.privacy_policy.telemetry_usage_analytics;
    if telemetry_on {
        checks.push(DoctorCheck::warn(
            "privacy.telemetry",
            "telemetry is enabled (user opt-in)",
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "privacy.telemetry",
            "telemetry disabled (default)",
        ));
    }
    if input.privacy_policy.relay_enabled {
        checks.push(DoctorCheck::warn(
            "privacy.relay",
            "cloud file relay enabled (user opt-in)",
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "privacy.relay",
            "cloud file relay disabled (default)",
        ));
    }
    if input.privacy_policy.update_network_off {
        checks.push(DoctorCheck::pass(
            "privacy.update",
            format!(
                "update network off (mode={})",
                input.privacy_policy.update_mode.as_deref().unwrap_or("off")
            ),
        ));
    } else {
        checks.push(DoctorCheck::warn(
            "privacy.update",
            format!(
                "update mode may use network (mode={})",
                input
                    .privacy_policy
                    .update_mode
                    .as_deref()
                    .unwrap_or("unknown")
            ),
        ));
    }

    // User-level service (not privileged broker)
    if !input.service.supported {
        checks.push(DoctorCheck::warn(
            "service.platform",
            input.service.message.clone().unwrap_or_else(|| {
                format!(
                    "user-level service management unsupported on {}",
                    input.service.platform
                )
            }),
        ));
    } else if input.service.installed {
        let running = match input.service.running {
            Some(true) => "running",
            Some(false) => "installed, not running",
            None => "installed, run-state unknown",
        };
        checks.push(
            DoctorCheck::pass("service", format!("user-level ownmeshd service {running}"))
                .with_detail(input.service.unit_path.clone().unwrap_or_default()),
        );
    } else {
        checks.push(DoctorCheck::warn(
            "service",
            input
                .service
                .message
                .clone()
                .unwrap_or_else(|| "user-level ownmeshd service not installed".into()),
        ));
    }

    DoctorReport::from_checks(
        if input.binary.cli_version.is_empty() {
            crate_version().to_string()
        } else {
            input.binary.cli_version.clone()
        },
        checks,
    )
}

fn observed_credential_state(present: bool, state: CredentialState) -> CredentialState {
    if present {
        CredentialState::Present
    } else {
        state
    }
}

fn credential_check(
    id: &str,
    state: CredentialState,
    label: &str,
    remediation: Option<&str>,
) -> DoctorCheck {
    let check = match state {
        CredentialState::Present => {
            DoctorCheck::pass(id, format!("{label} present (value redacted)"))
        }
        CredentialState::Missing => DoctorCheck::warn(
            id,
            format!(
                "{label} missing{}",
                remediation.map_or(String::new(), |hint| format!("; {hint}"))
            ),
        ),
        CredentialState::Unknown => DoctorCheck::warn(
            id,
            format!("{label} state unknown (may be managed in the OS keychain)"),
        ),
        CredentialState::NotRequiredForCurrentMode => {
            DoctorCheck::pass(id, format!("{label} not required for current mode"))
        }
    };
    check.with_credential_state(state)
}

/// Legacy thin input used by older tests — maps into [`DoctorInput`].
#[derive(Debug, Clone, Default)]
pub struct LegacyDoctorInput {
    pub config_readable: bool,
    pub daemon_reachable: bool,
    pub identity_present: bool,
    pub control_plane_url: Option<String>,
    pub telemetry_enabled: bool,
    pub relay_enabled: bool,
}

/// Compatibility wrapper around [`run_doctor`].
#[must_use]
pub fn run_doctor_legacy(input: &LegacyDoctorInput) -> DoctorReport {
    let mut full = DoctorInput::default();
    full.binary.cli_version = crate_version().to_string();
    full.binary.cli_on_path = true;
    full.config.present = input.config_readable;
    full.config.readable = input.config_readable;
    full.config.parse_ok = input.config_readable;
    full.config.validate_ok = input.config_readable;
    full.config.permissions_ok = true;
    full.credentials.device_key_present = input.identity_present;
    full.credentials.device_credential_present = input.identity_present;
    full.credentials.enrolled_device_id_present = input.identity_present;
    full.daemon.reachable = input.daemon_reachable;
    full.control_plane.configured = input.control_plane_url.is_some();
    full.control_plane.url = input.control_plane_url.clone();
    full.privacy_policy.policy_present = true;
    full.privacy_policy.policy_valid = true;
    full.privacy_policy.policy_preset = Some("recommended".into());
    full.privacy_policy.telemetry_project = input.telemetry_enabled;
    full.privacy_policy.relay_enabled = input.relay_enabled;
    full.privacy_policy.update_network_off = true;
    full.privacy_policy.update_mode = Some("off".into());
    full.service.platform = std::env::consts::OS.to_string();
    full.service.supported = true;
    run_doctor(&full)
}

/// Redact secrets from text.
#[must_use]
pub fn redact_text(input: &str) -> String {
    let mut out = input.to_string();
    for key in [
        "token",
        "refresh_token",
        "access_token",
        "client_secret",
        "authorization",
        "password",
        "secret",
        "api_key",
        "private_key",
        "bearer",
    ] {
        let mut lines = Vec::new();
        for line in out.lines() {
            let lower = line.to_ascii_lowercase();
            if lower.contains(key) {
                lines.push(format!("[REDACTED line containing {key}]"));
            } else {
                lines.push(line.to_string());
            }
        }
        out = lines.join("\n");
    }
    out
}

/// Return true when `text` appears free of secret-like payloads (for assertions).
#[must_use]
pub fn appears_redacted(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    for needle in [
        "refresh_token=",
        "access_token=",
        "client_secret=",
        "bearer ",
        "-----begin",
    ] {
        if lower.contains(needle) {
            return false;
        }
    }
    true
}

/// Support bundle (local only until user exports).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundle {
    pub created_unix: i64,
    pub doctor: DoctorReport,
    pub sections: BTreeMap<String, String>,
    pub redacted: bool,
}

/// Build a redacted support bundle preview.
#[must_use]
pub fn build_support_bundle(
    doctor: DoctorReport,
    raw_sections: BTreeMap<String, String>,
    created_unix: i64,
) -> SupportBundle {
    let mut sections = BTreeMap::new();
    for (k, v) in raw_sections {
        sections.insert(k, redact_text(&v));
    }
    SupportBundle {
        created_unix,
        doctor,
        sections,
        redacted: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_defaults_privacy() {
        let report = run_doctor_legacy(&LegacyDoctorInput {
            config_readable: true,
            daemon_reachable: true,
            identity_present: true,
            control_plane_url: Some("https://example.workers.dev".into()),
            telemetry_enabled: false,
            relay_enabled: false,
        });
        assert!(report.ok);
        assert_eq!(report.outcome, DoctorOutcome::Warn); // health skipped without probe still ok
        assert!(report
            .checks
            .iter()
            .any(|c| c.id == "privacy.telemetry" && c.status == CheckStatus::Pass));
    }

    #[test]
    fn doctor_fail_sets_error_outcome() {
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.0.0".into();
        input.config.present = true;
        input.config.readable = true;
        input.config.parse_ok = false;
        input.config.message = Some("bad toml".into());
        let report = run_doctor(&input);
        assert!(!report.ok);
        assert_eq!(report.outcome, DoctorOutcome::Error);
        assert!(report.checks.iter().any(|c| c.status == CheckStatus::Fail));
    }

    #[test]
    fn redacts_secrets() {
        let s = redact_text("access_token=abc\nhello");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("abc"));
        assert!(appears_redacted(&s));
    }

    #[test]
    fn report_never_embeds_raw_tokens_in_messages() {
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.0.0".into();
        input.credentials.human_refresh_present = true;
        input.credentials.device_credential_present = true;
        let report = run_doctor(&input);
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("redacted") || json.contains("present"));
        assert!(!json.contains("eyJ"));
        assert!(appears_redacted(&json));
    }
}
