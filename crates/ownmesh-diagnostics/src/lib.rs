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
use thiserror::Error;

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Op-journal hard caps mirrored from ownmeshd (doctor must not depend on the
/// daemon crate). Completed receipts are compacted and evicted at 30 days.
const OP_JOURNAL_MAX_ENTRIES: usize = 4_096;
const OP_JOURNAL_MAX_BYTES: usize = 4 * 1024 * 1024;

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

/// Non-secret credential-store provenance persisted by the runtime for doctor.
#[derive(Debug, Clone, Default)]
pub struct CredentialStoreObservation {
    pub metadata_present: bool,
    pub backend_name: Option<String>,
    pub fallback_policy: Option<String>,
    pub degraded: bool,
    pub residual_fallback_entries: usize,
    pub read_error: Option<String>,
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
    /// Effective service hardening disclosure (Linux systemd --user units).
    pub hardening: Option<ServiceHardeningObservation>,
}

/// Effective hardening of an installed systemd --user unit as observed
/// read-only from the unit file plus drop-ins (values only, never content).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools)] // serializable DTO: one bool per directive
pub struct ServiceHardeningObservation {
    pub no_new_privileges: bool,
    /// Per-user-safe baseline directives from the shipped unit (P1-E).
    pub umask_set: bool,
    pub restrict_suidsgid: bool,
    pub restrict_realtime: bool,
    pub lock_personality: bool,
    /// Seccomp guards from the shipped baseline unit (P1-E): available in
    /// user services without a user namespace.
    pub system_call_architectures: bool,
    pub restrict_namespaces: bool,
    pub capability_bounding_set: bool,
    /// Any directive that forces a user namespace in a per-user service
    /// (`PrivateUsers=yes` or the filesystem namespacing directives
    /// `ProtectSystem=`/`ProtectHome=`/`ReadWritePaths=`/`PrivateTmp=`/
    /// `ProtectKernelTunables=`/`ProtectControlGroups=`/`ProtectHostname=`/…).
    /// Inside the namespace every host uid outside the mapping — host root
    /// and every other host user alike — appears as the overflow uid 65534,
    /// so OwnMesh custody validation cannot verify real ownership and the
    /// daemon fails to start with `ancestor is owned by untrusted uid 65534`
    /// (v1.2.13 review, ADR 0011). Disclosed as start-breaking, never
    /// counted as baseline.
    pub user_namespace_forcing: bool,
    pub read_only_hierarchy: bool,
    /// `PrivateUsers=yes` present (forces the user namespace; see
    /// [`ServiceHardeningObservation::user_namespace_forcing`]).
    pub private_users: bool,
    pub protect_system_full: bool,
    pub private_tmp: bool,
    pub protect_proc: bool,
    /// `ProtectKernelTunables=yes` present (forces the user namespace).
    pub protect_kernel_tunables: bool,
    /// `ProtectControlGroups=yes|private|strict` present (forces the user
    /// namespace).
    pub protect_control_groups: bool,
    /// `ProtectHostname=yes` present (forces the user namespace).
    pub protect_hostname: bool,
    /// `ReadWritePaths=` present with a non-empty list (forces the user
    /// namespace).
    pub read_write_paths_set: bool,
    /// Start-breaking --user directives (CapabilityBoundingSet=/ProtectClock=/
    /// ProtectKernelLogs=/ProtectKernelModules=; 218/CAPABILITIES on v259).
    pub start_breaking_directives: bool,
    /// The unit file is masked (empty or symlink to /dev/null).
    pub masked: bool,
    pub summary: String,
}

/// Read-only observation of durable daemon journals (P0-A/P0-B). Only counts
/// and sizes are surfaced — never entry content or result bodies.
#[derive(Debug, Clone, Default)]
pub struct JournalsObservation {
    /// Pending transition-journal records (any phase), from the journal file.
    pub transition_pending: usize,
    /// Pending records whose host TTL has expired (poison-pill class).
    pub transition_expired: usize,
    pub transition_read_error: Option<String>,
    /// Op-journal entries and in-progress (uncertain) markers.
    pub op_journal_entries: usize,
    pub op_journal_in_progress: usize,
    /// Entries the runtime refuses to replay/compact/evict (unknown
    /// forward-version state, malformed state values, or non-object entries).
    /// Fail-closed state that must never be reported healthy (P1-F).
    pub op_journal_uncertain: usize,
    /// Durable op-journal file size in bytes (already compacted post-fix).
    pub op_journal_durable_bytes: usize,
    /// Stale `op-journal.json.bak` size in bytes, when present. The backup is
    /// created by the shared atomic writer *before* the replace, so a crash or
    /// a failed cleanup can leave the pre-compaction file (with full result
    /// bodies) behind even though the primary journal is compacted; doctor
    /// surfaces it so the class is not reported healthy (P0-B). `None` when
    /// no backup file exists.
    pub op_journal_backup_bytes: Option<usize>,
    pub op_journal_read_error: Option<String>,
}

/// Read-only observation of official-profile discovery (P1-D/P1-F): runs the
/// deterministic search (system PATH + user-local dirs) and compares it with
/// the bare system PATH. Never spawns version probes — observation must not
/// run binaries.
#[derive(Debug, Clone, Default)]
pub struct ProfileDiscoveryObservation {
    /// Official profiles that resolve only through user-local search dirs,
    /// i.e. a login shell would find them but a systemd user service with a
    /// system-only PATH would report them not-installed.
    pub user_local_only: Vec<String>,
    /// User-local bin dirs that exist on disk but are absent from PATH
    /// (would report installed CLIs as not-installed).
    pub existing_dirs_not_searched: Vec<String>,
    /// `HOME` is unset, so the deterministic user-local search could not be
    /// evaluated at all. This is a discovery-health issue, not a healthy
    /// result: installed user CLIs may be reported not-installed.
    pub home_unavailable: bool,
}

/// Full set of doctor inputs gathered by the CLI (read-only observations).
#[derive(Debug, Clone, Default)]
pub struct DoctorInput {
    pub binary: BinaryObservation,
    pub config: ConfigObservation,
    pub credentials: CredentialObservation,
    pub credential_store: CredentialStoreObservation,
    pub daemon: DaemonObservation,
    pub control_plane: ControlPlaneObservation,
    pub privacy_policy: PrivacyPolicyObservation,
    pub service: ServiceObservation,
    pub journals: JournalsObservation,
    pub profile_discovery: ProfileDiscoveryObservation,
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

    // Store provenance is non-secret metadata only. Missing/unreadable metadata
    // is a warning rather than a fabricated claim about OS-keychain health.
    let store_check = if let Some(error) = &input.credential_store.read_error {
        DoctorCheck::warn(
            "credential.store",
            "credential-store provenance metadata is unreadable",
        )
        .with_detail(error.clone())
    } else if !input.credential_store.metadata_present {
        DoctorCheck::warn(
            "credential.store",
            "credential-store provenance has not been observed yet",
        )
    } else if input.credential_store.degraded
        || input.credential_store.residual_fallback_entries > 0
        || input
            .credential_store
            .backend_name
            .as_deref()
            .is_some_and(|backend| backend.contains("encrypted-file"))
    {
        DoctorCheck::warn(
            "credential.store",
            format!(
                "credential store is using/dependent on fallback storage (backend={}, residual_fallback_entries={})",
                input
                    .credential_store
                    .backend_name
                    .as_deref()
                    .unwrap_or("unknown"),
                input.credential_store.residual_fallback_entries,
            ),
        )
    } else {
        DoctorCheck::pass(
            "credential.store",
            format!(
                "credential store backend {}",
                input
                    .credential_store
                    .backend_name
                    .as_deref()
                    .unwrap_or("unknown"),
            ),
        )
    };
    checks.push(store_check);
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

    // Effective service hardening (P1-E / v1.2.13 review): local overrides
    // that disable the meaningful guards, force a user namespace (which
    // hides real uids and makes custody validation unsound), re-introduce
    // unexpected filesystem/visibility directives, or add a start-breaking
    // directive must be disclosed instead of claiming an unmodified
    // baseline. A masked unit is disclosed first: the daemon is not running
    // under the shipped unit at all.
    if let Some(h) = &input.service.hardening {
        if h.masked {
            checks.push(DoctorCheck::warn(
                "service.hardening",
                "the systemd user unit is masked (empty file or symlink to /dev/null, systemd.unit(5)); \
the daemon is not running under the shipped unit — remove the mask and re-run `ownmesh service install`",
            ));
        } else if h.start_breaking_directives {
            checks.push(DoctorCheck::warn(
                "service.hardening",
                "effective unit sets a directive an unprivileged --user service cannot apply \
(CapabilityBoundingSet=/ProtectClock=/ProtectKernelLogs=/ProtectKernelModules=; startup fails \
with status 218/CAPABILITIES on systemd v259 even under PrivateUsers=yes); re-run `ownmesh \
service install` to restore the supported unit",
            ));
        } else if h.user_namespace_forcing {
            checks.push(DoctorCheck::warn(
                "service.hardening",
                "effective unit forces a user namespace (PrivateUsers=yes or the filesystem \
namespacing directives ProtectSystem/ProtectHome/ReadWritePaths/PrivateTmp/\
ProtectKernelTunables/ProtectControlGroups/ProtectHostname/...); inside it every host uid \
outside the namespace — host root and every other host user alike — appears as the overflow \
uid 65534, so OwnMesh custody validation cannot verify real ownership and the daemon fails to \
start with `ancestor is owned by untrusted uid 65534`; re-run `ownmesh service install` to \
remove OwnMesh-generated leftovers (operator drop-ins that still force a user namespace must \
be deleted by hand)",
            ));
        } else if !h.no_new_privileges
            || !h.umask_set
            || !h.restrict_suidsgid
            || !h.restrict_realtime
            || !h.lock_personality
            || !h.system_call_architectures
            || !h.restrict_namespaces
            || !h.protect_proc
        {
            checks.push(DoctorCheck::warn(
                "service.hardening",
                "a local override weakened the shipped hardening (NoNewPrivileges/UMask/\
RestrictSUIDSGID/RestrictRealtime/LockPersonality/SystemCallArchitectures/RestrictNamespaces/\
ProtectProc=invisible); re-run `ownmesh service install` to restore the supported unit",
            ));
        } else if h.capability_bounding_set {
            checks.push(DoctorCheck::warn(
                "service.hardening",
                "effective unit sets CapabilityBoundingSet=, which an unprivileged --user service cannot apply (startup fails with status 218/CAPABILITIES); re-run `ownmesh service install` to restore the supported unit",
            ));
        } else if h.read_only_hierarchy {
            checks.push(DoctorCheck::warn(
                "service.hardening",
                "effective unit hardening makes parts of the user/workspace hierarchy read-only; this can conflict with registered workspaces",
            ));
        } else {
            checks.push(DoctorCheck::pass(
                "service.hardening",
                "effective unit hardening baseline applied",
            ));
        }
    }

    // Durable journals (P0-A/P0-B): a pending/expired transition record or
    // dangerous op-journal pressure must never coexist with an unconditional
    // healthy result. Only counts/sizes are reported — never entry content.
    if let Some(error) = &input.journals.transition_read_error {
        checks.push(DoctorCheck::warn(
            "journals.transition",
            format!("transition journal unreadable: {error}"),
        ));
    } else if input.journals.transition_expired > 0 {
        checks.push(DoctorCheck::fail(
            "journals.transition",
            format!(
                "{} expired sidecar transition record(s) pending; sessions may fail closed until reconciled",
                input.journals.transition_expired
            ),
        ));
    } else if input.journals.transition_pending > 0 {
        checks.push(DoctorCheck::warn(
            "journals.transition",
            format!(
                "{} pending sidecar transition record(s) (none expired)",
                input.journals.transition_pending
            ),
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "journals.transition",
            "no pending sidecar transition records",
        ));
    }

    let op_at_capacity = input.journals.op_journal_entries >= OP_JOURNAL_MAX_ENTRIES
        || input.journals.op_journal_durable_bytes >= OP_JOURNAL_MAX_BYTES;
    let op_warn_entries = (OP_JOURNAL_MAX_ENTRIES as u64 * 6) / 10;
    let op_warn_bytes = (OP_JOURNAL_MAX_BYTES as u64 * 6) / 10;
    let op_warn = input.journals.op_journal_entries as u64 >= op_warn_entries
        || input.journals.op_journal_durable_bytes as u64 >= op_warn_bytes;
    let op_pressure = if op_at_capacity {
        Some("critical")
    } else if op_warn {
        Some("warn")
    } else {
        None
    };
    if let Some(error) = &input.journals.op_journal_read_error {
        checks.push(DoctorCheck::fail(
            "journals.op_journal",
            format!(
                "op journal unreadable: {error}; daemon starts read-only. Repair locally with `ownmesh doctor --repair-journal --i-understand-replay-risk`"
            ),
        ));
    } else if let Some(bak_bytes) = input.journals.op_journal_backup_bytes {
        // P0-B: the shared atomic writer copies the previous file to
        // `op-journal.json.bak` *before* the replace, so a crash or a failed
        // cleanup can leave the pre-compaction journal (with full result
        // bodies) behind even though the primary journal is compacted. While
        // it exists, doctor surfaces it instead of reporting the journal
        // healthy; the daemon removes the stale backup on the next
        // load/persist (and the v1.2.13 writer no longer creates one).
        checks.push(DoctorCheck::warn(
            "journals.op_journal",
            format!(
                "stale op-journal backup present (op-journal.json.bak, {bak_bytes} bytes); it may \
hold pre-compaction result bodies — restarting ownmeshd removes it, or delete it manually",
            ),
        ));
    } else if input.journals.op_journal_uncertain > 0 {
        // P1-F: entries the runtime refuses to replay/compact/evict (unknown
        // forward-version state, malformed state values, or non-object
        // entries) are fail-closed state; reporting the journal as okay would
        // hide an uncertain outcome behind a healthy result.
        checks.push(DoctorCheck::warn(
            "journals.op_journal",
            format!(
                "{} uncertain op-journal entr{} (unknown/forward-version or malformed state) that the \
runtime refuses to replay, compact, or evict; run `ownmesh doctor` after checking the journal",
                input.journals.op_journal_uncertain,
                if input.journals.op_journal_uncertain == 1 { "y" } else { "ies" },
            ),
        ));
    } else if let Some(pressure) = op_pressure {
        let hint = if pressure == "critical" {
            "new side-effect operations will be refused until completed receipts age out (eviction at capacity, 30d+)"
        } else {
            "op journal approaching capacity; old completed receipts are evicted only at capacity (30d+)"
        };
        checks.push(DoctorCheck::warn(
            "journals.op_journal",
            format!(
                "op journal pressure {pressure} ({} entries, {} durable bytes; {hint})",
                input.journals.op_journal_entries, input.journals.op_journal_durable_bytes
            ),
        ));
    } else if input.journals.op_journal_in_progress > 0 {
        // P0-B review: a durable `in_progress` marker is permanently
        // non-replayable (the runtime refuses to replay, compact, or evict
        // it), so an operation that crashed or failed after reserving its key
        // can never be retried. Reporting the journal as a plain pass hid
        // that stuck outcome behind a healthy result; surface it with an
        // actionable note instead. An operation genuinely in flight while
        // doctor runs is the same durable shape, so the message says so.
        checks.push(DoctorCheck::warn(
            "journals.op_journal",
            format!(
                "{} durable in-progress op-journal marker(s) present; the referenced operation \
outcome is uncertain and its key is permanently non-replayable until reconciled (an operation \
truly in flight while doctor runs is expected to show this briefly) — run `ownmesh doctor` \
after the operation finishes or reconcile the marker manually",
                input.journals.op_journal_in_progress
            ),
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "journals.op_journal",
            format!(
                "op journal ok ({} entries, {} durable bytes, {} in-progress)",
                input.journals.op_journal_entries,
                input.journals.op_journal_durable_bytes,
                input.journals.op_journal_in_progress
            ),
        ));
    }

    // Official-profile discovery (P1-D/P1-F): installed CLIs that only
    // resolve through user-local dirs (or dirs that exist but are not
    // searched) must be surfaced instead of an unconditional healthy result.
    // A missing `HOME` means the user-local search could not be evaluated at
    // all — that is a discovery-health issue, not a healthy result.
    let discovery_warned = !input.profile_discovery.user_local_only.is_empty()
        || !input
            .profile_discovery
            .existing_dirs_not_searched
            .is_empty()
        || input.profile_discovery.home_unavailable;
    if discovery_warned {
        let mut detail = String::new();
        if input.profile_discovery.home_unavailable {
            detail.push_str(
                "HOME is unset, so the deterministic user-local CLI search could not be evaluated; \
installed user CLIs may be reported not-installed",
            );
        }
        if !input.profile_discovery.user_local_only.is_empty() {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str("official profile(s) resolve only through user-local search dirs, not the service PATH: ");
            detail.push_str(&input.profile_discovery.user_local_only.join(", "));
        }
        if !input
            .profile_discovery
            .existing_dirs_not_searched
            .is_empty()
        {
            if !detail.is_empty() {
                detail.push_str("; ");
            }
            detail.push_str("user-local bin dir(s) exist but are not searched: ");
            detail.push_str(
                &input
                    .profile_discovery
                    .existing_dirs_not_searched
                    .join(", "),
            );
        }
        checks.push(DoctorCheck::warn(
            "profiles.discovery",
            format!(
                "official profile discovery mismatch — {detail}; a login shell finds these, a \
daemon service with the bare system PATH reports them not-installed"
            ),
        ));
    } else {
        checks.push(DoctorCheck::pass(
            "profiles.discovery",
            "official profile discovery consistent with service PATH",
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

/// Versioned, allowlisted support-bundle schema. No raw file/text section map
/// exists in the production API: every exported field is explicitly reviewed.
pub const SUPPORT_BUNDLE_SCHEMA_VERSION: u32 = 2;
const SUPPORT_MAX_TEXT_BYTES: usize = 2 * 1024;
const SUPPORT_MAX_DOCTOR_CHECKS: usize = 128;
const SUPPORT_MAX_EVENTS: usize = 64;
const SUPPORT_MAX_SERIALIZED_BYTES: usize = 512 * 1024;
const SUPPORT_HIGH_ENTROPY_MIN_BYTES: usize = 48;
const SUPPORT_HIGH_ENTROPY_MIN_DISTINCT: usize = 20;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPlatformFacts {
    pub os: String,
    pub arch: String,
    pub ownmesh_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicServiceFacts {
    pub platform: String,
    pub supported: bool,
    pub installed: bool,
    pub running: Option<bool>,
    pub hardening_summary: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PublicJournalHealth {
    pub transition_pending: usize,
    pub transition_expired: usize,
    pub op_journal_entries: usize,
    pub op_journal_in_progress: usize,
    pub op_journal_uncertain: usize,
    pub op_journal_durable_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDiagnosticEvent {
    pub kind: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupportBundleV2 {
    pub schema_version: u32,
    pub created_unix: i64,
    pub doctor: DoctorReport,
    pub platform: PublicPlatformFacts,
    pub service: PublicServiceFacts,
    pub journal_health: PublicJournalHealth,
    pub recent_events: Vec<PublicDiagnosticEvent>,
}

/// Explicit input for support export. Secret-bearing internal structs cannot be
/// inserted here; callers must select reviewed public fields individually.
#[derive(Debug, Clone)]
pub struct SupportBundleInput {
    pub doctor: DoctorReport,
    pub platform: PublicPlatformFacts,
    pub service: PublicServiceFacts,
    pub journal_health: PublicJournalHealth,
    pub recent_events: Vec<PublicDiagnosticEvent>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SupportBundleError {
    #[error("support bundle field exceeds limit: {0}")]
    FieldTooLarge(String),
    #[error("support bundle collection exceeds limit: {0}")]
    CollectionTooLarge(String),
    #[error("support bundle secret scanner rejected section: {0}")]
    SuspiciousContent(String),
    #[error("support bundle serialization failed")]
    Serialization,
    #[error("support bundle owner-only write failed")]
    Write,
}

/// Immutable preview/export payload. Preview metadata and file export both use
/// these exact serialized bytes; no source is re-gathered after preview.
#[derive(Debug, Clone)]
pub struct PreparedSupportBundle {
    bytes: Vec<u8>,
    sha256_hex: String,
}

impl PreparedSupportBundle {
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub fn sha256_hex(&self) -> &str {
        &self.sha256_hex
    }

    #[must_use]
    pub fn size(&self) -> usize {
        self.bytes.len()
    }

    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        SUPPORT_BUNDLE_SCHEMA_VERSION
    }

    #[must_use]
    pub fn included_sections(&self) -> [&'static str; 5] {
        ["doctor", "platform", "service", "journal_health", "recent_events"]
    }
}

/// Build and freeze the exact bytes shown in preview and later exported.
pub fn prepare_support_bundle(
    input: SupportBundleInput,
    created_unix: i64,
) -> Result<PreparedSupportBundle, SupportBundleError> {
    validate_support_input(&input)?;
    let bundle = SupportBundleV2 {
        schema_version: SUPPORT_BUNDLE_SCHEMA_VERSION,
        created_unix,
        doctor: input.doctor,
        platform: input.platform,
        service: input.service,
        journal_health: input.journal_health,
        recent_events: input.recent_events,
    };

    scan_serializable_section("doctor", &bundle.doctor)?;
    scan_serializable_section("platform", &bundle.platform)?;
    scan_serializable_section("service", &bundle.service)?;
    scan_serializable_section("journal_health", &bundle.journal_health)?;
    scan_serializable_section("recent_events", &bundle.recent_events)?;

    let bytes = serde_json::to_vec_pretty(&bundle).map_err(|_| SupportBundleError::Serialization)?;
    if bytes.len() > SUPPORT_MAX_SERIALIZED_BYTES {
        return Err(SupportBundleError::CollectionTooLarge(
            "serialized_bundle".into(),
        ));
    }
    let sha256_hex = support_sha256_hex(&bytes);
    Ok(PreparedSupportBundle { bytes, sha256_hex })
}

/// Atomically export the already-previewed bytes with owner-only file custody.
/// This performs no network activity and does not re-read any diagnostic source.
pub fn write_prepared_support_bundle(
    path: &std::path::Path,
    prepared: &PreparedSupportBundle,
) -> Result<(), SupportBundleError> {
    ownmesh_ipc::atomic_write_owner_only(path, prepared.bytes())
        .map_err(|_| SupportBundleError::Write)
}

fn validate_support_input(input: &SupportBundleInput) -> Result<(), SupportBundleError> {
    if input.doctor.checks.len() > SUPPORT_MAX_DOCTOR_CHECKS {
        return Err(SupportBundleError::CollectionTooLarge("doctor.checks".into()));
    }
    if input.recent_events.len() > SUPPORT_MAX_EVENTS {
        return Err(SupportBundleError::CollectionTooLarge("recent_events".into()));
    }
    check_support_text("doctor.version", &input.doctor.version)?;
    for check in &input.doctor.checks {
        check_support_text("doctor.check.id", &check.id)?;
        check_support_text("doctor.check.message", &check.message)?;
        if let Some(detail) = &check.detail {
            check_support_text("doctor.check.detail", detail)?;
        }
    }
    check_support_text("platform.os", &input.platform.os)?;
    check_support_text("platform.arch", &input.platform.arch)?;
    check_support_text("platform.ownmesh_version", &input.platform.ownmesh_version)?;
    check_support_text("service.platform", &input.service.platform)?;
    if let Some(summary) = &input.service.hardening_summary {
        check_support_text("service.hardening_summary", summary)?;
    }
    for event in &input.recent_events {
        check_support_text("recent_events.kind", &event.kind)?;
        check_support_text("recent_events.message", &event.message)?;
    }
    Ok(())
}

fn check_support_text(field: &str, text: &str) -> Result<(), SupportBundleError> {
    if text.len() > SUPPORT_MAX_TEXT_BYTES {
        return Err(SupportBundleError::FieldTooLarge(field.into()));
    }
    Ok(())
}

fn scan_serializable_section<T: Serialize>(
    section: &str,
    value: &T,
) -> Result<(), SupportBundleError> {
    let bytes = serde_json::to_vec(value).map_err(|_| SupportBundleError::Serialization)?;
    let text = String::from_utf8_lossy(&bytes);
    if contains_suspicious_support_content(&text) {
        return Err(SupportBundleError::SuspiciousContent(section.into()));
    }
    Ok(())
}

fn contains_suspicious_support_content(text: &str) -> bool {
    let normalized = normalize_support_scan_text(text);
    let whitespace_normalized = normalized
        .replace("\\n", " ")
        .replace("\\r", " ")
        .replace("\\t", " ");
    if contains_suspicious_support_content_normalized(&whitespace_normalized) {
        return true;
    }
    let percent_decoded = percent_decode_ascii(&whitespace_normalized);
    if percent_decoded != whitespace_normalized
        && contains_suspicious_support_content_normalized(&percent_decoded)
    {
        return true;
    }

    // JSON serialization represents embedded line breaks as `\\n`. A secret
    // split only to evade line-oriented scanners must still be treated as one
    // candidate. Keep punctuation intact so ordinary prose is not joined into
    // a synthetic high-entropy token.
    let compact_escapes = normalized
        .replace("\\n", "")
        .replace("\\r", "")
        .replace("\\t", "");
    if compact_escapes != normalized
        && contains_suspicious_support_content_normalized(&compact_escapes)
    {
        return true;
    }
    let compact_percent_decoded = percent_decode_ascii(&compact_escapes);
    compact_percent_decoded != compact_escapes
        && contains_suspicious_support_content_normalized(&compact_percent_decoded)
}

fn contains_suspicious_support_content_normalized(text: &str) -> bool {
    if [
        "-----begin private key",
        "-----begin rsa private key",
        "-----begin ec private key",
        "-----begin openssh private key",
    ]
    .iter()
    .any(|needle| text.contains(needle))
    {
        return true;
    }

    if has_labeled_secret(text, "authorization", true)
        || has_labeled_secret(text, "cookie", false)
        || has_labeled_secret(text, "set-cookie", false)
        || [
            "access_token",
            "refresh_token",
            "device_code",
            "client_assertion",
            "client_secret",
            "api_key",
            "password",
            "private_key",
            "code_verifier",
        ]
        .iter()
        .any(|label| has_labeled_secret(text, label, false))
    {
        return true;
    }

    // Reject JWT-like three-segment bearer material without copying it into an
    // error. Ordinary dotted versions/hostnames do not meet these bounds.
    for token in text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | ',' | ';' | '(' | ')' | '[' | ']' | '{' | '}'
            )
    }) {
        let token = token.trim_matches(|character: char| matches!(character, ':' | '='));
        let segments: Vec<&str> = token.split('.').collect();
        if segments.len() == 3
            && segments.iter().all(|segment| {
                segment.len() >= 8
                    && segment
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            })
        {
            return true;
        }
        if looks_like_high_entropy_secret(token) {
            return true;
        }
    }
    false
}

fn normalize_support_scan_text(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    for character in text.chars() {
        let folded = match character {
            '\u{3000}' => ' ',
            '\u{ff01}'..='\u{ff5e}' => char::from_u32(u32::from(character) - 0xfee0)
                .unwrap_or(character),
            _ => character,
        };
        for lowercase in folded.to_lowercase() {
            normalized.push(lowercase);
        }
    }
    normalized
}

fn percent_decode_ascii(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let high = hex_nibble(bytes[index + 1]);
            let low = hex_nibble(bytes[index + 2]);
            if let (Some(high), Some(low)) = (high, low) {
                output.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        output.push(bytes[index]);
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn has_labeled_secret(text: &str, label: &str, require_bearer: bool) -> bool {
    let mut remainder = text;
    while let Some(offset) = remainder.find(label) {
        let after_label = &remainder[offset + label.len()..];
        let structural = after_label.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, '\\' | '"' | '\'')
        });
        let Some(value) = structural
            .strip_prefix(':')
            .or_else(|| structural.strip_prefix('='))
        else {
            remainder = after_label;
            continue;
        };
        let value = value.trim_start_matches(|character: char| {
            character.is_whitespace() || matches!(character, '\\' | '"' | '\'' | ':' | '=')
        });
        if require_bearer {
            if let Some(after_bearer) = value.strip_prefix("bearer") {
                let bearer_value = after_bearer.trim_start_matches(|character: char| {
                    character.is_whitespace()
                        || matches!(character, '\\' | '"' | '\'' | ':' | '=')
                });
                if has_nonempty_secret_value(bearer_value) {
                    return true;
                }
            }
        } else if has_nonempty_secret_value(value) {
            return true;
        }
        remainder = after_label;
    }
    false
}

fn has_nonempty_secret_value(value: &str) -> bool {
    value
        .chars()
        .next()
        .is_some_and(|character| !matches!(character, ',' | '}' | ']' | ')' | ';'))
}

fn looks_like_high_entropy_secret(token: &str) -> bool {
    let token = token.trim_matches(|character: char| {
        matches!(character, '[' | ']' | '{' | '}' | ':' | '=')
    });
    if token.len() < SUPPORT_HIGH_ENTROPY_MIN_BYTES || token.len() > SUPPORT_MAX_TEXT_BYTES {
        return false;
    }
    if token.starts_with("http://")
        || token.starts_with("https://")
        || token.starts_with('/')
        || token.starts_with("./")
        || token.starts_with("../")
        || token.contains("\\\\")
    {
        return false;
    }
    if !token.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'+' | b'/' | b'=')
    }) {
        return false;
    }

    let mut distinct = [false; 128];
    let mut distinct_count = 0;
    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    for byte in token.bytes() {
        if byte.is_ascii_lowercase() {
            has_lower = true;
        } else if byte.is_ascii_uppercase() {
            has_upper = true;
        } else if byte.is_ascii_digit() {
            has_digit = true;
        } else {
            has_symbol = true;
        }
        let index = usize::from(byte);
        if !distinct[index] {
            distinct[index] = true;
            distinct_count += 1;
        }
    }
    let categories = usize::from(has_lower)
        + usize::from(has_upper)
        + usize::from(has_digit)
        + usize::from(has_symbol);
    distinct_count >= SUPPORT_HIGH_ENTROPY_MIN_DISTINCT && categories >= 3
}

fn support_sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
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

    /// P0-A/P0-B: run_doctor must surface poisoned transition-journal and
    /// op-journal pressure state instead of an unconditional healthy result.
    #[test]
    fn doctor_surfaces_journal_health() {
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();

        // Healthy journals → pass rows.
        let report = run_doctor(&input);
        let transition = report
            .checks
            .iter()
            .find(|c| c.id == "journals.transition")
            .unwrap();
        assert_eq!(transition.status, CheckStatus::Pass, "{report:?}");
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .unwrap();
        assert_eq!(op.status, CheckStatus::Pass, "{report:?}");

        // Expired transition record → fail.
        input.journals.transition_pending = 2;
        input.journals.transition_expired = 1;
        let report = run_doctor(&input);
        let transition = report
            .checks
            .iter()
            .find(|c| c.id == "journals.transition")
            .unwrap();
        assert_eq!(transition.status, CheckStatus::Fail, "{report:?}");
        assert!(!report.ok);

        // Critical op-journal pressure → warn with actionable hint.
        input.journals.transition_pending = 0;
        input.journals.transition_expired = 0;
        input.journals.op_journal_entries = OP_JOURNAL_MAX_ENTRIES;
        input.journals.op_journal_durable_bytes = OP_JOURNAL_MAX_BYTES;
        let report = run_doctor(&input);
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .unwrap();
        assert_eq!(op.status, CheckStatus::Warn, "{report:?}");
        assert!(op.message.contains("pressure"));
        assert!(op.message.contains("30d"), "{}", op.message);

        // P1-F: uncertain entries (unknown/forward-version state, malformed
        // state values, or non-object entries) must be surfaced, never
        // reported as an okay journal — even far below capacity.
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();
        input.journals.op_journal_entries = 1;
        input.journals.op_journal_uncertain = 1;
        let report = run_doctor(&input);
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .unwrap();
        assert_eq!(op.status, CheckStatus::Warn, "{report:?}");
        assert!(
            op.message.contains("uncertain"),
            "uncertain entries must be surfaced: {}",
            op.message
        );
        assert_eq!(report.outcome, DoctorOutcome::Warn, "{report:?}");

        let mut unreadable = DoctorInput::default();
        unreadable.binary.cli_version = "1.2.13".into();
        unreadable.journals.op_journal_read_error = Some("corrupt primary".into());
        let report = run_doctor(&unreadable);
        let op = report
            .checks
            .iter()
            .find(|c| c.id == "journals.op_journal")
            .unwrap();
        assert_eq!(op.status, CheckStatus::Fail, "{report:?}");
        assert!(op.message.contains("read-only"), "{}", op.message);
        assert!(op.message.contains("--repair-journal"), "{}", op.message);
        assert_eq!(report.outcome, DoctorOutcome::Error, "{report:?}");
    }

    /// P1-D/P1-F: run_doctor must surface user-local-only official profiles
    /// and existing-but-unsearched user bin dirs instead of an unconditional
    /// healthy result.
    #[test]
    fn doctor_surfaces_profile_discovery_mismatch() {
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "profiles.discovery")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Pass, "{report:?}");

        input.profile_discovery = ProfileDiscoveryObservation {
            user_local_only: vec!["codex".into(), "pi".into()],
            existing_dirs_not_searched: vec!["~/.local/bin".into()],
            home_unavailable: false,
        };
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "profiles.discovery")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(check.message.contains("codex"));
        assert!(check.message.contains("pi"));
        assert!(check.message.contains("~/.local/bin"));
        assert!(check.message.contains("not-installed"));

        // The serialized report must stay redacted (profile ids are fixed
        // official ids — no user data or tokens).
        let json = serde_json::to_string(&report).unwrap();
        assert!(appears_redacted(&json));
    }

    /// P1-F: a missing `HOME` must surface as a profile-discovery health
    /// issue instead of silently producing a healthy observation.
    #[test]
    fn doctor_surfaces_missing_home_in_profile_discovery() {
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();
        input.profile_discovery.home_unavailable = true;
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "profiles.discovery")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(
            check.message.contains("HOME is unset"),
            "actionable message expected: {check:?}"
        );
        assert_eq!(report.outcome, DoctorOutcome::Warn, "{report:?}");
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

    /// P1-E / v1.2.13 review: doctor must disclose effective service
    /// hardening, including degraded local overrides and user-namespace-
    /// forcing directives, instead of claiming an unmodified baseline.
    #[test]
    fn doctor_discloses_degraded_service_hardening() {
        let mut input = DoctorInput::default();
        input.binary.cli_version = "1.2.13".into();
        input.service.platform = "linux".into();
        input.service.supported = true;
        input.service.installed = true;

        // Baseline: pass (no start-breaking or degraded directives). The
        // v1.2.13 baseline does NOT force a user namespace (ADR 0011).
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: true,
            umask_set: true,
            restrict_suidsgid: true,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: false,
            user_namespace_forcing: false,
            read_only_hierarchy: false,
            private_users: false,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: true,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: false,
            masked: false,
            summary: "baseline".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .expect("hardening check row");
        assert_eq!(check.status, CheckStatus::Pass, "{report:?}");

        // The shipped baseline omits `CapabilityBoundingSet=` by design
        // (systemd.exec(5): an unset option leaves the bounding set
        // unmodified, and an unprivileged --user service cannot apply any
        // value — startup fails with status 218/CAPABILITIES). Doctor must
        // NOT warn on the clean shipped unit.
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: true,
            umask_set: true,
            restrict_suidsgid: true,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: false,
            user_namespace_forcing: false,
            read_only_hierarchy: false,
            private_users: false,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: true,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: false,
            masked: false,
            summary: "shipped baseline without CapabilityBoundingSet".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .expect("hardening check row");
        assert_eq!(
            check.status,
            CheckStatus::Pass,
            "clean shipped unit must not warn: {report:?}"
        );

        // A unit that re-adds `CapabilityBoundingSet=` is start-breaking in a
        // --user service (status 218/CAPABILITIES): doctor must warn even
        // when every baseline guard is intact.
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: true,
            umask_set: true,
            restrict_suidsgid: true,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: true,
            user_namespace_forcing: false,
            read_only_hierarchy: false,
            private_users: false,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: true,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: true,
            masked: false,
            summary: "local override adds CapabilityBoundingSet=".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .expect("hardening check row");
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(
            check.message.contains("CapabilityBoundingSet="),
            "{}",
            check.message
        );

        // NoNewPrivileges disabled by a local override: warn.
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: false,
            umask_set: true,
            restrict_suidsgid: true,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: false,
            user_namespace_forcing: false,
            read_only_hierarchy: false,
            private_users: false,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: true,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: false,
            masked: false,
            summary: "disabled".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(check.message.contains("weakened"));

        // A drop-in disabling only RestrictSUIDSGID must also warn.
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: true,
            umask_set: true,
            restrict_suidsgid: false,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: false,
            user_namespace_forcing: false,
            read_only_hierarchy: false,
            private_users: false,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: true,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: false,
            masked: false,
            summary: "restrict_suidsgid disabled".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(check.message.contains("weakened"));

        // A drop-in re-adding a user-namespace-forcing directive
        // (PrivateUsers=yes) must be disclosed as start-breaking with the
        // custody consequence: inside the namespace every host uid outside
        // the mapping appears as the overflow uid 65534, so the daemon
        // fails to start (v1.2.13 review, ADR 0011).
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: true,
            umask_set: true,
            restrict_suidsgid: true,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: false,
            user_namespace_forcing: true,
            read_only_hierarchy: false,
            private_users: true,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: true,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: false,
            masked: false,
            summary: "local override adds PrivateUsers=yes".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(
            check.message.contains("user namespace"),
            "userns-forcing must be disclosed with the custody consequence: {check:?}"
        );
        assert!(
            check.message.contains("ownmesh service install"),
            "actionable remediation expected: {check:?}"
        );

        // A drop-in disabling only ProtectProc=invisible (or another
        // process-level guard) while every other baseline guard is intact
        // must also warn — a wrong value of those is part of the doctor
        // predicate.
        for (field, label) in [
            ("protect_proc", "ProtectProc=default"),
            ("umask_set", "UMask cleared"),
            ("restrict_realtime", "RestrictRealtime=no"),
            ("lock_personality", "LockPersonality=no"),
        ] {
            let mut base = ServiceHardeningObservation {
                no_new_privileges: true,
                umask_set: true,
                restrict_suidsgid: true,
                restrict_realtime: true,
                lock_personality: true,
                system_call_architectures: true,
                restrict_namespaces: true,
                capability_bounding_set: false,
                user_namespace_forcing: false,
                read_only_hierarchy: false,
                private_users: false,
                protect_system_full: false,
                private_tmp: false,
                protect_proc: true,
                protect_kernel_tunables: false,
                protect_control_groups: false,
                protect_hostname: false,
                read_write_paths_set: false,
                start_breaking_directives: false,
                masked: false,
                summary: format!("local override: {label}"),
            };
            match field {
                "protect_proc" => base.protect_proc = false,
                "umask_set" => base.umask_set = false,
                "restrict_realtime" => base.restrict_realtime = false,
                _ => base.lock_personality = false,
            }
            input.service.hardening = Some(base);
            let report = run_doctor(&input);
            let check = report
                .checks
                .iter()
                .find(|c| c.id == "service.hardening")
                .unwrap();
            assert_eq!(check.status, CheckStatus::Warn, "{field}: {report:?}");
            assert!(
                check.message.contains("weakened"),
                "{field} must warn as weakened: {check:?}"
            );
        }

        // Legacy user-namespace-forcing directives: warn with remediation.
        input.service.hardening = Some(ServiceHardeningObservation {
            no_new_privileges: true,
            umask_set: true,
            restrict_suidsgid: true,
            restrict_realtime: true,
            lock_personality: true,
            system_call_architectures: true,
            restrict_namespaces: true,
            capability_bounding_set: true,
            user_namespace_forcing: true,
            read_only_hierarchy: true,
            private_users: false,
            protect_system_full: false,
            private_tmp: false,
            protect_proc: false,
            protect_kernel_tunables: false,
            protect_control_groups: false,
            protect_hostname: false,
            read_write_paths_set: false,
            start_breaking_directives: true,
            masked: false,
            summary: "legacy unit".into(),
        });
        let report = run_doctor(&input);
        let check = report
            .checks
            .iter()
            .find(|c| c.id == "service.hardening")
            .unwrap();
        assert_eq!(check.status, CheckStatus::Warn, "{report:?}");
        assert!(
            check.message.contains("ownmesh service install"),
            "actionable remediation expected: {check:?}"
        );
    }
}
