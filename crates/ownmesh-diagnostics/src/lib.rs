//! `OwnMesh` doctor, support bundles, and local diagnostics.
//!
//! Support bundles are previewed and redacted before any export. Nothing is
//! sent to `OwnMesh` operators unless the user explicitly exports a bundle.

#![allow(
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
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
    Pass,
    Warn,
    Fail,
}

/// One doctor row.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DoctorCheck {
    pub id: String,
    pub status: CheckStatus,
    pub message: String,
}

/// Full doctor report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub version: String,
    pub checks: Vec<DoctorCheck>,
    pub ok: bool,
}

/// Inputs gathered by CLI/daemon for doctor.
///
/// The boolean fields are independent diagnostic observations and privacy
/// settings, so replacing them with a state machine would obscure the API.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Default)]
pub struct DoctorInput {
    pub config_readable: bool,
    pub daemon_reachable: bool,
    pub identity_present: bool,
    pub control_plane_url: Option<String>,
    pub telemetry_enabled: bool,
    pub relay_enabled: bool,
}

/// Run local doctor checks (no network required).
#[must_use]
pub fn run_doctor(input: &DoctorInput) -> DoctorReport {
    let mut checks = vec![
        DoctorCheck {
            id: "config".into(),
            status: if input.config_readable {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            },
            message: if input.config_readable {
                "config readable".into()
            } else {
                "config missing or unreadable".into()
            },
        },
        DoctorCheck {
            id: "daemon".into(),
            status: if input.daemon_reachable {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            message: if input.daemon_reachable {
                "daemon reachable via local IPC".into()
            } else {
                "daemon not reachable".into()
            },
        },
        DoctorCheck {
            id: "identity".into(),
            status: if input.identity_present {
                CheckStatus::Pass
            } else {
                CheckStatus::Warn
            },
            message: if input.identity_present {
                "device identity present".into()
            } else {
                "device identity not enrolled".into()
            },
        },
        DoctorCheck {
            id: "telemetry_default".into(),
            status: if input.telemetry_enabled {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            message: if input.telemetry_enabled {
                "telemetry is enabled (user opt-in)".into()
            } else {
                "telemetry disabled (default)".into()
            },
        },
        DoctorCheck {
            id: "relay_default".into(),
            status: if input.relay_enabled {
                CheckStatus::Warn
            } else {
                CheckStatus::Pass
            },
            message: if input.relay_enabled {
                "cloud file relay enabled (user opt-in)".into()
            } else {
                "cloud file relay disabled (default)".into()
            },
        },
    ];
    if input.control_plane_url.is_none() {
        checks.push(DoctorCheck {
            id: "control_plane".into(),
            status: CheckStatus::Warn,
            message: "control plane URL not configured".into(),
        });
    } else {
        checks.push(DoctorCheck {
            id: "control_plane".into(),
            status: CheckStatus::Pass,
            message: format!(
                "control plane configured: {}",
                input.control_plane_url.as_deref().unwrap_or("")
            ),
        });
    }
    let ok = checks.iter().all(|c| c.status != CheckStatus::Fail);
    DoctorReport {
        version: crate_version().to_string(),
        checks,
        ok,
    }
}

/// Support bundle (local only until user exports).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupportBundle {
    pub created_unix: i64,
    pub doctor: DoctorReport,
    pub sections: BTreeMap<String, String>,
    pub redacted: bool,
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
    ] {
        // crude line-based redaction
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
        let report = run_doctor(&DoctorInput {
            config_readable: true,
            daemon_reachable: true,
            identity_present: true,
            control_plane_url: Some("https://example.workers.dev".into()),
            telemetry_enabled: false,
            relay_enabled: false,
        });
        assert!(report.ok);
        assert!(report
            .checks
            .iter()
            .any(|c| c.id == "telemetry_default" && c.status == CheckStatus::Pass));
    }

    #[test]
    fn redacts_secrets() {
        let s = redact_text("access_token=abc\nhello");
        assert!(s.contains("REDACTED"));
        assert!(!s.contains("abc"));
    }
}
