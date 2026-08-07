//! Error taxonomy and CLI exit codes (specification §14.7 / §16.3).

use serde::{Deserialize, Serialize};
use std::fmt;

/// Process exit codes for `ownmesh` CLI (specification §16.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum ExitCode {
    Success = 0,
    UsageConfig = 2,
    Authentication = 3,
    Authorization = 4,
    DeviceOffline = 5,
    TimeoutCancelled = 6,
    Conflict = 7,
    ProfileUnavailable = 8,
    Internal = 9,
}

impl ExitCode {
    /// Numeric value used as the process exit status.
    #[must_use]
    pub const fn code(self) -> i32 {
        self as i32
    }

    /// Human-readable English meaning (stable, not localized).
    #[must_use]
    pub const fn meaning(self) -> &'static str {
        match self {
            Self::Success => "Success",
            Self::UsageConfig => "Usage/config error",
            Self::Authentication => "Authentication error",
            Self::Authorization => "Authorization/policy denied",
            Self::DeviceOffline => "Device offline/unreachable",
            Self::TimeoutCancelled => "Timeout/cancelled",
            Self::Conflict => "Conflict/stale snapshot/controller conflict",
            Self::ProfileUnavailable => "Profile/dependency unavailable",
            Self::Internal => "Internal error",
        }
    }

    /// All non-success exit codes in ascending order.
    #[must_use]
    pub const fn all_error_codes() -> [Self; 8] {
        [
            Self::UsageConfig,
            Self::Authentication,
            Self::Authorization,
            Self::DeviceOffline,
            Self::TimeoutCancelled,
            Self::Conflict,
            Self::ProfileUnavailable,
            Self::Internal,
        ]
    }
}

impl fmt::Display for ExitCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.code(), self.meaning())
    }
}

/// Stable machine-readable error codes (`OWNMESH_E_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    // exit 2 — usage / config / validation
    #[serde(rename = "OWNMESH_E_INVALID_ID")]
    InvalidId,
    #[serde(rename = "OWNMESH_E_INVALID_ARGUMENT")]
    InvalidArgument,
    #[serde(rename = "OWNMESH_E_SCHEMA_VALIDATION")]
    SchemaValidation,
    #[serde(rename = "OWNMESH_E_BAD_ENVELOPE")]
    BadEnvelope,
    #[serde(rename = "OWNMESH_E_UNSUPPORTED_PROTOCOL")]
    UnsupportedProtocol,
    #[serde(rename = "OWNMESH_E_CONFIG")]
    Config,

    // exit 3
    #[serde(rename = "OWNMESH_E_AUTHENTICATION")]
    Authentication,

    // exit 4
    #[serde(rename = "OWNMESH_E_AUTHORIZATION")]
    Authorization,
    #[serde(rename = "OWNMESH_E_POLICY_DENIED")]
    PolicyDenied,

    // exit 5
    #[serde(rename = "OWNMESH_E_DEVICE_OFFLINE")]
    DeviceOffline,

    // exit 6
    #[serde(rename = "OWNMESH_E_TIMEOUT")]
    Timeout,
    #[serde(rename = "OWNMESH_E_CANCELLED")]
    Cancelled,
    #[serde(rename = "OWNMESH_E_EXPIRED")]
    Expired,

    // exit 7
    #[serde(rename = "OWNMESH_E_CONFLICT")]
    Conflict,
    #[serde(rename = "OWNMESH_E_STALE_SNAPSHOT")]
    StaleSnapshot,
    #[serde(rename = "OWNMESH_E_CONTROLLER_CONFLICT")]
    ControllerConflict,
    #[serde(rename = "OWNMESH_E_SESSION_NOT_CONTROLLER")]
    SessionNotController,

    // exit 8
    #[serde(rename = "OWNMESH_E_PROFILE_UNAVAILABLE")]
    ProfileUnavailable,

    // exit 9
    #[serde(rename = "OWNMESH_E_INTERNAL")]
    Internal,
}

impl ErrorCode {
    /// Stable wire / JSON string (English, fixed).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidId => "OWNMESH_E_INVALID_ID",
            Self::InvalidArgument => "OWNMESH_E_INVALID_ARGUMENT",
            Self::SchemaValidation => "OWNMESH_E_SCHEMA_VALIDATION",
            Self::BadEnvelope => "OWNMESH_E_BAD_ENVELOPE",
            Self::UnsupportedProtocol => "OWNMESH_E_UNSUPPORTED_PROTOCOL",
            Self::Config => "OWNMESH_E_CONFIG",
            Self::Authentication => "OWNMESH_E_AUTHENTICATION",
            Self::Authorization => "OWNMESH_E_AUTHORIZATION",
            Self::PolicyDenied => "OWNMESH_E_POLICY_DENIED",
            Self::DeviceOffline => "OWNMESH_E_DEVICE_OFFLINE",
            Self::Timeout => "OWNMESH_E_TIMEOUT",
            Self::Cancelled => "OWNMESH_E_CANCELLED",
            Self::Expired => "OWNMESH_E_EXPIRED",
            Self::Conflict => "OWNMESH_E_CONFLICT",
            Self::StaleSnapshot => "OWNMESH_E_STALE_SNAPSHOT",
            Self::ControllerConflict => "OWNMESH_E_CONTROLLER_CONFLICT",
            Self::SessionNotController => "OWNMESH_E_SESSION_NOT_CONTROLLER",
            Self::ProfileUnavailable => "OWNMESH_E_PROFILE_UNAVAILABLE",
            Self::Internal => "OWNMESH_E_INTERNAL",
        }
    }

    /// Parse a stable wire code.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when `raw` is not a recognized error code.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        match raw {
            "OWNMESH_E_INVALID_ID" => Ok(Self::InvalidId),
            "OWNMESH_E_INVALID_ARGUMENT" => Ok(Self::InvalidArgument),
            "OWNMESH_E_SCHEMA_VALIDATION" => Ok(Self::SchemaValidation),
            "OWNMESH_E_BAD_ENVELOPE" => Ok(Self::BadEnvelope),
            "OWNMESH_E_UNSUPPORTED_PROTOCOL" => Ok(Self::UnsupportedProtocol),
            "OWNMESH_E_CONFIG" => Ok(Self::Config),
            "OWNMESH_E_AUTHENTICATION" => Ok(Self::Authentication),
            "OWNMESH_E_AUTHORIZATION" => Ok(Self::Authorization),
            "OWNMESH_E_POLICY_DENIED" => Ok(Self::PolicyDenied),
            "OWNMESH_E_DEVICE_OFFLINE" => Ok(Self::DeviceOffline),
            "OWNMESH_E_TIMEOUT" => Ok(Self::Timeout),
            "OWNMESH_E_CANCELLED" => Ok(Self::Cancelled),
            "OWNMESH_E_EXPIRED" => Ok(Self::Expired),
            "OWNMESH_E_CONFLICT" => Ok(Self::Conflict),
            "OWNMESH_E_STALE_SNAPSHOT" => Ok(Self::StaleSnapshot),
            "OWNMESH_E_CONTROLLER_CONFLICT" => Ok(Self::ControllerConflict),
            "OWNMESH_E_SESSION_NOT_CONTROLLER" => Ok(Self::SessionNotController),
            "OWNMESH_E_PROFILE_UNAVAILABLE" => Ok(Self::ProfileUnavailable),
            "OWNMESH_E_INTERNAL" => Ok(Self::Internal),
            _ => Err(DomainError::new(
                Self::InvalidArgument,
                format!("unknown error code: {raw}"),
            )),
        }
    }

    /// Mapped CLI exit code.
    #[must_use]
    pub const fn exit_code(self) -> ExitCode {
        match self {
            Self::InvalidId
            | Self::InvalidArgument
            | Self::SchemaValidation
            | Self::BadEnvelope
            | Self::UnsupportedProtocol
            | Self::Config => ExitCode::UsageConfig,
            Self::Authentication => ExitCode::Authentication,
            Self::Authorization | Self::PolicyDenied => ExitCode::Authorization,
            Self::DeviceOffline => ExitCode::DeviceOffline,
            Self::Timeout | Self::Cancelled | Self::Expired => ExitCode::TimeoutCancelled,
            Self::Conflict
            | Self::StaleSnapshot
            | Self::ControllerConflict
            | Self::SessionNotController => ExitCode::Conflict,
            Self::ProfileUnavailable => ExitCode::ProfileUnavailable,
            Self::Internal => ExitCode::Internal,
        }
    }

    /// Whether a client may reasonably retry the operation.
    #[must_use]
    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::DeviceOffline | Self::Timeout | Self::Conflict | Self::Internal
        )
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Structured domain/protocol error returned as `Result` (never swallowed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainError {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<serde_json::Value>,
}

impl std::error::Error for DomainError {}

impl DomainError {
    #[must_use]
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            operation_id: None,
            details: None,
        }
    }

    #[must_use]
    pub fn with_operation_id(mut self, operation_id: impl Into<String>) -> Self {
        self.operation_id = Some(operation_id.into());
        self
    }

    #[must_use]
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = Some(details);
        self
    }

    #[must_use]
    pub const fn exit_code(&self) -> ExitCode {
        self.code.exit_code()
    }

    #[must_use]
    pub const fn retryable(&self) -> bool {
        self.code.retryable()
    }

    /// MCP / tool error envelope (specification §14.7).
    #[must_use]
    pub fn to_error_envelope(&self) -> ErrorEnvelope {
        ErrorEnvelope {
            error: ErrorBody {
                code: self.code,
                message: self.message.clone(),
                retryable: self.retryable(),
                operation_id: self.operation_id.clone(),
                details: self.details.clone().unwrap_or(serde_json::json!({})),
            },
        }
    }
}

impl fmt::Display for DomainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

/// Wire form `{ "error": { ... } }` from specification §14.7.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub error: ErrorBody,
}

/// Body of the error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default)]
    pub details: serde_json::Value,
}

/// Exit code lookup table entry for docs and diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ExitCodeRow {
    pub code: i32,
    pub meaning: &'static str,
}

/// Full exit-code table from specification §16.3 (including success).
#[must_use]
pub fn exit_code_table() -> [ExitCodeRow; 9] {
    [
        ExitCodeRow {
            code: ExitCode::Success.code(),
            meaning: ExitCode::Success.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::UsageConfig.code(),
            meaning: ExitCode::UsageConfig.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::Authentication.code(),
            meaning: ExitCode::Authentication.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::Authorization.code(),
            meaning: ExitCode::Authorization.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::DeviceOffline.code(),
            meaning: ExitCode::DeviceOffline.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::TimeoutCancelled.code(),
            meaning: ExitCode::TimeoutCancelled.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::Conflict.code(),
            meaning: ExitCode::Conflict.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::ProfileUnavailable.code(),
            meaning: ExitCode::ProfileUnavailable.meaning(),
        },
        ExitCodeRow {
            code: ExitCode::Internal.code(),
            meaning: ExitCode::Internal.meaning(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_code_table_matches_spec() {
        let table = exit_code_table();
        assert_eq!(table[0].code, 0);
        assert_eq!(table[1].code, 2);
        assert_eq!(table[8].code, 9);
        assert!(table.iter().any(|r| r.meaning.contains("Device offline")));
    }

    #[test]
    fn invalid_id_maps_to_usage_exit() {
        let err = DomainError::new(ErrorCode::InvalidId, "bad id");
        assert_eq!(err.exit_code(), ExitCode::UsageConfig);
        assert!(!err.retryable());
    }

    #[test]
    fn expired_maps_to_timeout_exit() {
        let err = DomainError::new(ErrorCode::Expired, "expired");
        assert_eq!(err.exit_code(), ExitCode::TimeoutCancelled);
        assert_eq!(err.code.as_str(), "OWNMESH_E_EXPIRED");
    }

    #[test]
    fn device_offline_is_retryable() {
        assert!(ErrorCode::DeviceOffline.retryable());
        assert_eq!(
            ErrorCode::DeviceOffline.exit_code(),
            ExitCode::DeviceOffline
        );
    }

    #[test]
    fn error_envelope_roundtrip() {
        let err = DomainError::new(ErrorCode::DeviceOffline, "The selected device is offline.")
            .with_operation_id("op_01TEST");
        let env = err.to_error_envelope();
        let json = serde_json::to_string(&env).expect("serialize");
        let back: ErrorEnvelope = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.error.code, ErrorCode::DeviceOffline);
        assert_eq!(back.error.operation_id.as_deref(), Some("op_01TEST"));
    }

    #[test]
    fn unknown_error_code_rejected() {
        let err = ErrorCode::parse("OWNMESH_E_NOT_A_REAL_CODE").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}
