//! Versioned operation payload contract carried by device protocol envelopes.

use crate::Envelope;
use ownmesh_domain::{DomainError, ErrorCode, OperationId, WorkspaceId};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Independent version identifier for operation payloads.
pub const OPERATION_CONTRACT_V1: &str = "ownmesh.operation/1.0";

const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
const OPERATION_ENVELOPE_KEYS: &[&str] = &[
    "protocol",
    "message_id",
    "type",
    "device_id",
    "correlation_id",
    "seq",
    "sent_at",
    "expires_at",
    "payload",
];

/// Operation payload contract version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationContract {
    #[serde(rename = "ownmesh.operation/1.0")]
    V1,
}

/// Non-terminal operation state reported by an Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationProgressStatus {
    Queued,
    PendingApproval,
    Running,
}

/// Terminal operation state reported by an Agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationResultStatus {
    Completed,
    Failed,
    Cancelled,
    TimedOut,
    DeviceOffline,
}

/// Stable error body for terminal operation failures.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationError {
    pub code: String,
    pub message: String,
    pub retryable: bool,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_optional_json_value"
    )]
    pub details: Option<Value>,
}

fn deserialize_optional_json_value<'de, D>(deserializer: D) -> Result<Option<Value>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Value::deserialize(deserializer).map(Some)
}

/// Control Plane to Agent request payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationRequestPayload {
    pub operation_contract: OperationContract,
    pub operation_id: OperationId,
    pub capability: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workspace_id: Option<WorkspaceId>,
    pub idempotency_key: String,
    pub arguments: Value,
}

/// Agent to Control Plane non-terminal progress payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationProgressPayload {
    pub operation_contract: OperationContract,
    pub operation_id: OperationId,
    pub status: OperationProgressStatus,
    pub progress_seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

/// Agent to Control Plane ordered operation event payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationEventPayload {
    pub operation_contract: OperationContract,
    pub operation_id: OperationId,
    pub event_seq: u64,
    pub event_type: String,
    pub data: Value,
}

/// Agent to Control Plane terminal result payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationResultPayload {
    pub operation_contract: OperationContract,
    pub operation_id: OperationId,
    pub status: OperationResultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<OperationError>,
}

/// Typed payload selected by the outer device-envelope message type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationPayload {
    Request(OperationRequestPayload),
    Progress(OperationProgressPayload),
    Event(OperationEventPayload),
    Result(OperationResultPayload),
}

impl OperationPayload {
    fn message_type(&self) -> &'static str {
        match self {
            Self::Request(_) => "operation.request",
            Self::Progress(_) => "operation.progress",
            Self::Event(_) => "operation.event",
            Self::Result(_) => "operation.result",
        }
    }

    fn operation_id(&self) -> &OperationId {
        match self {
            Self::Request(payload) => &payload.operation_id,
            Self::Progress(payload) => &payload.operation_id,
            Self::Event(payload) => &payload.operation_id,
            Self::Result(payload) => &payload.operation_id,
        }
    }

    fn to_value(&self) -> Result<Value, DomainError> {
        let result = match self {
            Self::Request(payload) => serde_json::to_value(payload),
            Self::Progress(payload) => serde_json::to_value(payload),
            Self::Event(payload) => serde_json::to_value(payload),
            Self::Result(payload) => serde_json::to_value(payload),
        };
        result.map_err(|error| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                format!("failed to serialize operation payload: {error}"),
            )
        })
    }

    fn validate(&self) -> Result<(), DomainError> {
        match self {
            Self::Request(payload) => validate_request(payload),
            Self::Progress(payload) => validate_progress(payload),
            Self::Event(payload) => validate_event(payload),
            Self::Result(payload) => validate_result(payload),
        }
    }
}

fn bad_envelope(message: &'static str) -> DomainError {
    DomainError::new(ErrorCode::BadEnvelope, message)
}

fn reject_explicit_nulls(
    payload: &Value,
    fields: &[&str],
    label: &'static str,
) -> Result<(), DomainError> {
    let object = payload
        .as_object()
        .ok_or_else(|| bad_envelope("operation payload must be a JSON object"))?;
    if let Some(field) = fields
        .iter()
        .find(|field| object.get(**field).is_some_and(Value::is_null))
    {
        return Err(DomainError::new(
            ErrorCode::BadEnvelope,
            format!("{label} field '{field}' must not be null"),
        ));
    }
    Ok(())
}

fn validate_request(payload: &OperationRequestPayload) -> Result<(), DomainError> {
    if payload.capability.trim().is_empty()
        || payload.capability.chars().count() > 128
        || payload.idempotency_key.trim().is_empty()
        || payload.idempotency_key.chars().count() > 256
        || !payload.arguments.is_object()
    {
        return Err(bad_envelope(
            "operation.request requires non-empty capability/idempotency_key and object arguments",
        ));
    }
    Ok(())
}

fn validate_progress(payload: &OperationProgressPayload) -> Result<(), DomainError> {
    if payload.progress_seq > MAX_SAFE_JSON_INTEGER {
        return Err(bad_envelope(
            "operation.progress progress_seq exceeds the JSON safe-integer range",
        ));
    }
    if payload
        .summary
        .as_ref()
        .is_some_and(|value| value.trim().is_empty() || value.chars().count() > 1024)
    {
        return Err(bad_envelope("operation.progress summary must not be empty"));
    }
    if payload
        .details
        .as_ref()
        .is_some_and(|value| !value.is_object())
    {
        return Err(bad_envelope("operation.progress details must be an object"));
    }
    Ok(())
}

fn validate_event(payload: &OperationEventPayload) -> Result<(), DomainError> {
    if payload.event_seq > MAX_SAFE_JSON_INTEGER
        || payload.event_type.trim().is_empty()
        || payload.event_type.chars().count() > 128
        || !payload.data.is_object()
    {
        return Err(bad_envelope(
            "operation.event requires a safe event_seq, non-empty event_type, and object data",
        ));
    }
    Ok(())
}

fn valid_error(error: &OperationError) -> bool {
    !error.code.trim().is_empty()
        && error.code.chars().count() <= 128
        && !error.message.trim().is_empty()
        && error.message.chars().count() <= 4096
}

fn validate_result(payload: &OperationResultPayload) -> Result<(), DomainError> {
    match payload.status {
        OperationResultStatus::Completed => {
            if payload
                .result
                .as_ref()
                .is_none_or(|value| !value.is_object())
                || payload.error.is_some()
            {
                return Err(bad_envelope(
                    "completed operation.result requires object result and forbids error",
                ));
            }
        }
        OperationResultStatus::Failed
        | OperationResultStatus::TimedOut
        | OperationResultStatus::DeviceOffline => {
            if payload
                .error
                .as_ref()
                .is_none_or(|error| !valid_error(error))
                || payload.result.is_some()
            {
                return Err(bad_envelope(
                    "failed operation.result requires error and forbids result",
                ));
            }
        }
        OperationResultStatus::Cancelled => {
            if payload.result.is_some() {
                return Err(bad_envelope("cancelled operation.result forbids result"));
            }
            if payload
                .error
                .as_ref()
                .is_some_and(|error| !valid_error(error))
            {
                return Err(bad_envelope(
                    "cancelled operation.result error fields must not be empty",
                ));
            }
        }
    }
    Ok(())
}

/// A device envelope whose operation payload has been parsed and validated.
#[derive(Debug, Clone, PartialEq)]
pub struct OperationEnvelope {
    pub envelope: Envelope,
    pub payload: OperationPayload,
}

impl OperationEnvelope {
    /// Parse and validate a typed operation envelope.
    pub fn parse_slice(data: &[u8]) -> Result<Self, DomainError> {
        let envelope = Envelope::parse_slice(data)?;
        let raw: Value = serde_json::from_slice(data).map_err(|error| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                format!("invalid operation envelope JSON: {error}"),
            )
        })?;
        let object = raw.as_object().ok_or_else(|| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                "operation envelope must be a JSON object",
            )
        })?;
        if let Some(unknown) = object
            .keys()
            .find(|key| !OPERATION_ENVELOPE_KEYS.contains(&key.as_str()))
        {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                format!("operation envelope contains unknown field '{unknown}'"),
            ));
        }
        if object.get("expires_at").is_some_and(Value::is_null) {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "operation envelope expires_at must not be null",
            ));
        }
        let payload = match envelope.message_type.as_str() {
            "operation.request" => {
                reject_explicit_nulls(
                    &envelope.payload,
                    &["workspace_id"],
                    "operation.request payload",
                )?;
                serde_json::from_value(envelope.payload.clone()).map(OperationPayload::Request)
            }
            "operation.progress" => {
                reject_explicit_nulls(
                    &envelope.payload,
                    &["summary", "details"],
                    "operation.progress payload",
                )?;
                serde_json::from_value(envelope.payload.clone()).map(OperationPayload::Progress)
            }
            "operation.event" => {
                serde_json::from_value(envelope.payload.clone()).map(OperationPayload::Event)
            }
            "operation.result" => {
                reject_explicit_nulls(
                    &envelope.payload,
                    &["result", "error"],
                    "operation.result payload",
                )?;
                serde_json::from_value(envelope.payload.clone()).map(OperationPayload::Result)
            }
            other => {
                return Err(DomainError::new(
                    ErrorCode::BadEnvelope,
                    format!("unsupported operation envelope type '{other}'"),
                ));
            }
        }
        .map_err(|error| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                format!("invalid operation payload: {error}"),
            )
        })?;

        let typed = Self { envelope, payload };
        typed.validate_contract()?;
        Ok(typed)
    }

    /// Parse and validate a typed operation envelope from JSON text.
    pub fn parse_str(data: &str) -> Result<Self, DomainError> {
        Self::parse_slice(data.as_bytes())
    }

    /// Serialize the typed envelope to compact JSON bytes.
    pub fn to_vec(&self) -> Result<Vec<u8>, DomainError> {
        self.validate_contract()?;
        let mut envelope = self.envelope.clone();
        envelope.payload = self.payload.to_value()?;
        envelope.to_vec()
    }

    /// Serialize the typed envelope to pretty fixture JSON.
    pub fn to_pretty_json(&self) -> Result<String, DomainError> {
        self.validate_contract()?;
        let mut envelope = self.envelope.clone();
        envelope.payload = self.payload.to_value()?;
        envelope.to_pretty_json()
    }

    /// Validate cross-field bindings that JSON Schema cannot express portably.
    pub fn validate_contract(&self) -> Result<(), DomainError> {
        if self.envelope.message_type != self.payload.message_type() {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "operation payload does not match envelope type",
            ));
        }
        let correlation = self.envelope.correlation_id.as_deref().ok_or_else(|| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                "operation envelope requires correlation_id",
            )
        })?;
        if correlation != self.payload.operation_id().as_str() {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "correlation_id must equal payload operation_id",
            ));
        }
        if self.envelope.seq > MAX_SAFE_JSON_INTEGER {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "operation envelope seq exceeds the JSON safe-integer range",
            ));
        }
        if matches!(self.payload, OperationPayload::Request(_))
            && self.envelope.expires_at.is_none()
        {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "operation.request requires expires_at",
            ));
        }

        self.payload.validate()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SHARED_FIXTURES_DIR;
    use ownmesh_domain::DeviceId;
    use std::fs;
    use std::path::Path;

    #[test]
    fn operation_contract_constant_matches_wire_enum() {
        assert_eq!(
            serde_json::to_value(OperationContract::V1).unwrap(),
            Value::String(OPERATION_CONTRACT_V1.into())
        );
    }

    #[test]
    fn rejects_mismatched_operation_binding() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_request_envelope.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        value["correlation_id"] = Value::String("op_different".into());
        let error =
            OperationEnvelope::parse_slice(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error.code, ErrorCode::BadEnvelope);
    }

    #[test]
    fn rejects_request_without_expiry() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_request_envelope.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        value.as_object_mut().unwrap().remove("expires_at");
        let error =
            OperationEnvelope::parse_slice(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error.code, ErrorCode::BadEnvelope);
    }

    #[test]
    fn rejects_unknown_outer_field() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_request_envelope.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        value["force_allow"] = Value::Bool(true);
        let error =
            OperationEnvelope::parse_slice(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error.code, ErrorCode::BadEnvelope);
    }

    #[test]
    fn rejects_completed_result_with_error() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_result_envelope.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        value["payload"]["error"] = serde_json::json!({
            "code": "OWNMESH_E_INTERNAL",
            "message": "must not accompany success",
            "retryable": false
        });
        let error =
            OperationEnvelope::parse_slice(&serde_json::to_vec(&value).unwrap()).unwrap_err();
        assert_eq!(error.code, ErrorCode::BadEnvelope);
    }

    #[test]
    fn rejects_null_expiry_and_unsafe_seq() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_request_envelope.json");
        let original: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();

        let mut null_expiry = original.clone();
        null_expiry["expires_at"] = Value::Null;
        assert!(
            OperationEnvelope::parse_slice(&serde_json::to_vec(&null_expiry).unwrap()).is_err()
        );

        let mut unsafe_seq = original.clone();
        unsafe_seq["seq"] = Value::from(MAX_SAFE_JSON_INTEGER + 1);
        assert!(OperationEnvelope::parse_slice(&serde_json::to_vec(&unsafe_seq).unwrap()).is_err());

        for timestamp in ["2026-02-30T00:00:00Z", "2026-01-01T24:00:00Z"] {
            let mut invalid = original.clone();
            invalid["sent_at"] = Value::String(timestamp.into());
            assert!(
                OperationEnvelope::parse_slice(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }
    }

    #[test]
    fn rejects_explicit_null_optional_payload_fields() {
        let request_path = Path::new(SHARED_FIXTURES_DIR).join("operation_request_envelope.json");
        let request: Value =
            serde_json::from_str(&fs::read_to_string(request_path).unwrap()).unwrap();
        let mut null_workspace = request;
        null_workspace["payload"]["workspace_id"] = Value::Null;
        assert!(
            OperationEnvelope::parse_slice(&serde_json::to_vec(&null_workspace).unwrap()).is_err()
        );

        let progress_path = Path::new(SHARED_FIXTURES_DIR).join("operation_progress_envelope.json");
        let progress: Value =
            serde_json::from_str(&fs::read_to_string(progress_path).unwrap()).unwrap();
        for field in ["summary", "details"] {
            let mut invalid = progress.clone();
            invalid["payload"][field] = Value::Null;
            assert!(
                OperationEnvelope::parse_slice(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }

        let result_path = Path::new(SHARED_FIXTURES_DIR).join("operation_result_envelope.json");
        let result: Value =
            serde_json::from_str(&fs::read_to_string(result_path).unwrap()).unwrap();
        for field in ["result", "error"] {
            let mut invalid = result.clone();
            invalid["payload"][field] = Value::Null;
            assert!(
                OperationEnvelope::parse_slice(&serde_json::to_vec(&invalid).unwrap()).is_err()
            );
        }
    }

    #[test]
    fn preserves_null_error_details_as_intentional_json() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_result_envelope.json");
        let mut value: Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
        value["payload"] = serde_json::json!({
            "operation_contract": OPERATION_CONTRACT_V1,
            "operation_id": value["correlation_id"],
            "status": "failed",
            "error": {
                "code": "OWNMESH_E_INTERNAL",
                "message": "failed",
                "retryable": false,
                "details": null
            }
        });
        let parsed = OperationEnvelope::parse_slice(&serde_json::to_vec(&value).unwrap()).unwrap();
        let serialized: Value = serde_json::from_slice(&parsed.to_vec().unwrap()).unwrap();
        assert!(serialized["payload"]["error"]["details"].is_null());
    }

    #[test]
    fn typed_serialization_rechecks_message_type() {
        let path = Path::new(SHARED_FIXTURES_DIR).join("operation_request_envelope.json");
        let raw = fs::read_to_string(path).unwrap();
        let mut typed = OperationEnvelope::parse_str(&raw).unwrap();
        typed.envelope.message_type = "operation.result".into();
        assert!(typed.to_vec().is_err());
        assert_eq!(
            typed.envelope.device_id,
            DeviceId::parse("dev_windows-01").unwrap()
        );
    }
}
