//! Device protocol envelope (specification §21.3).

use ownmesh_domain::{DomainError, ErrorCode, Expiry, MessageId, Timestamp, DEFAULT_CLOCK_SKEW};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::Duration;

/// Canonical protocol identifier for the `OwnMesh` device channel 1.0.
pub const PROTOCOL_DEVICE_V1: &str = "ownmesh.device/1.0";

/// WebSocket JSON envelope between Agent and Control Plane.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Envelope {
    pub protocol: String,
    pub message_id: MessageId,
    #[serde(rename = "type")]
    pub message_type: String,
    pub device_id: ownmesh_domain::DeviceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    pub seq: u64,
    pub sent_at: Timestamp,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Expiry>,
    pub payload: Value,
}

impl Envelope {
    /// Serialize to canonical JSON bytes (UTF-8).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the envelope cannot be serialized.
    pub fn to_vec(&self) -> Result<Vec<u8>, DomainError> {
        serde_json::to_vec(self).map_err(|e| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                format!("failed to serialize envelope: {e}"),
            )
        })
    }

    /// Serialize to a pretty JSON string (fixtures / diagnostics).
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the envelope cannot be serialized.
    pub fn to_pretty_json(&self) -> Result<String, DomainError> {
        serde_json::to_string_pretty(self).map_err(|e| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                format!("failed to serialize envelope: {e}"),
            )
        })
    }

    /// Parse from UTF-8 JSON bytes without temporal validation.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the input is empty, oversized, invalid JSON, or
    /// fails the envelope's structural checks.
    pub fn parse_slice(data: &[u8]) -> Result<Self, DomainError> {
        const MAX_ENVELOPE_BYTES: usize = 1024 * 1024;

        if data.is_empty() {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "envelope is empty",
            ));
        }
        // Reject oversized frames early (1 MiB soft limit for parser safety).
        if data.len() > MAX_ENVELOPE_BYTES {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                format!("envelope exceeds {MAX_ENVELOPE_BYTES} bytes"),
            ));
        }
        let env: Self = serde_json::from_slice(data).map_err(|e| {
            DomainError::new(
                ErrorCode::BadEnvelope,
                format!("invalid envelope JSON: {e}"),
            )
        })?;
        env.validate_structure()?;
        Ok(env)
    }

    /// Parse from a JSON string without temporal validation.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the input cannot be parsed into a structurally
    /// valid envelope.
    pub fn parse_str(data: &str) -> Result<Self, DomainError> {
        Self::parse_slice(data.as_bytes())
    }

    /// Structural checks independent of wall clock.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] for an unsupported protocol, empty message type,
    /// or non-object payload.
    pub fn validate_structure(&self) -> Result<(), DomainError> {
        if self.protocol != PROTOCOL_DEVICE_V1 {
            return Err(DomainError::new(
                ErrorCode::UnsupportedProtocol,
                format!(
                    "unsupported protocol '{}', expected '{PROTOCOL_DEVICE_V1}'",
                    self.protocol
                ),
            ));
        }
        if self.message_type.trim().is_empty() {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "message type must not be empty",
            ));
        }
        if !self.payload.is_object() {
            return Err(DomainError::new(
                ErrorCode::BadEnvelope,
                "payload must be a JSON object",
            ));
        }
        Ok(())
    }

    /// Validate `expires_at` against `now` with the given skew.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the envelope is expired at `now` after applying
    /// `skew`.
    pub fn validate_expiry_at(&self, now: Timestamp, skew: Duration) -> Result<(), DomainError> {
        if let Some(exp) = self.expires_at {
            exp.check_at(now, skew).map_err(|e| {
                DomainError::new(
                    ErrorCode::Expired,
                    format!("envelope {}: {}", self.message_id, e.message),
                )
            })?;
        }
        Ok(())
    }

    /// Validate expiry with default skew against current time.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if the envelope is expired after applying the
    /// default clock skew.
    pub fn validate_expiry_now(&self) -> Result<(), DomainError> {
        self.validate_expiry_at(Timestamp::now(), DEFAULT_CLOCK_SKEW)
    }

    /// Full parse + structure + expiry validation.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if parsing, structural validation, or expiry
    /// validation fails.
    pub fn parse_and_validate_at(
        data: &[u8],
        now: Timestamp,
        skew: Duration,
    ) -> Result<Self, DomainError> {
        let env = Self::parse_slice(data)?;
        env.validate_expiry_at(now, skew)?;
        Ok(env)
    }
}

/// Fuzz / adversarial entry point: never panics on input bytes.
pub fn fuzz_parse_envelope(data: &[u8]) {
    let _ = Envelope::parse_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_domain::{DeviceId, ExitCode};
    use time::macros::datetime;

    fn sample() -> Envelope {
        Envelope {
            protocol: PROTOCOL_DEVICE_V1.into(),
            message_id: MessageId::parse("msg_01SAMPLE").unwrap(),
            message_type: "operation.request".into(),
            device_id: DeviceId::parse("dev_windows-01").unwrap(),
            correlation_id: Some("op_01SAMPLE".into()),
            seq: 123,
            sent_at: Timestamp::from_offset(datetime!(2026-08-06 00:00:00 UTC)),
            expires_at: Some(Expiry::new(Timestamp::from_offset(datetime!(
                2026-08-06 00:01:00 UTC
            )))),
            payload: serde_json::json!({ "capability": "read_file" }),
        }
    }

    #[test]
    fn envelope_roundtrip() {
        let env = sample();
        let bytes = env.to_vec().unwrap();
        let back = Envelope::parse_slice(&bytes).unwrap();
        assert_eq!(back, env);
    }

    #[test]
    fn bad_json_is_bad_envelope() {
        let err = Envelope::parse_str("{not json").unwrap_err();
        assert_eq!(err.code, ErrorCode::BadEnvelope);
        assert_eq!(err.exit_code(), ExitCode::UsageConfig);
    }

    #[test]
    fn empty_is_bad_envelope() {
        let err = Envelope::parse_slice(b"").unwrap_err();
        assert_eq!(err.code, ErrorCode::BadEnvelope);
    }

    #[test]
    fn wrong_protocol_rejected() {
        let mut env = sample();
        env.protocol = "ownmesh.device/0.9".into();
        let bytes = serde_json::to_vec(&env).unwrap();
        let err = Envelope::parse_slice(&bytes).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedProtocol);
    }

    #[test]
    fn invalid_device_id_rejected() {
        let raw = r#"{
            "protocol": "ownmesh.device/1.0",
            "message_id": "msg_ok",
            "type": "ping",
            "device_id": "not_a_device",
            "seq": 1,
            "sent_at": "2026-08-06T00:00:00Z",
            "payload": {}
        }"#;
        let err = Envelope::parse_str(raw).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadEnvelope);
    }

    #[test]
    fn expired_envelope_taxonomy() {
        let env = sample();
        let now = Timestamp::from_offset(datetime!(2026-08-06 00:05:00 UTC));
        let err = env
            .validate_expiry_at(now, Duration::from_secs(0))
            .unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
        assert_eq!(err.exit_code(), ExitCode::TimeoutCancelled);
    }

    #[test]
    fn fuzz_entry_does_not_panic() {
        for data in [
            &b""[..],
            b"{",
            b"null",
            b"[]",
            br#"{"protocol":"x"}"#,
            &[0xff, 0xfe, 0x00][..],
        ] {
            fuzz_parse_envelope(data);
        }
    }
}
