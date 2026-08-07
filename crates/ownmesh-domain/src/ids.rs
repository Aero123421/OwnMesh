//! Stable OwnMesh identifiers: `{prefix}_{body}` with body `[A-Za-z0-9][A-Za-z0-9._-]*`.

use crate::error::{DomainError, ErrorCode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Known ID prefixes used across the OwnMesh domain and protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IdKind {
    Tenant,
    Principal,
    Membership,
    Device,
    Workspace,
    CapabilityGrant,
    PolicyRule,
    Approval,
    Operation,
    Session,
    AuditEvent,
    Message,
    Cursor,
    Policy,
}

impl IdKind {
    /// Wire prefix including trailing underscore, e.g. `ten_`.
    #[must_use]
    pub const fn prefix(self) -> &'static str {
        match self {
            Self::Tenant => "ten_",
            Self::Principal => "prin_",
            Self::Membership => "mem_",
            Self::Device => "dev_",
            Self::Workspace => "ws_",
            Self::CapabilityGrant => "grant_",
            Self::PolicyRule => "rule_",
            Self::Approval => "apr_",
            Self::Operation => "op_",
            Self::Session => "sess_",
            Self::AuditEvent => "aud_",
            Self::Message => "msg_",
            Self::Cursor => "cur_",
            Self::Policy => "pol_",
        }
    }

    /// Short English name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Tenant => "tenant",
            Self::Principal => "principal",
            Self::Membership => "membership",
            Self::Device => "device",
            Self::Workspace => "workspace",
            Self::CapabilityGrant => "capability_grant",
            Self::PolicyRule => "policy_rule",
            Self::Approval => "approval",
            Self::Operation => "operation",
            Self::Session => "session",
            Self::AuditEvent => "audit_event",
            Self::Message => "message",
            Self::Cursor => "cursor",
            Self::Policy => "policy",
        }
    }

    /// Resolve kind from a full ID string prefix.
    #[must_use]
    pub fn from_id(raw: &str) -> Option<Self> {
        const KINDS: [IdKind; 14] = [
            IdKind::Tenant,
            IdKind::Principal,
            IdKind::Membership,
            IdKind::Device,
            IdKind::Workspace,
            IdKind::CapabilityGrant,
            IdKind::PolicyRule,
            IdKind::Approval,
            IdKind::Operation,
            IdKind::Session,
            IdKind::AuditEvent,
            IdKind::Message,
            IdKind::Cursor,
            IdKind::Policy,
        ];
        KINDS.into_iter().find(|k| raw.starts_with(k.prefix()))
    }
}

/// Maximum total ID length (prefix + body).
pub const MAX_ID_LEN: usize = 128;

/// Validate body characters after the prefix.
fn validate_body(body: &str) -> Result<(), DomainError> {
    if body.is_empty() {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            "id body must not be empty",
        ));
    }
    let mut chars = body.chars();
    let Some(first) = chars.next() else {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            "id body must not be empty",
        ));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            "id body must start with an ASCII alphanumeric character",
        ));
    }
    for c in chars {
        if !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-') {
            return Err(DomainError::new(
                ErrorCode::InvalidId,
                format!("id body contains illegal character: {c:?}"),
            ));
        }
    }
    Ok(())
}

/// Parse and validate a prefixed stable ID.
pub fn parse_prefixed_id(raw: &str, kind: IdKind) -> Result<String, DomainError> {
    if raw.len() > MAX_ID_LEN {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            format!("id exceeds maximum length of {MAX_ID_LEN}"),
        ));
    }
    if raw.is_empty() {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            "id must not be empty",
        ));
    }
    let prefix = kind.prefix();
    if !raw.starts_with(prefix) {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            format!(
                "expected {} id with prefix '{prefix}', got '{raw}'",
                kind.name()
            ),
        ));
    }
    let body = &raw[prefix.len()..];
    validate_body(body)?;
    Ok(raw.to_owned())
}

/// Validate any known OwnMesh stable ID and return its kind.
pub fn parse_any_id(raw: &str) -> Result<(IdKind, String), DomainError> {
    let Some(kind) = IdKind::from_id(raw) else {
        return Err(DomainError::new(
            ErrorCode::InvalidId,
            format!("unknown id prefix in '{raw}'"),
        ));
    };
    let id = parse_prefixed_id(raw, kind)?;
    Ok((kind, id))
}

macro_rules! define_id {
    ($name:ident, $kind:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Kind of this identifier.
            pub const KIND: IdKind = $kind;

            /// Parse a stable ID string.
            pub fn parse(raw: impl AsRef<str>) -> Result<Self, DomainError> {
                let s = parse_prefixed_id(raw.as_ref(), Self::KIND)?;
                Ok(Self(s))
            }

            /// Borrow the full wire string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Body after the prefix.
            #[must_use]
            pub fn body(&self) -> &str {
                &self.0[Self::KIND.prefix().len()..]
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::parse(s)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = String::deserialize(deserializer)?;
                Self::parse(raw).map_err(serde::de::Error::custom)
            }
        }
    };
}

define_id!(TenantId, IdKind::Tenant, "Tenant identifier (`ten_...`).");
define_id!(
    PrincipalId,
    IdKind::Principal,
    "Principal identifier (`prin_...`)."
);
define_id!(
    MembershipId,
    IdKind::Membership,
    "Membership identifier (`mem_...`)."
);
define_id!(DeviceId, IdKind::Device, "Device identifier (`dev_...`).");
define_id!(
    WorkspaceId,
    IdKind::Workspace,
    "Workspace identifier (`ws_...`)."
);
define_id!(
    CapabilityGrantId,
    IdKind::CapabilityGrant,
    "Capability grant identifier (`grant_...`)."
);
define_id!(
    PolicyRuleId,
    IdKind::PolicyRule,
    "Policy rule identifier (`rule_...`)."
);
define_id!(
    ApprovalId,
    IdKind::Approval,
    "Approval identifier (`apr_...`)."
);
define_id!(
    OperationId,
    IdKind::Operation,
    "Operation identifier (`op_...`)."
);
define_id!(
    SessionId,
    IdKind::Session,
    "Session identifier (`sess_...`)."
);
define_id!(
    AuditEventId,
    IdKind::AuditEvent,
    "Audit event identifier (`aud_...`)."
);
define_id!(
    MessageId,
    IdKind::Message,
    "Protocol message identifier (`msg_...`)."
);
define_id!(PolicyId, IdKind::Policy, "Policy identifier (`pol_...`).");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_ids() {
        assert_eq!(
            TenantId::parse("ten_example").unwrap().as_str(),
            "ten_example"
        );
        assert_eq!(
            DeviceId::parse("dev_windows-01").unwrap().body(),
            "windows-01"
        );
        assert_eq!(
            SessionId::parse("sess_01HABCXYZ").unwrap().as_str(),
            "sess_01HABCXYZ"
        );
        assert_eq!(WorkspaceId::parse("ws_app").unwrap().as_str(), "ws_app");
        assert!(MessageId::parse("msg_a.b-c_1").is_ok());
    }

    #[test]
    fn rejects_unknown_prefix() {
        let err = parse_any_id("foo_bar").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
    }

    #[test]
    fn rejects_wrong_prefix_for_kind() {
        let err = DeviceId::parse("ten_example").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
        assert!(err.message.contains("dev_"));
    }

    #[test]
    fn rejects_empty_body() {
        let err = TenantId::parse("ten_").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
    }

    #[test]
    fn rejects_illegal_characters() {
        let err = OperationId::parse("op_has space").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
        let err = OperationId::parse("op_/etc/passwd").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
    }

    #[test]
    fn rejects_body_starting_with_separator() {
        let err = DeviceId::parse("dev_-leading").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
    }

    #[test]
    fn serde_roundtrip() {
        let id = OperationId::parse("op_01TEST").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"op_01TEST\"");
        let back: OperationId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    #[test]
    fn serde_rejects_invalid() {
        let result = serde_json::from_str::<DeviceId>("\"not_a_device\"");
        assert!(result.is_err());
    }
}
