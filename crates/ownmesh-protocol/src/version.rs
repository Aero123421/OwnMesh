//! Protocol version negotiation (specification §21.6).

use crate::envelope::PROTOCOL_DEVICE_V1;
use ownmesh_domain::{DomainError, ErrorCode};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Parsed `ownmesh.device/{major}.{minor}` style protocol version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProtocolVersion {
    pub major: u32,
    pub minor: u32,
}

impl ProtocolVersion {
    /// Current `OwnMesh` device protocol.
    pub const CURRENT: Self = Self { major: 1, minor: 0 };

    /// Parse `ownmesh.device/1.0` or bare `1.0`.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] if `raw` does not contain a valid major and minor
    /// protocol version.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let rest = raw
            .strip_prefix("ownmesh.device/")
            .or_else(|| raw.strip_prefix("ownmesh.device"))
            .map_or(raw, |s| s.trim_start_matches('/'));
        let mut parts = rest.split('.');
        let major_s = parts.next().unwrap_or("");
        let minor_s = parts.next().unwrap_or("0");
        if parts.next().is_some() || major_s.is_empty() {
            return Err(DomainError::new(
                ErrorCode::UnsupportedProtocol,
                format!("invalid protocol version '{raw}'"),
            ));
        }
        let major: u32 = major_s.parse().map_err(|_| {
            DomainError::new(
                ErrorCode::UnsupportedProtocol,
                format!("invalid protocol major in '{raw}'"),
            )
        })?;
        let minor: u32 = minor_s.parse().map_err(|_| {
            DomainError::new(
                ErrorCode::UnsupportedProtocol,
                format!("invalid protocol minor in '{raw}'"),
            )
        })?;
        Ok(Self { major, minor })
    }

    /// Wire form `ownmesh.device/{major}.{minor}`.
    #[must_use]
    pub fn to_wire(self) -> String {
        format!("ownmesh.device/{}.{}", self.major, self.minor)
    }

    /// Major-incompatible check.
    #[must_use]
    pub const fn is_major_compatible_with(self, other: Self) -> bool {
        self.major == other.major
    }
}

impl fmt::Display for ProtocolVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_wire())
    }
}

impl Default for ProtocolVersion {
    fn default() -> Self {
        Self::CURRENT
    }
}

/// Result of version negotiation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiatedProtocol {
    pub selected: ProtocolVersion,
    pub wire: String,
}

/// Negotiate a protocol version.
///
/// Rules (specification §21.6):
/// - major must match for compatibility
/// - prefer highest mutually supported minor
/// - Control Plane and Agent support current minor and the previous minor
///
/// # Errors
///
/// Returns [`DomainError`] if either version set is empty or the two sets have
/// no version in common.
pub fn negotiate(
    offered: &[ProtocolVersion],
    supported: &[ProtocolVersion],
) -> Result<NegotiatedProtocol, DomainError> {
    if offered.is_empty() {
        return Err(DomainError::new(
            ErrorCode::UnsupportedProtocol,
            "peer offered no protocol versions",
        ));
    }
    if supported.is_empty() {
        return Err(DomainError::new(
            ErrorCode::UnsupportedProtocol,
            "local side supports no protocol versions",
        ));
    }

    let mut best: Option<ProtocolVersion> = None;
    for offer in offered {
        for local in supported {
            if offer.major != local.major {
                continue;
            }
            // Capability-based minor: select the minimum of the two minors
            // only when both sides list that exact version, or pick the
            // highest minor present on both lists.
            if offer == local {
                best = Some(match best {
                    Some(b) if b >= *offer => b,
                    _ => *offer,
                });
            }
        }
    }

    let selected = best.ok_or_else(|| {
        DomainError::new(
            ErrorCode::UnsupportedProtocol,
            format!(
                "no compatible protocol between offered {offered:?} and supported {supported:?}"
            ),
        )
    })?;

    Ok(NegotiatedProtocol {
        wire: selected.to_wire(),
        selected,
    })
}

/// Default supported set: current minor and one previous minor (when major>0 or minor>0).
#[must_use]
pub fn default_supported_versions() -> Vec<ProtocolVersion> {
    let current = ProtocolVersion::CURRENT;
    let mut out = vec![current];
    if current.minor > 0 {
        out.push(ProtocolVersion {
            major: current.major,
            minor: current.minor - 1,
        });
    }
    out
}

/// Ensure the constant wire string parses to [`ProtocolVersion::CURRENT`].
///
/// # Errors
///
/// Returns [`DomainError`] if [`PROTOCOL_DEVICE_V1`] is invalid or does not match
/// [`ProtocolVersion::CURRENT`].
pub fn assert_current_wire_constant() -> Result<(), DomainError> {
    let parsed = ProtocolVersion::parse(PROTOCOL_DEVICE_V1)?;
    if parsed != ProtocolVersion::CURRENT {
        return Err(DomainError::new(
            ErrorCode::Internal,
            "PROTOCOL_DEVICE_V1 does not match ProtocolVersion::CURRENT",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_current() {
        let v = ProtocolVersion::parse(PROTOCOL_DEVICE_V1).unwrap();
        assert_eq!(v, ProtocolVersion::CURRENT);
        assert_eq!(v.to_wire(), PROTOCOL_DEVICE_V1);
    }

    #[test]
    fn negotiate_picks_common_highest() {
        let offered = [
            ProtocolVersion { major: 1, minor: 0 },
            ProtocolVersion { major: 1, minor: 1 },
        ];
        let supported = [
            ProtocolVersion { major: 1, minor: 0 },
            ProtocolVersion { major: 1, minor: 1 },
        ];
        let n = negotiate(&offered, &supported).unwrap();
        assert_eq!(n.selected.minor, 1);
    }

    #[test]
    fn negotiate_rejects_major_mismatch() {
        let offered = [ProtocolVersion { major: 2, minor: 0 }];
        let supported = default_supported_versions();
        let err = negotiate(&offered, &supported).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedProtocol);
    }

    #[test]
    fn negotiate_empty_offered() {
        let err = negotiate(&[], &default_supported_versions()).unwrap_err();
        assert_eq!(err.code, ErrorCode::UnsupportedProtocol);
    }
}
