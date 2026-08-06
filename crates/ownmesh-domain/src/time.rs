//! Shared timestamp, expiry, and clock-skew helpers.

use crate::error::{DomainError, ErrorCode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Default allowed clock skew when validating expiry (specification §21.4).
pub const DEFAULT_CLOCK_SKEW: Duration = Duration::from_secs(60);

/// UTC timestamp stored and serialized as RFC3339 (`...Z`, no fractional seconds when zero).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Timestamp(OffsetDateTime);

impl Serialize for Timestamp {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_rfc3339())
    }
}

impl<'de> Deserialize<'de> for Timestamp {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(&raw).map_err(serde::de::Error::custom)
    }
}

impl Timestamp {
    /// Create from an `OffsetDateTime` (normalized to UTC).
    #[must_use]
    pub fn from_offset(dt: OffsetDateTime) -> Self {
        Self(dt.to_offset(time::UtcOffset::UTC))
    }

    /// Current UTC time.
    #[must_use]
    pub fn now() -> Self {
        Self::from_offset(OffsetDateTime::now_utc())
    }

    /// Parse an RFC3339 string.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when `raw` is not a valid RFC3339 timestamp.
    pub fn parse(raw: &str) -> Result<Self, DomainError> {
        let dt = OffsetDateTime::parse(raw, &Rfc3339).map_err(|e| {
            DomainError::new(
                ErrorCode::InvalidArgument,
                format!("invalid RFC3339 timestamp '{raw}': {e}"),
            )
        })?;
        Ok(Self::from_offset(dt))
    }

    /// Borrow the inner offset datetime (UTC).
    #[must_use]
    pub fn date_time(self) -> OffsetDateTime {
        self.0
    }

    /// Format as RFC3339 UTC with `Z` suffix.
    ///
    /// Fractional seconds are omitted when nanoseconds are zero so fixtures stay stable.
    #[must_use]
    pub fn to_rfc3339(self) -> String {
        let dt = self.0;
        if dt.nanosecond() == 0 {
            format!(
                "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                dt.year(),
                u8::from(dt.month()),
                dt.day(),
                dt.hour(),
                dt.minute(),
                dt.second(),
            )
        } else {
            dt.format(&Rfc3339).unwrap_or_else(|_| dt.to_string())
        }
    }

    /// Checked addition of a duration.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the duration cannot be represented or the
    /// resulting timestamp would overflow.
    pub fn checked_add(self, duration: Duration) -> Result<Self, DomainError> {
        let t_duration = time::Duration::try_from(duration)
            .map_err(|_| DomainError::new(ErrorCode::InvalidArgument, "duration out of range"))?;
        self.0
            .checked_add(t_duration)
            .map(Self)
            .ok_or_else(|| DomainError::new(ErrorCode::InvalidArgument, "timestamp overflow"))
    }

    /// Checked subtraction of a duration.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when the duration cannot be represented or the
    /// resulting timestamp would underflow.
    pub fn checked_sub(self, duration: Duration) -> Result<Self, DomainError> {
        let t_duration = time::Duration::try_from(duration)
            .map_err(|_| DomainError::new(ErrorCode::InvalidArgument, "duration out of range"))?;
        self.0
            .checked_sub(t_duration)
            .map(Self)
            .ok_or_else(|| DomainError::new(ErrorCode::InvalidArgument, "timestamp underflow"))
    }
}

impl fmt::Display for Timestamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_rfc3339())
    }
}

/// Absolute expiry instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Expiry {
    pub at: Timestamp,
}

impl Expiry {
    #[must_use]
    pub const fn new(at: Timestamp) -> Self {
        Self { at }
    }

    /// Whether `now` is at or after expiry, ignoring skew.
    #[must_use]
    pub fn is_expired_at(self, now: Timestamp) -> bool {
        now >= self.at
    }

    /// Whether expired given clock skew allowance (treat as valid until `at + skew`).
    #[must_use]
    pub fn is_expired_at_with_skew(self, now: Timestamp, skew: Duration) -> bool {
        match self.at.checked_add(skew) {
            Ok(deadline) => now >= deadline,
            // On overflow, treat as not expired via skew path; strict compare still applies.
            Err(_) => now >= self.at,
        }
    }

    /// Return `Err(OWNMESH_E_EXPIRED)` when expired under the given skew.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when this expiry is at or before the skew-adjusted
    /// current time.
    pub fn check_at(self, now: Timestamp, skew: Duration) -> Result<(), DomainError> {
        if self.is_expired_at_with_skew(now, skew) {
            Err(DomainError::new(
                ErrorCode::Expired,
                format!(
                    "expired at {} (now {now}, skew {}s)",
                    self.at,
                    skew.as_secs()
                ),
            ))
        } else {
            Ok(())
        }
    }

    /// Check against current wall clock with default skew.
    ///
    /// # Errors
    ///
    /// Returns [`DomainError`] when this expiry has passed after applying the
    /// default clock skew.
    pub fn check_now(self) -> Result<(), DomainError> {
        self.check_at(Timestamp::now(), DEFAULT_CLOCK_SKEW)
    }
}

impl fmt::Display for Expiry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "expires_at={}", self.at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn rfc3339_roundtrip() {
        let ts = Timestamp::from_offset(datetime!(2026-08-06 00:00:00 UTC));
        let s = ts.to_rfc3339();
        let back = Timestamp::parse(&s).unwrap();
        assert_eq!(back, ts);
    }

    #[test]
    fn expiry_detects_past() {
        let exp = Expiry::new(Timestamp::from_offset(datetime!(2020-01-01 00:00:00 UTC)));
        let now = Timestamp::from_offset(datetime!(2026-01-01 00:00:00 UTC));
        assert!(exp.is_expired_at(now));
        let err = exp.check_at(now, Duration::from_secs(0)).unwrap_err();
        assert_eq!(err.code, ErrorCode::Expired);
    }

    #[test]
    fn skew_allows_near_future_past_boundary() {
        let at = Timestamp::from_offset(datetime!(2026-01-01 00:00:00 UTC));
        let exp = Expiry::new(at);
        // 30s after expiry, within 60s skew → still acceptable
        let now = Timestamp::from_offset(datetime!(2026-01-01 00:00:30 UTC));
        assert!(!exp.is_expired_at_with_skew(now, Duration::from_secs(60)));
        assert!(exp.check_at(now, Duration::from_secs(60)).is_ok());
        // 90s after expiry, beyond skew → expired
        let later = Timestamp::from_offset(datetime!(2026-01-01 00:01:30 UTC));
        assert!(exp.is_expired_at_with_skew(later, Duration::from_secs(60)));
    }

    #[test]
    fn invalid_timestamp_errors() {
        let err = Timestamp::parse("not-a-date").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);
    }
}
