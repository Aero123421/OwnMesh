//! Cursor and pagination common types (tool results, log queries, lists).

use crate::error::{DomainError, ErrorCode};
use crate::ids::{parse_prefixed_id, IdKind};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Default page size when callers omit `limit`.
pub const DEFAULT_PAGE_LIMIT: u32 = 50;
/// Hard upper bound for a single page.
pub const MAX_PAGE_LIMIT: u32 = 1000;

/// Opaque pagination cursor (`cur_...`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cursor(String);

impl Cursor {
    /// Parse a stable cursor id.
    pub fn parse(raw: impl AsRef<str>) -> Result<Self, DomainError> {
        let s = parse_prefixed_id(raw.as_ref(), IdKind::Cursor)?;
        Ok(Self(s))
    }

    /// Construct from a validated body (without prefix).
    pub fn from_body(body: impl AsRef<str>) -> Result<Self, DomainError> {
        let raw = format!("cur_{}", body.as_ref());
        Self::parse(raw)
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Cursor").field(&self.0).finish()
    }
}

impl fmt::Display for Cursor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for Cursor {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Cursor {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(deserializer)?;
        Self::parse(raw).map_err(serde::de::Error::custom)
    }
}

/// Incoming page request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PageRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<Cursor>,
    #[serde(default = "default_limit")]
    pub limit: u32,
}

fn default_limit() -> u32 {
    DEFAULT_PAGE_LIMIT
}

impl Default for PageRequest {
    fn default() -> Self {
        Self {
            cursor: None,
            limit: DEFAULT_PAGE_LIMIT,
        }
    }
}

impl PageRequest {
    /// Validate and clamp limit into the allowed range.
    pub fn validated(self) -> Result<Self, DomainError> {
        if self.limit == 0 {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                "page limit must be >= 1",
            ));
        }
        if self.limit > MAX_PAGE_LIMIT {
            return Err(DomainError::new(
                ErrorCode::InvalidArgument,
                format!("page limit must be <= {MAX_PAGE_LIMIT}"),
            ));
        }
        Ok(self)
    }
}

/// Page of items with optional continuation cursor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Cursor>,
    #[serde(default)]
    pub truncated: bool,
}

impl<T> Page<T> {
    #[must_use]
    pub fn empty() -> Self {
        Self {
            items: Vec::new(),
            next_cursor: None,
            truncated: false,
        }
    }

    #[must_use]
    pub fn new(items: Vec<T>, next_cursor: Option<Cursor>, truncated: bool) -> Self {
        Self {
            items,
            next_cursor,
            truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_roundtrip() {
        let c = Cursor::parse("cur_page2").unwrap();
        let json = serde_json::to_string(&c).unwrap();
        let back: Cursor = serde_json::from_str(&json).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn rejects_bad_cursor() {
        let err = Cursor::parse("page2").unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidId);
    }

    #[test]
    fn page_request_validates_limit() {
        let err = PageRequest {
            cursor: None,
            limit: 0,
        }
        .validated()
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        let err = PageRequest {
            cursor: None,
            limit: MAX_PAGE_LIMIT + 1,
        }
        .validated()
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::InvalidArgument);

        assert!(PageRequest::default().validated().is_ok());
    }
}
