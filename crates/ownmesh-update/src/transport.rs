//! HTTP transport abstraction and host allow-list policy.

use crate::error::{UpdateError, UpdateResult};
use crate::limits::{
    DOWNLOAD_TIMEOUT_SECS, MAX_ARCHIVE_BYTES, MAX_CHECKSUMS_BYTES, MAX_METADATA_BYTES,
    MAX_RELEASE_META_BYTES, MAX_SIGNATURE_BYTES, METADATA_TIMEOUT_SECS,
};
use crate::redaction::redact_url;
use std::collections::BTreeMap;
use std::time::Duration;

/// Allowed download / redirect hosts (fail-closed).
pub const ALLOWED_HOSTS: &[&str] = &[
    "github.com",
    "api.github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
];

/// Kind of fetch for size / timeout budgets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchKind {
    /// GitHub release JSON.
    Metadata,
    /// `SHA256SUMS`.
    Checksums,
    /// `SHA256SUMS.minisig`.
    Signature,
    /// `ownmesh-release-meta.json`.
    ReleaseMeta,
    /// Portable archive.
    Archive,
}

impl FetchKind {
    /// Maximum accepted response body size.
    #[must_use]
    pub const fn max_bytes(self) -> u64 {
        match self {
            Self::Metadata => MAX_METADATA_BYTES,
            Self::Checksums => MAX_CHECKSUMS_BYTES,
            Self::Signature => MAX_SIGNATURE_BYTES,
            Self::ReleaseMeta => MAX_RELEASE_META_BYTES,
            Self::Archive => MAX_ARCHIVE_BYTES,
        }
    }

    /// Suggested timeout.
    #[must_use]
    pub const fn timeout(self) -> Duration {
        match self {
            Self::Archive => Duration::from_secs(DOWNLOAD_TIMEOUT_SECS),
            _ => Duration::from_secs(METADATA_TIMEOUT_SECS),
        }
    }
}

/// A single HTTP GET.
#[derive(Debug, Clone)]
pub struct FetchRequest {
    /// Absolute HTTPS URL.
    pub url: String,
    /// Budget class.
    pub kind: FetchKind,
    /// Optional extra headers (never log secret values).
    pub headers: BTreeMap<String, String>,
}

/// Successful GET body.
#[derive(Debug, Clone)]
pub struct FetchResponse {
    /// Final URL after redirects (still host-checked by the client).
    pub final_url: String,
    /// Response body.
    pub body: Vec<u8>,
}

/// Pluggable HTTPS client used by the update engine.
pub trait HttpTransport {
    /// Perform a GET with size/time limits and host policy.
    ///
    /// # Errors
    ///
    /// Returns transport / policy errors.
    fn fetch(&self, request: &FetchRequest) -> UpdateResult<FetchResponse>;
}

/// Validate that `raw_url` is HTTPS and targets an allowed host.
///
/// # Errors
///
/// Returns [`UpdateError::RedirectHostRefused`] or [`UpdateError::InvalidArgument`].
pub fn validate_url_host(raw_url: &str) -> UpdateResult<url::Url> {
    let url = url::Url::parse(raw_url).map_err(|err| {
        UpdateError::InvalidArgument(format!("invalid URL '{}': {err}", redact_url(raw_url)))
    })?;
    if url.scheme() != "https" {
        return Err(UpdateError::RedirectHostRefused(format!(
            "refusing non-https URL {}",
            redact_url(raw_url)
        )));
    }
    if url.username() != "" || url.password().is_some() {
        return Err(UpdateError::RedirectHostRefused(format!(
            "refusing URL with userinfo {}",
            redact_url(raw_url)
        )));
    }
    let host = url
        .host_str()
        .ok_or_else(|| UpdateError::RedirectHostRefused("URL missing host".into()))?;
    if !host_allowed(host) {
        return Err(UpdateError::RedirectHostRefused(host.to_owned()));
    }
    Ok(url)
}

/// True when `host` is on the release CDN allow-list.
#[must_use]
pub fn host_allowed(host: &str) -> bool {
    let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
    ALLOWED_HOSTS
        .iter()
        .any(|allowed| host == *allowed || host.ends_with(&format!(".{allowed}")))
}

/// In-memory transport for unit tests.
#[derive(Debug, Default, Clone)]
pub struct MapTransport {
    /// Exact URL → body mapping.
    pub bodies: BTreeMap<String, Vec<u8>>,
    /// Optional redirect map (request URL → final URL used for lookup).
    pub redirects: BTreeMap<String, String>,
}

impl MapTransport {
    /// Insert a UTF-8 body.
    #[must_use]
    pub fn with_text(mut self, url: impl Into<String>, body: impl Into<String>) -> Self {
        self.bodies.insert(url.into(), body.into().into_bytes());
        self
    }

    /// Insert raw bytes.
    #[must_use]
    pub fn with_bytes(mut self, url: impl Into<String>, body: Vec<u8>) -> Self {
        self.bodies.insert(url.into(), body);
        self
    }
}

impl HttpTransport for MapTransport {
    fn fetch(&self, request: &FetchRequest) -> UpdateResult<FetchResponse> {
        validate_url_host(&request.url)?;
        let final_url = self
            .redirects
            .get(&request.url)
            .cloned()
            .unwrap_or_else(|| request.url.clone());
        validate_url_host(&final_url)?;
        let body =
            self.bodies.get(&final_url).cloned().ok_or_else(|| {
                UpdateError::Transport(format!("404 for {}", redact_url(&final_url)))
            })?;
        if body.len() as u64 > request.kind.max_bytes() {
            return Err(UpdateError::LimitExceeded(format!(
                "{} exceeded {} bytes",
                redact_url(&final_url),
                request.kind.max_bytes()
            )));
        }
        Ok(FetchResponse { final_url, body })
    }
}
