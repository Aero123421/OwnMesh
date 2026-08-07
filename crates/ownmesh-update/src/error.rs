//! Update error taxonomy.

use thiserror::Error;

/// Update errors (fail-closed).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum UpdateError {
    /// Automatic / background network access is disabled.
    #[error(
        "updates disabled (network off by default; set update.mode or run an explicit command)"
    )]
    Disabled,
    /// Signature verification failed.
    #[error("signature invalid")]
    BadSignature,
    /// Checksum mismatch.
    #[error("checksum mismatch")]
    BadChecksum,
    /// Unknown release channel.
    #[error("channel unknown: {0}")]
    UnknownChannel(String),
    /// Device protocol is outside the release's supported range.
    #[error("protocol incompatible: {0}")]
    ProtocolIncompatible(String),
    /// Target version would downgrade the installation.
    #[error("downgrade refused: {0}")]
    DowngradeRefused(String),
    /// Redirect or download host is not on the allow-list.
    #[error("redirect host refused: {0}")]
    RedirectHostRefused(String),
    /// Asset selection failed for this OS/arch.
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
    /// Required release metadata or asset is missing.
    #[error("release metadata missing: {0}")]
    MissingMetadata(String),
    /// Size / time budget exceeded.
    #[error("limit exceeded: {0}")]
    LimitExceeded(String),
    /// Archive failed safety checks (traversal, missing members, partial set).
    #[error("archive unsafe or incomplete: {0}")]
    UnsafeArchive(String),
    /// Install / apply failure.
    #[error("install failed: {0}")]
    Install(String),
    /// Homebrew-managed install must use brew.
    #[error("homebrew-managed install; run `brew upgrade ownmesh` instead of self-update")]
    HomebrewManaged,
    /// HTTP / IO transport failure (message is redacted by callers when needed).
    #[error("transport error: {0}")]
    Transport(String),
    /// Invalid user input or configuration.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Already up to date.
    #[error("already up to date ({0})")]
    AlreadyCurrent(String),
}

/// Result alias for update operations.
pub type UpdateResult<T> = Result<T, UpdateError>;
