//! Identity and keystore errors.

use ownmesh_domain::{DomainError, ErrorCode};
use std::fmt;

/// Errors from device key and secret storage operations.
#[derive(Debug)]
pub enum IdentityError {
    /// Underlying IO failure.
    Io(std::io::Error),
    /// OS keychain backend failure.
    Keychain(String),
    /// Encrypted keystore failure.
    Keystore(String),
    /// Cryptographic failure.
    Crypto(String),
    /// Requested secret was not found.
    NotFound(String),
    /// Caller provided invalid input.
    Invalid(String),
}

impl IdentityError {
    /// Map into the shared domain error taxonomy.
    #[must_use]
    pub fn to_domain_error(&self) -> DomainError {
        match self {
            Self::Io(err) => DomainError::new(ErrorCode::Internal, format!("identity io: {err}")),
            Self::Keychain(msg) | Self::Keystore(msg) => {
                DomainError::new(ErrorCode::Internal, msg.clone())
            }
            Self::Crypto(msg) => DomainError::new(ErrorCode::Internal, format!("crypto: {msg}")),
            Self::NotFound(msg) => DomainError::new(ErrorCode::Authentication, msg.clone()),
            Self::Invalid(msg) => DomainError::new(ErrorCode::InvalidArgument, msg.clone()),
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "identity io error: {err}"),
            Self::Keychain(msg) => write!(f, "keychain error: {msg}"),
            Self::Keystore(msg) => write!(f, "keystore error: {msg}"),
            Self::Crypto(msg) => write!(f, "crypto error: {msg}"),
            Self::NotFound(msg) => write!(f, "secret not found: {msg}"),
            Self::Invalid(msg) => write!(f, "invalid identity input: {msg}"),
        }
    }
}

impl std::error::Error for IdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IdentityError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

/// Result alias for identity operations.
pub type IdentityResult<T> = Result<T, IdentityError>;
