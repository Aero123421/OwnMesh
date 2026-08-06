//! Configuration errors.

use ownmesh_domain::{DomainError, ErrorCode};
use std::fmt;
use std::path::PathBuf;

/// Errors produced while resolving, loading, or writing configuration.
#[derive(Debug)]
pub enum ConfigError {
    /// Filesystem failure.
    Io {
        /// Path related to the failure when known.
        path: Option<PathBuf>,
        /// Underlying IO error.
        source: std::io::Error,
    },
    /// TOML / JSON parse failure.
    Parse {
        /// Path being parsed.
        path: PathBuf,
        /// Parse message.
        message: String,
    },
    /// Schema / semantic validation failure.
    Validation {
        /// Field or rule that failed.
        message: String,
    },
    /// Unsupported or corrupt schema version.
    Migration {
        /// Explanation.
        message: String,
    },
    /// Generic configuration error.
    Other(String),
}

impl ConfigError {
    /// Map into the shared domain error taxonomy.
    #[must_use]
    pub fn to_domain_error(&self) -> DomainError {
        match self {
            Self::Io { path, source } => {
                let msg = match path {
                    Some(p) => format!("config io at {}: {source}", p.display()),
                    None => format!("config io: {source}"),
                };
                DomainError::new(ErrorCode::Config, msg)
            }
            Self::Parse { path, message } => DomainError::new(
                ErrorCode::SchemaValidation,
                format!("config parse {}: {message}", path.display()),
            ),
            Self::Validation { message } | Self::Migration { message } | Self::Other(message) => {
                DomainError::new(ErrorCode::Config, message.clone())
            }
        }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => match path {
                Some(p) => write!(f, "config io error at {}: {source}", p.display()),
                None => write!(f, "config io error: {source}"),
            },
            Self::Parse { path, message } => {
                write!(f, "config parse error at {}: {message}", path.display())
            }
            Self::Validation { message } => write!(f, "config validation error: {message}"),
            Self::Migration { message } => write!(f, "config migration error: {message}"),
            Self::Other(message) => write!(f, "config error: {message}"),
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ConfigError {
    fn from(source: std::io::Error) -> Self {
        Self::Io { path: None, source }
    }
}

/// Result alias for config operations.
pub type ConfigResult<T> = Result<T, ConfigError>;
