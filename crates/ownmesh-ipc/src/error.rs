//! IPC error types mapped onto the OwnMesh domain taxonomy.

use ownmesh_domain::{DomainError, ErrorCode};
use std::fmt;

/// Errors raised by the local IPC stack.
#[derive(Debug)]
pub enum IpcError {
    /// I/O failure on the underlying transport.
    Io(std::io::Error),
    /// Framing (length prefix / UTF-8) failure.
    Framing(String),
    /// JSON codec failure.
    Codec(String),
    /// Peer failed authentication / ACL checks.
    Unauthorized(String),
    /// Request exceeded its deadline.
    Timeout,
    /// Request was cancelled by the caller.
    Cancelled,
    /// Remote JSON-RPC error payload.
    Remote {
        /// JSON-RPC error code.
        code: i64,
        /// Human-readable message (never contains secrets).
        message: String,
    },
    /// Local protocol / usage error.
    Protocol(String),
    /// Endpoint is not currently reachable (daemon down, reconnect exhausted).
    Disconnected(String),
}

impl IpcError {
    /// Convert into a stable domain error.
    #[must_use]
    pub fn to_domain_error(&self) -> DomainError {
        match self {
            Self::Io(err) => DomainError::new(ErrorCode::Internal, format!("ipc io: {err}")),
            Self::Framing(msg) | Self::Codec(msg) | Self::Protocol(msg) => {
                DomainError::new(ErrorCode::BadEnvelope, msg.clone())
            }
            Self::Unauthorized(msg) => DomainError::new(ErrorCode::Authentication, msg.clone()),
            Self::Timeout => DomainError::new(ErrorCode::Timeout, "ipc request timed out"),
            Self::Cancelled => DomainError::new(ErrorCode::Cancelled, "ipc request cancelled"),
            Self::Remote { code, message } => DomainError::new(
                ErrorCode::Internal,
                format!("remote ipc error {code}: {message}"),
            ),
            Self::Disconnected(msg) => DomainError::new(ErrorCode::DeviceOffline, msg.clone()),
        }
    }

    /// Stable error code string for logs and tests.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Io(_) => "ipc_io",
            Self::Framing(_) => "ipc_framing",
            Self::Codec(_) => "ipc_codec",
            Self::Unauthorized(_) => "ipc_unauthorized",
            Self::Timeout => "ipc_timeout",
            Self::Cancelled => "ipc_cancelled",
            Self::Remote { .. } => "ipc_remote",
            Self::Protocol(_) => "ipc_protocol",
            Self::Disconnected(_) => "ipc_disconnected",
        }
    }
}

impl fmt::Display for IpcError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "ipc io error: {err}"),
            Self::Framing(msg) => write!(f, "ipc framing error: {msg}"),
            Self::Codec(msg) => write!(f, "ipc codec error: {msg}"),
            Self::Unauthorized(msg) => write!(f, "ipc unauthorized: {msg}"),
            Self::Timeout => f.write_str("ipc timeout"),
            Self::Cancelled => f.write_str("ipc cancelled"),
            Self::Remote { code, message } => {
                write!(f, "ipc remote error {code}: {message}")
            }
            Self::Protocol(msg) => write!(f, "ipc protocol error: {msg}"),
            Self::Disconnected(msg) => write!(f, "ipc disconnected: {msg}"),
        }
    }
}

impl std::error::Error for IpcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IpcError {
    fn from(value: std::io::Error) -> Self {
        Self::Io(value)
    }
}

impl From<serde_json::Error> for IpcError {
    fn from(value: serde_json::Error) -> Self {
        Self::Codec(value.to_string())
    }
}

/// Result alias for IPC operations.
pub type IpcResult<T> = Result<T, IpcError>;
