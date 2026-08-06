//! JSON-RPC 2.0 message types used on the local IPC bus.

use crate::error::{IpcError, IpcResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

/// JSON-RPC 2.0 version marker.
pub const JSONRPC_VERSION: &str = "2.0";

/// Well-known local IPC methods.
pub mod methods {
    /// Handshake / authentication.
    pub const HELLO: &str = "ipc.hello";
    /// Daemon status snapshot.
    pub const STATUS: &str = "daemon.status";
    /// Graceful ping used by reconnect probes.
    pub const PING: &str = "ipc.ping";

    /// Structured / raw command execution (policy-gated).
    pub const OPS_EXEC: &str = "ops.exec";
    /// Filesystem list.
    pub const OPS_FS_LIST: &str = "ops.fs.list";
    /// Filesystem stat.
    pub const OPS_FS_STAT: &str = "ops.fs.stat";
    /// Filesystem read.
    pub const OPS_FS_READ: &str = "ops.fs.read";
    /// Filesystem write.
    pub const OPS_FS_WRITE: &str = "ops.fs.write";
    /// Filesystem delete.
    pub const OPS_FS_DELETE: &str = "ops.fs.delete";
    /// Log query.
    pub const OPS_LOGS_QUERY: &str = "ops.logs.query";

    /// List pending / recent approvals.
    pub const APPROVAL_LIST: &str = "approval.list";
    /// Show one approval.
    pub const APPROVAL_SHOW: &str = "approval.show";
    /// Approve a pending request (may execute + temporary grant).
    pub const APPROVAL_APPROVE: &str = "approval.approve";
    /// Deny a pending request.
    pub const APPROVAL_DENY: &str = "approval.deny";

    /// Show effective policy.
    pub const POLICY_SHOW: &str = "policy.show";
    /// Select built-in preset.
    pub const POLICY_PRESET: &str = "policy.preset";
    /// Validate policy document.
    pub const POLICY_VALIDATE: &str = "policy.validate";
    /// Explain a decision for facts.
    pub const POLICY_EXPLAIN: &str = "policy.explain";

    /// Emergency lockdown (deny new ops; local unlock remains).
    pub const DAEMON_LOCKDOWN: &str = "daemon.lockdown";
    /// Lift lockdown.
    pub const DAEMON_UNLOCK: &str = "daemon.unlock";
    /// Revoke a local token / client label.
    pub const TOKEN_REVOKE: &str = "token.revoke";
}

/// Correlation identifier for a single request/response pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RequestId {
    /// String form (preferred; UUID).
    String(String),
    /// Numeric form accepted for compatibility.
    Number(i64),
}

impl RequestId {
    /// Fresh random string id.
    #[must_use]
    pub fn fresh() -> Self {
        Self::String(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for RequestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::String(s) => f.write_str(s),
            Self::Number(n) => write!(f, "{n}"),
        }
    }
}

/// Outgoing or incoming JSON-RPC request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcRequest {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Correlation id.
    pub id: RequestId,
    /// Method name.
    pub method: String,
    /// Optional params object/array.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl RpcRequest {
    /// Build a request with fresh id.
    #[must_use]
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id: RequestId::fresh(),
            method: method.into(),
            params,
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> IpcResult<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> IpcResult<Self> {
        let req: Self = serde_json::from_slice(bytes)?;
        if req.jsonrpc != JSONRPC_VERSION {
            return Err(IpcError::Protocol(format!(
                "unsupported jsonrpc version: {}",
                req.jsonrpc
            )));
        }
        Ok(req)
    }
}

/// JSON-RPC error object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcErrorObject {
    /// Numeric JSON-RPC error code.
    pub code: i64,
    /// Safe message (no secrets).
    pub message: String,
    /// Optional structured details.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// JSON-RPC response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RpcResponse {
    /// Must be `"2.0"`.
    pub jsonrpc: String,
    /// Correlation id mirrored from the request.
    pub id: RequestId,
    /// Successful result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error payload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
}

impl RpcResponse {
    /// Successful response.
    #[must_use]
    pub fn success(id: RequestId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Error response.
    #[must_use]
    pub fn failure(id: RequestId, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_owned(),
            id,
            result: None,
            error: Some(RpcErrorObject {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }

    /// Serialize to JSON bytes.
    pub fn to_bytes(&self) -> IpcResult<Vec<u8>> {
        Ok(serde_json::to_vec(self)?)
    }

    /// Parse from JSON bytes.
    pub fn from_bytes(bytes: &[u8]) -> IpcResult<Self> {
        let resp: Self = serde_json::from_slice(bytes)?;
        if resp.jsonrpc != JSONRPC_VERSION {
            return Err(IpcError::Protocol(format!(
                "unsupported jsonrpc version: {}",
                resp.jsonrpc
            )));
        }
        Ok(resp)
    }

    /// Extract result or map remote error.
    pub fn into_result(self) -> IpcResult<Value> {
        if let Some(err) = self.error {
            return Err(IpcError::Remote {
                code: err.code,
                message: err.message,
            });
        }
        self.result
            .ok_or_else(|| IpcError::Protocol("response missing result and error".into()))
    }
}

/// Parameters for `ipc.hello`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloParams {
    /// Shared daemon token from the runtime directory.
    pub token: String,
    /// Client process label (`ownmesh`, `ownmesh-tui`, …).
    pub client_name: String,
    /// Optional client version string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_version: Option<String>,
}

/// Successful hello acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloResult {
    /// Server protocol revision for local IPC.
    pub server_name: String,
    /// Server package version.
    pub server_version: String,
    /// Authenticated peer accepted.
    pub authenticated: bool,
}

/// Daemon status payload returned by `daemon.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonStatus {
    /// Daemon package version.
    pub version: String,
    /// Process id of the daemon.
    pub pid: u32,
    /// High-level lifecycle state.
    pub state: String,
    /// Endpoint path or pipe name currently served.
    pub endpoint: String,
    /// Monotonic uptime seconds since start.
    pub uptime_secs: u64,
}

/// JSON-RPC application error codes (local IPC).
pub mod app_error {
    /// Peer failed authentication.
    pub const UNAUTHORIZED: i64 = -32_000;
    /// Method not found.
    pub const METHOD_NOT_FOUND: i64 = -32_601;
    /// Invalid params.
    pub const INVALID_PARAMS: i64 = -32_602;
    /// Internal error.
    pub const INTERNAL: i64 = -32_603;
    /// Policy deny.
    pub const POLICY_DENIED: i64 = -32_010;
    /// Emergency lockdown active.
    pub const LOCKDOWN: i64 = -32_011;
    /// Token / client revoked.
    pub const TOKEN_REVOKED: i64 = -32_012;
    /// Conflict (e.g. approval already decided).
    pub const CONFLICT: i64 = -32_013;
}
