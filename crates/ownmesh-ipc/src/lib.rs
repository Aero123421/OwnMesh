//! `OwnMesh` local IPC transport (Named Pipe on Windows, Unix domain sockets elsewhere).
//!
//! Framing is 4-byte big-endian length + UTF-8 JSON-RPC 2.0. Peers authenticate via
//! **OS peer credentials** (Unix `SO_PEERCRED` / Windows named-pipe client PID+SID+exe)
//! with optional server-managed per-client non-shared credentials. Shared
//! `daemon.token` authentication is abolished. Self-reported HELLO `client_name`
//! is never a trusted principal input.

#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod auth;
mod client;
mod endpoint;
mod error;
mod frame;
mod registry;
mod rpc;
mod server;
mod transport;

pub use auth::{
    canonicalize_principal_key, constant_time_eq, current_os_user_id, generate_token,
    normalize_principal_part, read_token_file, redact_secrets, write_token_file, AuthGate,
    AuthResolution, ClientCredentialRecord, OsPeerIdentity, PeerCredential, RedactedSecret,
    AUTH_TOKEN_FILE_NAME,
};
pub use client::{ClientIdentity, ClientOptions, IpcClient};
pub use endpoint::{Endpoint, IpcBus};
pub use error::{IpcError, IpcResult};
pub use frame::{read_frame, write_frame, FrameDecoder, MAX_FRAME_BYTES};
pub use registry::{
    read_management_credential, BootstrapStatus, CLIENT_CREDENTIAL_ENV,
    MANAGEMENT_CREDENTIAL_FILE_NAME,
};
pub use rpc::{
    app_error, methods, CredentialClientParams, CredentialProvisionParams, CredentialSecretResult,
    DaemonStatus, HelloParams, HelloResult, RequestId, RpcErrorObject, RpcRequest, RpcResponse,
    JSONRPC_VERSION,
};
pub use server::{reject_unknown_handler, IpcServer, MethodHandler, RevokedClients, ServerConfig};
pub use transport::{connect, ClientConnection, LocalListener, ServerConnection};

/// Stable crate name used by diagnostics and tests.
#[must_use]
pub const fn crate_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

/// Crate version string from Cargo package metadata.
#[must_use]
pub const fn crate_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crate_metadata_is_stable() {
        assert_eq!(crate_name(), "ownmesh-ipc");
        assert!(!crate_version().is_empty());
    }
}
