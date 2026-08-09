//! `OwnMesh` local IPC transport (Named Pipe on Windows, Unix domain sockets elsewhere).
//!
//! Framing is 4-byte big-endian length + UTF-8 JSON-RPC 2.0. Peers authenticate via
//! **OS peer credentials** (Unix `SO_PEERCRED` / Windows named-pipe client PID+SID+exe)
//! with optional server-managed per-client non-shared credentials. Shared
//! `daemon.token` authentication is abolished. Self-reported HELLO `client_name`
//! is never a trusted principal input.

#![allow(
    clippy::borrow_as_ptr,
    clippy::cast_possible_truncation,
    clippy::doc_markdown,
    clippy::items_after_statements,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::redundant_closure_for_method_calls,
    clippy::similar_names,
    clippy::single_match,
    clippy::single_match_else,
    clippy::too_many_lines,
    clippy::trivially_copy_pass_by_ref,
    clippy::unnecessary_wraps,
    clippy::unnested_or_patterns,
    clippy::unused_async
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
    human_operator_disabled_message, human_operator_method, is_credentialed_client_principal,
    is_human_os_principal, normalize_principal_part, read_token_file, redact_secrets,
    write_token_file, AuthGate, AuthResolution, ClientCredentialRecord, OsPeerIdentity,
    PeerCredential, RedactedSecret, AUTH_TOKEN_FILE_NAME,
};
pub use client::{ClientIdentity, ClientOptions, IpcClient};
pub use endpoint::{Endpoint, IpcBus};
pub use error::{IpcError, IpcResult};
pub use frame::{read_frame, write_frame, FrameDecoder, MAX_FRAME_BYTES};
pub use registry::{
    atomic_write_owner_only, create_owner_only_file_new, open_owner_only_file_append,
    open_owner_only_file_read, prepare_owner_only_state_dir, publish_owner_only_file_no_replace,
    read_management_credential, read_owner_only_file_bounded, remove_owner_only_file,
    BootstrapStatus, CLIENT_CREDENTIAL_ENV, MANAGEMENT_CREDENTIAL_FILE_NAME,
};
pub use rpc::{
    app_error, methods, CredentialClientParams, CredentialProvisionParams, CredentialSecretResult,
    DaemonStatus, HelloParams, HelloResult, RequestId, RpcErrorObject, RpcRequest, RpcResponse,
    JSONRPC_VERSION,
};
pub use server::{reject_unknown_handler, IpcServer, MethodHandler, RevokedClients, ServerConfig};
pub use transport::{connect, ClientConnection, LocalListener, ServerConnection};
#[cfg(windows)]
pub use transport::{
    windows_process_facts, windows_running_service_facts, WindowsPipePeerFacts,
    WindowsProcessFacts, WindowsServiceFacts,
};

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
