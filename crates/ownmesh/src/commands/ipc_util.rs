//! Shared helpers for CLI ↔ ownmeshd IPC calls.

use ownmesh_config::OwnMeshPaths;
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{
    app_error, ClientIdentity, ClientOptions, Endpoint, IpcBus, IpcClient, IpcError,
};
use serde_json::Value;
use std::time::Duration;

/// Build a short-lived client targeting the local daemon.
pub fn connect_daemon() -> Result<(OwnMeshPaths, IpcClient), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("config path error: {err}");
        ExitCode::UsageConfig
    })?;
    let _ = paths.ensure_layout();
    let endpoint = Endpoint::default_for(&paths.runtime_dir, IpcBus::Daemon);
    let client = IpcClient::new(
        endpoint,
        paths.runtime_dir.clone(),
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout: Duration::from_secs(60),
            max_reconnect_attempts: 3,
            reconnect_base_delay: Duration::from_millis(50),
        },
    );
    Ok((paths, client))
}

/// Map IPC errors onto CLI exit codes.
pub fn map_ipc_err(err: IpcError) -> ExitCode {
    match &err {
        IpcError::Unauthorized(_) => {
            eprintln!("authentication failed: {err}");
            ExitCode::Authentication
        }
        IpcError::Remote { code, message } if *code == app_error::POLICY_DENIED => {
            eprintln!("policy denied: {message}");
            ExitCode::Authorization
        }
        IpcError::Remote { code, message } if *code == app_error::LOCKDOWN => {
            eprintln!("lockdown: {message}");
            ExitCode::Authorization
        }
        IpcError::Remote { code, message } if *code == app_error::TOKEN_REVOKED => {
            eprintln!("token revoked: {message}");
            ExitCode::Authorization
        }
        IpcError::Remote { code, message } if *code == app_error::CONFLICT => {
            eprintln!("conflict: {message}");
            ExitCode::Conflict
        }
        IpcError::Timeout | IpcError::Cancelled => {
            eprintln!("{err}");
            ExitCode::TimeoutCancelled
        }
        IpcError::Disconnected(msg) => {
            eprintln!("failed to reach ownmeshd: {msg}");
            eprintln!("hint: start the daemon with `ownmeshd run`");
            ExitCode::DeviceOffline
        }
        other => {
            eprintln!("ipc error: {other}");
            ExitCode::Internal
        }
    }
}

/// Call a daemon method on a fresh runtime.
pub fn call_daemon(method: &str, params: Option<Value>) -> Result<Value, ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            eprintln!("failed to start async runtime: {err}");
            ExitCode::Internal
        })?;
    rt.block_on(async {
        let (_paths, client) = connect_daemon()?;
        client.call(method, params).await.map_err(map_ipc_err)
    })
}

/// Print a JSON value or a human one-liner summary.
pub fn print_value(json_mode: bool, value: &Value, human: impl FnOnce(&Value)) {
    if json_mode {
        println!("{value}");
    } else {
        human(value);
    }
}
