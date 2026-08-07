//! Shared helpers for CLI ↔ ownmeshd IPC calls.

use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{app_error, ClientIdentity, ClientOptions, Endpoint, IpcClient, IpcError};
use serde_json::Value;
use std::time::Duration;

/// Build a short-lived client targeting the local daemon.
pub fn connect_daemon() -> Result<(OwnMeshPaths, IpcClient), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        eprintln!("config path error: {err}");
        ExitCode::UsageConfig
    })?;
    let _ = paths.ensure_layout();
    let cfg = load_config(&paths).map_err(|err| {
        eprintln!("config load error: {err}");
        ExitCode::UsageConfig
    })?;
    let endpoint =
        Endpoint::configured_daemon(&paths.runtime_dir, cfg.service_socket.path.as_deref())
            .map_err(|err| {
                eprintln!("service endpoint configuration error: {err}");
                ExitCode::UsageConfig
            })?;
    let client = IpcClient::new(
        endpoint,
        paths.runtime_dir.clone(),
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout: Duration::from_secs(60),
            max_reconnect_attempts: 3,
            reconnect_base_delay: Duration::from_millis(50),
        },
    )
    .with_client_credential_from_env()
    .map_err(|err| {
        eprintln!("client credential configuration error: {err}");
        ExitCode::UsageConfig
    })?;
    Ok((paths, client))
}

/// Map IPC errors onto CLI exit codes.
pub fn map_ipc_err(err: IpcError) -> ExitCode {
    match &err {
        IpcError::Unauthorized(_)
        | IpcError::Remote {
            code: app_error::UNAUTHORIZED,
            ..
        } => {
            eprintln!("authentication failed: {err}");
            eprintln!(
                "hint: provision this cooperative client through the running daemon and set {}",
                ownmesh_ipc::CLIENT_CREDENTIAL_ENV
            );
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_unauthorized_maps_to_authentication_failure() {
        assert_eq!(
            map_ipc_err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "credential required".into(),
            }),
            ExitCode::Authentication
        );
    }
}
