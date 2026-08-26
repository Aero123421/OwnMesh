//! Shared helpers for CLI ↔ ownmeshd IPC calls.

use crate::cli::Cli;
use crate::commands::fail::fail;
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{app_error, ClientIdentity, ClientOptions, Endpoint, IpcClient, IpcError};
use serde_json::Value;
use std::time::Duration;

/// Hint shown whenever the local daemon cannot be reached.
///
/// Points at the supported user-level service lifecycle rather than the raw
/// foreground `ownmeshd run`, which is not how the docs tell users to start it.
pub const DAEMON_OFFLINE_HINT: &str =
    "start it with `ownmesh service start` (or `ownmesh service install` if it is not installed yet)";

/// Build a short-lived client targeting the local daemon.
pub fn connect_daemon(cli: &Cli) -> Result<(OwnMeshPaths, IpcClient), ExitCode> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        fail(
            cli,
            "OWNMESH_E_CONFIG_PATH",
            format!("config path error: {err}"),
            None,
            ExitCode::UsageConfig,
        )
    })?;
    let _ = paths.ensure_layout();
    let cfg = load_config(&paths).map_err(|err| {
        fail(
            cli,
            "OWNMESH_E_CONFIG_LOAD",
            format!("config load error: {err}"),
            Some("run `ownmesh config validate` to see what is wrong"),
            ExitCode::UsageConfig,
        )
    })?;
    let endpoint =
        Endpoint::configured_daemon(&paths.runtime_dir, cfg.service_socket.path.as_deref())
            .map_err(|err| {
                let hint = if err.to_string().contains("SUN_LEN") {
                    Some(
                        "the socket path is too long; set a shorter one with \
                         `ownmesh config set service_socket.path <path>`",
                    )
                } else {
                    None
                };
                fail(
                    cli,
                    "OWNMESH_E_SERVICE_ENDPOINT",
                    format!("service endpoint configuration error: {err}"),
                    hint,
                    ExitCode::UsageConfig,
                )
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
    .with_client_credential_from_env_or_management_file(&paths.state_dir)
    .map_err(|err| {
        fail(
            cli,
            "OWNMESH_E_CLIENT_CREDENTIAL",
            format!("client credential configuration error: {err}"),
            None,
            ExitCode::UsageConfig,
        )
    })?;
    Ok((paths, client))
}

/// Classify an IPC error into a stable code, message, hint, and exit status.
///
/// Split out from emission so both the text and JSON renderings stay in sync
/// and the mapping can be unit-tested without capturing output.
fn classify_ipc_err(err: &IpcError) -> (&'static str, String, Option<&'static str>, ExitCode) {
    const CREDENTIAL_HINT: &str = concat!(
        "restart `ownmesh service` to restore the owner-only cooperative credential, ",
        "or set OWNMESH_CLIENT_CREDENTIAL explicitly",
    );
    match err {
        IpcError::Unauthorized(_)
        | IpcError::Remote {
            code: app_error::UNAUTHORIZED,
            ..
        } => (
            "OWNMESH_E_AUTHENTICATION",
            format!("authentication failed: {err}"),
            Some(CREDENTIAL_HINT),
            ExitCode::Authentication,
        ),
        IpcError::Remote { code, message } if *code == app_error::POLICY_DENIED => (
            "OWNMESH_E_POLICY_DENIED",
            format!("policy denied: {message}"),
            Some("inspect the decision with `ownmesh policy explain <operation>`"),
            ExitCode::Authorization,
        ),
        IpcError::Remote { code, message } if *code == app_error::EXECUTABLE_IDENTITY_DRIFT => (
            "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT",
            format!("executable identity changed: {message}"),
            Some("submit the exact command again to request fresh authorization"),
            ExitCode::Authorization,
        ),
        IpcError::Remote { code, message } if *code == app_error::LOCKDOWN => (
            "OWNMESH_E_LOCKDOWN",
            format!("lockdown: {message}"),
            Some("lift it with `ownmesh unlock`"),
            ExitCode::Authorization,
        ),
        IpcError::Remote { code, message } if *code == app_error::TOKEN_REVOKED => (
            "OWNMESH_E_TOKEN_REVOKED",
            format!("token revoked: {message}"),
            None,
            ExitCode::Authorization,
        ),
        IpcError::Remote { code, message } if *code == app_error::CONFLICT => (
            "OWNMESH_E_CONFLICT",
            format!("conflict: {message}"),
            None,
            ExitCode::Conflict,
        ),
        IpcError::Timeout | IpcError::Cancelled => (
            "OWNMESH_E_TIMEOUT_CANCELLED",
            err.to_string(),
            None,
            ExitCode::TimeoutCancelled,
        ),
        IpcError::Disconnected(msg) => (
            "OWNMESH_E_DEVICE_OFFLINE",
            format!("failed to reach ownmeshd: {msg}"),
            Some(DAEMON_OFFLINE_HINT),
            ExitCode::DeviceOffline,
        ),
        other => (
            "OWNMESH_E_INTERNAL",
            format!("ipc error: {other}"),
            None,
            ExitCode::Internal,
        ),
    }
}

/// Map IPC errors onto CLI exit codes, emitting the canonical failure envelope.
pub fn map_ipc_err(cli: &Cli, err: IpcError) -> ExitCode {
    let (code, message, hint, exit) = classify_ipc_err(&err);
    fail(cli, code, message, hint, exit)
}

/// Like [`call_daemon`], but does not emit a failure envelope.
///
/// For callers with a documented fallback (for example `policy show` reading
/// the local file when the daemon is offline). Emitting eagerly there printed
/// an `ok: false` envelope immediately before the successful fallback payload,
/// leaving two JSON objects on stdout and a zero exit status. A caller that
/// cannot recover must emit the failure itself via [`emit_ipc_err`].
pub fn call_daemon_recoverable(
    cli: &Cli,
    method: &str,
    params: Option<Value>,
) -> Result<Value, IpcError> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| IpcError::Protocol(format!("failed to start async runtime: {err}")))?;
    rt.block_on(async {
        let (_paths, client) = connect_daemon(cli)
            .map_err(|_| IpcError::Protocol("local daemon endpoint is not usable".to_string()))?;
        client.call(method, params).await
    })
}

/// Exit code an IPC error maps to, without printing anything.
#[must_use]
pub fn ipc_exit_code(err: &IpcError) -> ExitCode {
    classify_ipc_err(err).3
}

/// Emit an IPC failure that the caller could not recover from.
pub fn emit_ipc_err(cli: &Cli, err: &IpcError) -> ExitCode {
    let (code, message, hint, exit) = classify_ipc_err(err);
    fail(cli, code, message, hint, exit)
}

/// Call a daemon method on a fresh runtime.
pub fn call_daemon(cli: &Cli, method: &str, params: Option<Value>) -> Result<Value, ExitCode> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            fail(
                cli,
                "OWNMESH_E_INTERNAL",
                format!("failed to start async runtime: {err}"),
                None,
                ExitCode::Internal,
            )
        })?;
    rt.block_on(async {
        let (_paths, client) = connect_daemon(cli)?;
        client
            .call(method, params)
            .await
            .map_err(|err| map_ipc_err(cli, err))
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
        let (code, _, hint, exit) = classify_ipc_err(&IpcError::Remote {
            code: app_error::UNAUTHORIZED,
            message: "credential required".into(),
        });
        assert_eq!(exit, ExitCode::Authentication);
        assert_eq!(code, "OWNMESH_E_AUTHENTICATION");
        assert!(hint.is_some());
    }

    #[test]
    fn disconnected_points_at_the_supported_service_lifecycle() {
        let (code, message, hint, exit) =
            classify_ipc_err(&IpcError::Disconnected("socket missing".into()));
        assert_eq!(exit, ExitCode::DeviceOffline);
        assert_eq!(code, "OWNMESH_E_DEVICE_OFFLINE");
        assert!(message.contains("failed to reach ownmeshd"));
        let hint = hint.expect("offline hint");
        assert!(hint.contains("ownmesh service start"), "{hint}");
        assert!(
            !hint.contains("ownmeshd run"),
            "hint must not steer users to the raw foreground command: {hint}"
        );
    }

    #[test]
    fn executable_identity_drift_maps_to_fresh_authorization() {
        let (code, message, hint, exit) = classify_ipc_err(&IpcError::Remote {
            code: app_error::EXECUTABLE_IDENTITY_DRIFT,
            message: "identity changed".into(),
        });
        assert_eq!(code, "OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT");
        assert_eq!(exit, ExitCode::Authorization);
        assert!(message.contains("identity changed"));
        assert!(hint.is_some_and(|value| value.contains("fresh authorization")));
    }

    #[test]
    fn every_classified_code_is_namespaced() {
        for err in [
            IpcError::Timeout,
            IpcError::Cancelled,
            IpcError::Unauthorized("no".into()),
            IpcError::Disconnected("gone".into()),
            IpcError::Remote {
                code: app_error::CONFLICT,
                message: "stale".into(),
            },
            IpcError::Remote {
                code: app_error::POLICY_DENIED,
                message: "denied".into(),
            },
            IpcError::Remote {
                code: app_error::LOCKDOWN,
                message: "locked".into(),
            },
            IpcError::Remote {
                code: app_error::TOKEN_REVOKED,
                message: "revoked".into(),
            },
            IpcError::Remote {
                code: app_error::EXECUTABLE_IDENTITY_DRIFT,
                message: "changed".into(),
            },
        ] {
            let (code, message, _, _) = classify_ipc_err(&err);
            assert!(code.starts_with("OWNMESH_E_"), "{code}");
            assert!(!message.is_empty());
        }
    }
}
