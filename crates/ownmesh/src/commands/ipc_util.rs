//! Shared helpers for CLI ↔ ownmeshd IPC calls.

use crate::cli::Cli;
use crate::commands::fail::fail;
use ownmesh_config::{load_config, OwnMeshPaths};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{
    app_error, methods, ClientIdentity, ClientOptions, Endpoint, IpcClient, IpcError,
};
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
    build_daemon_client()
        .map_err(|(code, message, hint, exit)| fail(cli, code, message, hint, exit))
}

/// Stable diagnostics for a client-construction failure: code, message, hint,
/// exit status.
type DaemonClientError = (&'static str, String, Option<&'static str>, ExitCode);

/// Silent variant of [`connect_daemon`] for best-effort notifications where
/// emitting a failure envelope would corrupt the command's own output.
fn build_daemon_client() -> Result<(OwnMeshPaths, IpcClient), DaemonClientError> {
    let paths = OwnMeshPaths::discover().map_err(|err| {
        (
            "OWNMESH_E_CONFIG_PATH",
            format!("config path error: {err}"),
            None,
            ExitCode::UsageConfig,
        )
    })?;
    let _ = paths.ensure_layout();
    let cfg = load_config(&paths).map_err(|err| {
        (
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
                (
                    "OWNMESH_E_SERVICE_ENDPOINT",
                    format!("service endpoint configuration error: {err}"),
                    hint,
                    ExitCode::UsageConfig,
                )
            })?;
    Ok((
        paths.clone(),
        build_client(paths, endpoint, Duration::from_secs(60), 3).map_err(|message| {
            (
                "OWNMESH_E_CLIENT_CREDENTIAL",
                message,
                None,
                ExitCode::UsageConfig,
            )
        })?,
    ))
}

/// Pure read of `service_socket.path` (no lock, no recovery, no create).
fn configured_socket_path_readonly(paths: &OwnMeshPaths) -> Option<String> {
    let raw = std::fs::read_to_string(paths.config_file()).ok()?;
    let cfg: ownmesh_config::OwnMeshConfig = toml::from_str(&raw).ok()?;
    cfg.service_socket.path.clone()
}

/// Construct the IPC client (shared by the strict and probe builders).
fn build_client(
    paths: OwnMeshPaths,
    endpoint: Endpoint,
    request_timeout: Duration,
    max_reconnect_attempts: u32,
) -> Result<IpcClient, String> {
    IpcClient::new(
        endpoint,
        paths.runtime_dir.clone(),
        ClientIdentity::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
        ClientOptions {
            request_timeout,
            max_reconnect_attempts,
            reconnect_base_delay: Duration::from_millis(20),
        },
    )
    .with_client_credential_from_env_or_management_file(&paths.state_dir)
    .map_err(|err| format!("client credential configuration error: {err}"))
}

/// Issue #248: bounded read-only probe of the daemon's live Agent route for
/// display surfaces (`doctor`, `service status`). Returns `None` when the
/// daemon is unreachable, the client cannot be built, the probe times out, or
/// the route is not one of the known states — never fails the caller and never
/// mutates the local layout.
pub fn observe_agent_route(timeout: Duration) -> Option<String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .ok()?;
    rt.block_on(async {
        let probe = async {
            let client = build_daemon_probe_client(timeout)?;
            let value = client.call(methods::ROUTE_STATUS, None).await.ok()?;
            value
                .get("route")
                .and_then(Value::as_str)
                .filter(|route| matches!(*route, "online" | "offline" | "disabled" | "unknown"))
                .map(str::to_owned)
        };
        // The request timeout does not cover dial/hello, so bound the whole
        // probe. Display surfaces must never hang on a wedged daemon.
        tokio::time::timeout(timeout, probe).await.ok().flatten()
    })
}

/// Build a client for read-only probes without creating or migrating local
/// state (`ensure_layout` / blocking config lock are deliberately skipped).
fn build_daemon_probe_client(request_timeout: Duration) -> Option<IpcClient> {
    let paths = OwnMeshPaths::discover().ok()?;
    let socket_path = configured_socket_path_readonly(&paths);
    let endpoint = Endpoint::configured_daemon(&paths.runtime_dir, socket_path.as_deref()).ok()?;
    build_client(paths, endpoint, request_timeout, 1).ok()
}

/// Issue #248: ask a running daemon to re-read the enrolled device credential.
///
/// Best-effort by design: `device enroll` has already succeeded and must not
/// fail or print an error envelope just because the user service is stopped
/// (a later service start reads the credential at boot). Never sends or
/// returns secret material.
pub async fn notify_running_daemon_agent_reload() {
    // Bounded end-to-end: client construction is a pure read and the whole
    // request (including dial/hello) is wrapped, so a wedged daemon cannot
    // delay the CLI's already-printed success.
    let Some(client) = build_daemon_probe_client(Duration::from_secs(2)) else {
        return;
    };
    let _ = tokio::time::timeout(
        Duration::from_secs(2),
        client.call(methods::AGENT_RELOAD, None),
    )
    .await;
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
