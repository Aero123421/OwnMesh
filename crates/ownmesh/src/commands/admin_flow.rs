//! Shared fresh-passkey browser flow for typed device-admin commands.

use super::exec::{emit_mcp_error, emit_remote_terminal_failure, validate_remote_text};
use super::mcp_client::{McpClientError, McpHttpClient};
use crate::auth::SessionPaths;
use crate::cli::Cli;
use ownmesh_domain::{ErrorCode, ExitCode};
use serde_json::{json, Value};
use std::time::Duration;
use url::Url;

const ADMIN_ROUTE_WAIT: Duration = Duration::from_secs(60);
const APPROVAL_WAIT: Duration = Duration::from_secs(5 * 60);

pub(super) fn run_admin_operation(
    cli: &Cli,
    tool: &str,
    mut arguments: Value,
    success_message: &str,
    denied_is_success: bool,
) -> Result<(), ExitCode> {
    let session_paths = SessionPaths::discover().map_err(|error| {
        emit_mcp_error(
            cli,
            &McpClientError::new(ErrorCode::Config, format!("path error: {error}")),
        )
    })?;
    let session = session_paths.load_session().map_err(|error| {
        emit_mcp_error(
            cli,
            &McpClientError::new(ErrorCode::Config, format!("session error: {error}")),
        )
    })?;
    let device_id = session
        .device_id
        .as_deref()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            emit_mcp_error(
                cli,
                &McpClientError::new(
                    ErrorCode::Config,
                    "no current device is enrolled; run `ownmesh setup` or `ownmesh device add`",
                ),
            )
        })?
        .to_owned();
    validate_remote_text("current device id", &device_id, 256)
        .map_err(|message| emit_mcp_error(cli, &McpClientError::new(ErrorCode::Config, message)))?;
    arguments
        .as_object_mut()
        .ok_or_else(|| {
            emit_mcp_error(
                cli,
                &McpClientError::new(
                    ErrorCode::InvalidArgument,
                    "admin arguments must be an object",
                ),
            )
        })?
        .insert("device_id".into(), Value::String(device_id.clone()));
    let object = arguments.as_object_mut().expect("validated object");
    if object.get("idempotency_key").is_none_or(Value::is_null) {
        object.insert(
            "idempotency_key".into(),
            Value::String(format!("cli_{}", uuid::Uuid::new_v4().simple())),
        );
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            emit_mcp_error(
                cli,
                &McpClientError::new(ErrorCode::Internal, error.to_string()),
            )
        })?;
    let result = runtime.block_on(async {
        let mut client = McpHttpClient::from_configured_auth().await?;
        let initial = client
            .call_tool_until_terminal(tool, arguments, &device_id, ADMIN_ROUTE_WAIT)
            .await?;
        if initial.get("status").and_then(Value::as_str) != Some("approval_required") {
            return Ok((initial, None));
        }
        let operation_id = initial
            .get("operation_id")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                McpClientError::new(
                    ErrorCode::BadEnvelope,
                    "approval response omitted operation_id",
                )
            })?;
        let approval_url = initial
            .get("approval_url")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .ok_or_else(|| {
                McpClientError::new(
                    ErrorCode::BadEnvelope,
                    "approval response omitted approval_url",
                )
            })?;
        validate_approval_url(&session.issuer, &approval_url, operation_id)?;
        if cli.json {
            return Ok((initial, Some(approval_url)));
        }
        println!("fresh passkey approval required for operation {operation_id}");
        println!("{approval_url}");
        if let Err(error) = webbrowser::open(&approval_url) {
            eprintln!("could not open a browser ({error}); open the URL above on any device");
        } else {
            println!("browser opened; waiting for the signed decision (up to 5 minutes)…");
        }
        let settled = client
            .poll_after_approval(operation_id, &device_id, APPROVAL_WAIT)
            .await?;
        Ok((settled, None))
    });

    let (value, json_approval_url) =
        result.map_err(|error: McpClientError| emit_mcp_error(cli, &error))?;
    if cli.json {
        let terminal_ok = value.get("status").and_then(Value::as_str) == Some("completed")
            || (denied_is_success && value.get("status").and_then(Value::as_str) == Some("denied"));
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": terminal_ok,
                "tool": tool,
                "operation": value,
                "approval_url": json_approval_url,
            })
        );
        crate::commands::fail::note_envelope_emitted();
        return if json_approval_url.is_some() {
            Err(ExitCode::Authorization)
        } else if terminal_ok {
            Ok(())
        } else {
            Err(ExitCode::Internal)
        };
    }

    match value.get("status").and_then(Value::as_str) {
        Some("completed") => {
            println!("{success_message}");
            Ok(())
        }
        Some("denied") if denied_is_success => {
            println!("{success_message}");
            Ok(())
        }
        Some("approval_required") => Err(ExitCode::Authorization),
        _ => emit_remote_terminal_failure(cli, &value),
    }
}

fn validate_approval_url(
    issuer: &str,
    approval_url: &str,
    operation_id: &str,
) -> Result<(), McpClientError> {
    let expected =
        Url::parse(&format!("{}/approve", issuer.trim_end_matches('/'))).map_err(|_| {
            McpClientError::new(
                ErrorCode::Config,
                "configured issuer cannot form an approval URL",
            )
        })?;
    let actual = Url::parse(approval_url).map_err(|_| {
        McpClientError::new(
            ErrorCode::BadEnvelope,
            "control-plane returned an invalid approval URL",
        )
    })?;
    let query: Vec<_> = actual.query_pairs().collect();
    let same_endpoint = actual.scheme() == expected.scheme()
        && actual.host_str() == expected.host_str()
        && actual.port_or_known_default() == expected.port_or_known_default()
        && actual.path() == expected.path()
        && actual.username().is_empty()
        && actual.password().is_none()
        && actual.fragment().is_none();
    let exact_query =
        query.len() == 1 && query[0].0 == "operation_id" && query[0].1.as_ref() == operation_id;
    if !same_endpoint || !exact_query {
        return Err(McpClientError::new(
            ErrorCode::BadEnvelope,
            "control-plane approval URL is not exact-bound to the configured issuer and operation",
        ));
    }
    Ok(())
}
