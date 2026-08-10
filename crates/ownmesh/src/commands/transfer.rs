//! `ownmesh transfer` — typed CLI façade for the public control-plane MCP contract.
//!
//! The CLI deliberately calls the same `ownmesh_transfer_*` tools as remote MCP
//! clients.  It never falls back to local daemon transfer internals, which are
//! Agent-only custody/data-plane operations rather than a cross-device API.

use crate::auth::{load_access_token, open_secret_store, resolve_issuer, SessionPaths};
use crate::cli::{Cli, TransferCmd};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};
use std::time::Duration;

const MAX_TEXT_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;

pub fn dispatch_transfer(cli: &Cli, cmd: &TransferCmd) -> Result<(), ExitCode> {
    let (tool, args) = match cmd {
        TransferCmd::Plan {
            source,
            dest,
            source_device,
            destination_device,
            source_workspace,
            destination_workspace,
            idempotency_key,
            ttl_seconds,
        } => {
            validate_path("source", source)?;
            validate_path("destination", dest)?;
            for (name, value) in [
                ("source-device", source_device),
                ("destination-device", destination_device),
                ("source-workspace", source_workspace),
                ("destination-workspace", destination_workspace),
                ("idempotency-key", idempotency_key),
            ] {
                validate_text(name, value)?;
            }
            (
                "ownmesh_transfer_plan",
                json!({
                    "source_device_id": source_device,
                    "destination_device_id": destination_device,
                    "source_workspace_id": source_workspace,
                    "destination_workspace_id": destination_workspace,
                    "source_path": source,
                    "destination_path": dest,
                    "idempotency_key": idempotency_key,
                    "ttl_seconds": ttl_seconds,
                }),
            )
        }
        TransferCmd::Send {
            id,
            idempotency_key,
        } => {
            validate_text("transfer id", id)?;
            validate_text("idempotency-key", idempotency_key)?;
            (
                "ownmesh_transfer_send",
                json!({ "transfer_id": id, "idempotency_key": idempotency_key }),
            )
        }
        TransferCmd::List { cursor, limit } => {
            if let Some(cursor) = cursor {
                validate_text("cursor", cursor)?;
            }
            (
                "ownmesh_transfer_list",
                json!({ "cursor": cursor, "limit": limit }),
            )
        }
        TransferCmd::Status { id } => {
            validate_text("transfer id", id)?;
            ("ownmesh_transfer_status", json!({ "transfer_id": id }))
        }
        TransferCmd::Cancel {
            id,
            idempotency_key,
        } => {
            validate_text("transfer id", id)?;
            validate_text("idempotency-key", idempotency_key)?;
            (
                "ownmesh_transfer_cancel",
                json!({ "transfer_id": id, "idempotency_key": idempotency_key }),
            )
        }
    };
    run_mcp_tool(cli, tool, args)
}

fn validate_text(name: &str, value: &str) -> Result<(), ExitCode> {
    let valid = !value.is_empty()
        && value == value.trim()
        && value.len() <= MAX_TEXT_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control());
    if valid {
        return Ok(());
    }
    eprintln!(
        "invalid {name}: must be a trimmed, non-control string of at most {MAX_TEXT_BYTES} bytes"
    );
    Err(ExitCode::UsageConfig)
}

fn validate_path(name: &str, value: &str) -> Result<(), ExitCode> {
    let valid = !value.is_empty()
        && value == value.trim()
        && value.len() <= MAX_PATH_BYTES
        && !value.starts_with(['/', '\\'])
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if valid {
        return Ok(());
    }
    eprintln!(
        "invalid {name} path: use a non-empty workspace-relative slash path without traversal"
    );
    Err(ExitCode::UsageConfig)
}

fn run_mcp_tool(cli: &Cli, tool: &str, arguments: Value) -> Result<(), ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            eprintln!("failed to start async runtime: {err}");
            ExitCode::Internal
        })?;
    runtime.block_on(async {
        let paths = SessionPaths::discover().map_err(|err| {
            eprintln!("path error: {err}");
            ExitCode::UsageConfig
        })?;
        let store = open_secret_store(&paths.paths).map_err(|err| {
            eprintln!("keychain error: {err}");
            ExitCode::Internal
        })?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| {
                eprintln!("http client error: {err}");
                ExitCode::Internal
            })?;
        let (access, session) = load_access_token(&paths, &store, &http)
            .await
            .map_err(|err| {
                eprintln!("{err}");
                eprintln!("hint: run `ownmesh login` first");
                ExitCode::Authentication
            })?;
        let issuer = resolve_issuer(&session).map_err(|err| {
            eprintln!("{err}");
            ExitCode::UsageConfig
        })?;
        let endpoint = format!("{issuer}/mcp");
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": { "name": tool, "arguments": arguments },
        });
        let response = http
            .post(endpoint)
            .bearer_auth(access)
            .header("mcp-protocol-version", "2025-03-26")
            .json(&request)
            .send()
            .await
            .map_err(|err| {
                eprintln!("control-plane request failed: {err}");
                ExitCode::DeviceOffline
            })?;
        let status = response.status();
        let body: Value = response.json().await.map_err(|err| {
            eprintln!("invalid control-plane response: {err}");
            ExitCode::Internal
        })?;
        if !status.is_success() {
            eprintln!(
                "control-plane request failed ({status}): {}",
                rpc_message(&body)
            );
            return Err(http_exit(status));
        }
        if let Some(error) = body.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            eprintln!("transfer request rejected: {}", rpc_message(&body));
            return Err(match code {
                -32602 => ExitCode::UsageConfig,
                -32004 => ExitCode::Authorization,
                -32009 => ExitCode::Conflict,
                _ => ExitCode::Internal,
            });
        }
        let value = extract_tool_value(&body).map_err(|message| {
            eprintln!("invalid control-plane response: {message}");
            ExitCode::Internal
        })?;
        if cli.json {
            println!(
                "{}",
                json!({ "schema_version": 1, "ok": true, "tool": tool, "result": value })
            );
        } else {
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
            );
        }
        Ok(())
    })
}

/// Decode the standard MCP `tools/call` content shape without a network call.
fn extract_tool_value(body: &Value) -> Result<Value, &'static str> {
    let result = body.get("result").ok_or("missing result")?;
    let content = result
        .get("content")
        .and_then(Value::as_array)
        .ok_or("missing tool content")?;
    let text = content
        .first()
        .and_then(|item| item.get("text"))
        .and_then(Value::as_str)
        .ok_or("missing tool JSON")?;
    serde_json::from_str(text).map_err(|_| "malformed tool JSON")
}

fn rpc_message(body: &Value) -> &str {
    body.pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("unknown control-plane error")
}

fn http_exit(status: reqwest::StatusCode) -> ExitCode {
    match status.as_u16() {
        401 => ExitCode::Authentication,
        403 => ExitCode::Authorization,
        408 | 504 => ExitCode::TimeoutCancelled,
        409 => ExitCode::Conflict,
        _ if status.is_server_error() => ExitCode::DeviceOffline,
        _ => ExitCode::Internal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Commands;
    use clap::Parser;

    #[test]
    fn transfer_subcommands_parse_with_the_public_contract_arguments() {
        let cli = Cli::try_parse_from([
            "ownmesh",
            "transfer",
            "plan",
            "in/a.bin",
            "out/a.bin",
            "--source-device",
            "dev_source",
            "--destination-device",
            "dev_destination",
            "--source-workspace",
            "ws_source",
            "--destination-workspace",
            "ws_destination",
            "--idempotency-key",
            "plan-1",
        ])
        .expect("plan should parse");
        assert!(matches!(
            cli.command,
            Some(Commands::Transfer(TransferCmd::Plan { .. }))
        ));
        assert!(Cli::try_parse_from([
            "ownmesh",
            "transfer",
            "send",
            "tr_1",
            "--idempotency-key",
            "send-1"
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["ownmesh", "transfer", "list", "--limit", "500"]).is_ok());
        assert!(Cli::try_parse_from(["ownmesh", "transfer", "status", "tr_1"]).is_ok());
        assert!(Cli::try_parse_from([
            "ownmesh",
            "transfer",
            "cancel",
            "tr_1",
            "--idempotency-key",
            "cancel-1"
        ])
        .is_ok());
    }

    #[test]
    fn traversal_path_is_rejected_before_network() {
        assert_eq!(
            validate_path("source", "../secret"),
            Err(ExitCode::UsageConfig)
        );
        assert_eq!(validate_path("source", "in/file.bin"), Ok(()));
    }

    #[test]
    fn public_mcp_tool_response_is_preserved_as_json_result() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": r#"{"operation_id":"tr_1","data":{"transfer":{"state":"planned"}}}"# }] }
        });
        assert_eq!(
            extract_tool_value(&response).expect("valid MCP tools/call response"),
            json!({ "operation_id": "tr_1", "data": { "transfer": { "state": "planned" } } })
        );
    }
}
