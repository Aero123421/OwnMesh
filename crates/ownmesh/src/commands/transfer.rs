//! `ownmesh transfer` — typed CLI façade for the public control-plane MCP contract.
//!
//! The CLI deliberately calls the same `ownmesh_transfer_*` tools as remote MCP
//! clients.  It never falls back to local daemon transfer internals, which are
//! Agent-only custody/data-plane operations rather than a cross-device API.

use crate::auth::{load_access_token, open_secret_store, resolve_issuer, SessionPaths};
use crate::cli::{Cli, TransferCmd};
use ownmesh_domain::{ErrorCode, ExitCode};
use reqwest::header::CONTENT_TYPE;
use serde_json::{json, Value};
use std::time::Duration;

const MAX_TEXT_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;
const MAX_MCP_RESPONSE_BYTES: usize = 256 * 1024;

#[derive(Debug)]
struct TransferFailure {
    code: ErrorCode,
    message: String,
    hint: Option<&'static str>,
}

impl TransferFailure {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
        }
    }

    fn with_hint(mut self, hint: &'static str) -> Self {
        self.hint = Some(hint);
        self
    }

    const fn exit_code(&self) -> ExitCode {
        self.code.exit_code()
    }
}

pub fn dispatch_transfer(cli: &Cli, cmd: &TransferCmd) -> Result<(), ExitCode> {
    dispatch_transfer_inner(cli, cmd).map_err(|failure| emit_failure(cli, &failure))
}

fn dispatch_transfer_inner(cli: &Cli, cmd: &TransferCmd) -> Result<(), TransferFailure> {
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

fn validate_text(name: &str, value: &str) -> Result<(), TransferFailure> {
    let valid = !value.is_empty()
        && value == value.trim()
        && utf8_byte_len(value) <= MAX_TEXT_BYTES
        && !value.bytes().any(|byte| byte.is_ascii_control());
    if valid {
        return Ok(());
    }
    Err(TransferFailure::new(
        ErrorCode::InvalidArgument,
        format!(
            "invalid {name}: must be a trimmed, non-control string of at most {MAX_TEXT_BYTES} UTF-8 bytes"
        ),
    ))
}

fn validate_path(name: &str, value: &str) -> Result<(), TransferFailure> {
    let valid = !value.is_empty()
        && value == value.trim()
        && utf8_byte_len(value) <= MAX_PATH_BYTES
        && !value.starts_with(['/', '\\'])
        && !value.contains('\\')
        && !value.bytes().any(|byte| byte.is_ascii_control())
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != "..");
    if valid {
        return Ok(());
    }
    Err(TransferFailure::new(
        ErrorCode::InvalidArgument,
        format!(
            "invalid {name} path: use at most {MAX_PATH_BYTES} UTF-8 bytes in a non-empty workspace-relative slash path without traversal"
        ),
    ))
}

const fn utf8_byte_len(value: &str) -> usize {
    // Rust strings are UTF-8; `str::len` is bytes, not Unicode scalar values.
    value.len()
}

fn run_mcp_tool(cli: &Cli, tool: &str, arguments: Value) -> Result<(), TransferFailure> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|err| {
            TransferFailure::new(
                ErrorCode::Internal,
                format!("failed to start async runtime: {err}"),
            )
        })?;
    runtime.block_on(async {
        let paths = SessionPaths::discover()
            .map_err(|err| TransferFailure::new(ErrorCode::Config, format!("path error: {err}")))?;
        let store = open_secret_store(&paths.paths).map_err(|err| {
            TransferFailure::new(ErrorCode::Internal, format!("keychain error: {err}"))
        })?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|err| {
                TransferFailure::new(ErrorCode::Internal, format!("http client error: {err}"))
            })?;
        let (access, session) = load_access_token(&paths, &store, &http)
            .await
            .map_err(|err| {
                TransferFailure::new(ErrorCode::Authentication, err.to_string())
                    .with_hint("run `ownmesh login` first")
            })?;
        let issuer = resolve_issuer(&session)
            .map_err(|err| TransferFailure::new(ErrorCode::Config, err.to_string()))?;
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
                TransferFailure::new(
                    ErrorCode::DeviceOffline,
                    format!("control-plane request failed: {err}"),
                )
            })?;
        let status = response.status();
        let body = read_response_json(response).await?;
        if !status.is_success() {
            return Err(TransferFailure::new(
                error_code_for_http(status),
                format!(
                    "control-plane request failed ({status}): {}",
                    rpc_message(&body)
                ),
            ));
        }
        if let Some(error) = body.get("error") {
            let code = error
                .get("code")
                .and_then(Value::as_i64)
                .unwrap_or_default();
            return Err(TransferFailure::new(
                match code {
                    -32602 => ErrorCode::InvalidArgument,
                    -32004 => ErrorCode::Authorization,
                    -32009 => ErrorCode::Conflict,
                    _ => ErrorCode::Internal,
                },
                format!("transfer request rejected: {}", rpc_message(&body)),
            ));
        }
        let value = extract_tool_value(&body).map_err(|message| {
            TransferFailure::new(
                ErrorCode::BadEnvelope,
                format!("invalid control-plane response: {message}"),
            )
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

async fn read_response_json(mut response: reqwest::Response) -> Result<Value, TransferFailure> {
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let expected_len = response.content_length();
    if expected_len.is_some_and(|len| len > MAX_MCP_RESPONSE_BYTES as u64) {
        return Err(TransferFailure::new(
            ErrorCode::BadEnvelope,
            format!("control-plane response exceeds the {MAX_MCP_RESPONSE_BYTES}-byte limit"),
        ));
    }

    let mut bytes = Vec::with_capacity(
        expected_len
            .and_then(|len| usize::try_from(len).ok())
            .unwrap_or_default()
            .min(MAX_MCP_RESPONSE_BYTES),
    );
    while let Some(chunk) = response.chunk().await.map_err(|err| {
        TransferFailure::new(
            ErrorCode::DeviceOffline,
            format!("failed to read control-plane response: {err}"),
        )
    })? {
        if bytes.len().saturating_add(chunk.len()) > MAX_MCP_RESPONSE_BYTES {
            return Err(TransferFailure::new(
                ErrorCode::BadEnvelope,
                format!("control-plane response exceeds the {MAX_MCP_RESPONSE_BYTES}-byte limit"),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    if expected_len.is_some_and(|len| len != bytes.len() as u64) {
        return Err(TransferFailure::new(
            ErrorCode::BadEnvelope,
            "control-plane response content-length does not match the received body",
        ));
    }
    decode_response_json(content_type.as_deref(), &bytes)
}

fn decode_response_json(
    content_type: Option<&str>,
    bytes: &[u8],
) -> Result<Value, TransferFailure> {
    if bytes.len() > MAX_MCP_RESPONSE_BYTES {
        return Err(TransferFailure::new(
            ErrorCode::BadEnvelope,
            format!("control-plane response exceeds the {MAX_MCP_RESPONSE_BYTES}-byte limit"),
        ));
    }
    let is_json = content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"));
    if !is_json {
        return Err(TransferFailure::new(
            ErrorCode::BadEnvelope,
            "control-plane response content type is not application/json",
        ));
    }
    serde_json::from_slice(bytes).map_err(|err| {
        TransferFailure::new(
            ErrorCode::BadEnvelope,
            format!("control-plane response is not valid JSON: {err}"),
        )
    })
}

fn failure_payload(failure: &TransferFailure) -> Value {
    let message = ownmesh_diagnostics::redact_text(&failure.message);
    let mut error = json!({
        "code": failure.code.as_str(),
        "message": message,
        "retryable": failure.code.retryable(),
    });
    if let Some(hint) = failure.hint {
        error["hint"] = json!(ownmesh_diagnostics::redact_text(hint));
    }
    json!({
        "schema_version": 1,
        "ok": false,
        "exit_code": failure.exit_code().code(),
        "error": error,
    })
}

fn emit_failure(cli: &Cli, failure: &TransferFailure) -> ExitCode {
    let payload = failure_payload(failure);
    if cli.json {
        println!("{payload}");
    } else {
        eprintln!(
            "{}: {}",
            failure.code.as_str(),
            payload["error"]["message"]
                .as_str()
                .unwrap_or("transfer failed")
        );
        if let Some(hint) = payload["error"]["hint"].as_str() {
            eprintln!("hint: {hint}");
        }
    }
    failure.exit_code()
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

fn error_code_for_http(status: reqwest::StatusCode) -> ErrorCode {
    match status.as_u16() {
        400 | 422 => ErrorCode::InvalidArgument,
        401 => ErrorCode::Authentication,
        403 => ErrorCode::Authorization,
        408 | 504 => ErrorCode::Timeout,
        409 => ErrorCode::Conflict,
        _ if status.is_server_error() => ErrorCode::DeviceOffline,
        _ => ErrorCode::Internal,
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
            validate_path("source", "../secret")
                .expect_err("traversal must fail")
                .exit_code(),
            ExitCode::UsageConfig
        );
        assert!(validate_path("source", "in/file.bin").is_ok());
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

    #[test]
    fn json_error_payload_is_structured_and_redacted() {
        let failure = TransferFailure::new(
            ErrorCode::Authentication,
            "refresh failed: access_token=top-secret-value",
        )
        .with_hint("run `ownmesh login` first");
        let payload = failure_payload(&failure);
        assert_eq!(payload["schema_version"], 1);
        assert_eq!(payload["ok"], false);
        assert_eq!(payload["exit_code"], ExitCode::Authentication.code());
        assert_eq!(payload["error"]["code"], "OWNMESH_E_AUTHENTICATION");
        assert_eq!(payload["error"]["hint"], "run `ownmesh login` first");
        assert!(!payload.to_string().contains("top-secret-value"));
    }

    #[test]
    fn oversized_mcp_response_is_rejected_before_json_parse() {
        let bytes = vec![b' '; MAX_MCP_RESPONSE_BYTES + 1];
        let failure = decode_response_json(Some("application/json"), &bytes)
            .expect_err("oversized response must fail");
        assert_eq!(failure.code, ErrorCode::BadEnvelope);
        assert!(failure.message.contains("exceeds"));
    }

    #[test]
    fn utf8_limits_are_measured_in_bytes() {
        assert!(validate_text("id", &"é".repeat(MAX_TEXT_BYTES / 2)).is_ok());
        assert!(validate_text("id", &"é".repeat((MAX_TEXT_BYTES / 2) + 1)).is_err());
        assert!(validate_path("path", &"界".repeat(MAX_PATH_BYTES / 3)).is_ok());
        assert!(validate_path("path", &"界".repeat((MAX_PATH_BYTES / 3) + 1)).is_err());
    }
}
