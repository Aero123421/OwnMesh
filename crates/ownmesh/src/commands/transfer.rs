//! `ownmesh transfer` — typed CLI façade for the public control-plane MCP contract.
//!
//! The CLI deliberately calls the same `ownmesh_transfer_*` tools as remote MCP
//! clients.  It never falls back to local daemon transfer internals, which are
//! Agent-only custody/data-plane operations rather than a cross-device API.

use super::mcp_client::{McpClientError, McpHttpClient};
use crate::cli::{Cli, TransferCmd};
use ownmesh_domain::{ErrorCode, ExitCode};
use serde_json::{json, Value};

const MAX_TEXT_BYTES: usize = 256;
const MAX_PATH_BYTES: usize = 4096;

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

    #[cfg(test)]
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
            overwrite_expected_sha256,
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
            if let Some(hash) = overwrite_expected_sha256 {
                validate_content_hash("overwrite-expected-sha256", hash)?;
            }
            let mut args = json!({
                "source_device_id": source_device,
                "destination_device_id": destination_device,
                "source_workspace_id": source_workspace,
                "destination_workspace_id": destination_workspace,
                "source_path": source,
                "destination_path": dest,
                "idempotency_key": idempotency_key,
                "ttl_seconds": ttl_seconds,
            });
            if let Some(hash) = overwrite_expected_sha256 {
                args["overwrite_expected_sha256"] = json!(hash);
            }
            ("ownmesh_transfer_plan", args)
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

fn validate_content_hash(name: &str, value: &str) -> Result<(), TransferFailure> {
    let valid = value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'));
    if valid {
        return Ok(());
    }
    Err(TransferFailure::new(
        ErrorCode::InvalidArgument,
        format!("invalid {name}: must be 64 lowercase hex characters"),
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
        let mut client = McpHttpClient::from_configured_auth()
            .await
            .map_err(transfer_failure_from_client)?;
        let value = client
            .call_tool_value(json!(1), tool, arguments)
            .await
            .map_err(transfer_failure_from_client)?;
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

fn transfer_failure_from_client(failure: McpClientError) -> TransferFailure {
    TransferFailure {
        code: failure.code,
        message: failure.message,
        hint: failure.hint,
    }
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
        crate::commands::fail::note_envelope_emitted();
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
    fn overwrite_expected_sha256_must_be_64_lowercase_hex() {
        assert!(validate_content_hash(
            "overwrite-expected-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
        .is_ok());
        assert_eq!(
            validate_content_hash("overwrite-expected-sha256", "not-a-hash")
                .expect_err("invalid hash must fail")
                .exit_code(),
            ExitCode::UsageConfig
        );
        assert_eq!(
            validate_content_hash(
                "overwrite-expected-sha256",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
            )
            .expect_err("uppercase hex must fail")
            .exit_code(),
            ExitCode::UsageConfig
        );
        assert!(Cli::try_parse_from([
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
            "--overwrite-expected-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ])
        .is_ok());
    }

    #[test]
    fn public_mcp_tool_response_is_preserved_as_json_result() {
        let response = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "result": { "content": [{ "type": "text", "text": r#"{"operation_id":"tr_1","data":{"transfer":{"state":"planned"}}}"# }] }
        });
        assert_eq!(
            crate::commands::mcp_client::extract_tool_value(&response)
                .expect("valid MCP tools/call response"),
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
    fn utf8_limits_are_measured_in_bytes() {
        assert!(validate_text("id", &"é".repeat(MAX_TEXT_BYTES / 2)).is_ok());
        assert!(validate_text("id", &"é".repeat((MAX_TEXT_BYTES / 2) + 1)).is_err());
        assert!(validate_path("path", &"界".repeat(MAX_PATH_BYTES / 3)).is_ok());
        assert!(validate_path("path", &"界".repeat((MAX_PATH_BYTES / 3) + 1)).is_err());
    }
}
