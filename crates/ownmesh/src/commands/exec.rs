//! `ownmesh exec` — policy-gated command execution via ownmeshd.

use crate::cli::{Cli, ExecArgs};
use crate::commands::ipc_util::{call_daemon, print_value};
use crate::commands::mcp_client::{McpClientError, McpHttpClient};
use ownmesh_domain::{ErrorCode, ExitCode};
use ownmesh_ipc::methods;
use serde_json::{json, Value};
use std::time::Duration;

const MAX_REMOTE_TEXT_BYTES: usize = 4_096;
const MAX_REMOTE_ARGS: usize = 64;
const MAX_REMOTE_TIMEOUT_MS: u64 = 300_000;

pub fn run_exec(cli: &Cli, args: &ExecArgs) -> Result<(), ExitCode> {
    run_exec_with(cli, args, call_daemon, |tool, device, payload, wait| {
        call_remote_operation(cli, tool, device, payload, wait)
    })
}

fn run_exec_with<Local, Remote>(
    cli: &Cli,
    args: &ExecArgs,
    call_local_daemon: Local,
    call_remote: Remote,
) -> Result<(), ExitCode>
where
    Local: FnOnce(&str, Option<Value>) -> Result<Value, ExitCode>,
    Remote: FnOnce(&str, &str, Value, Duration) -> Result<Value, ExitCode>,
{
    if args.command.is_empty() {
        eprintln!("exec: command is required");
        return Err(ExitCode::UsageConfig);
    }
    if args
        .timeout_ms
        .is_some_and(|value| value == 0 || value > MAX_REMOTE_TIMEOUT_MS)
    {
        return emit_validation(cli, "timeout-ms must be between 1 and 300000");
    }
    if args.raw_shell && args.elevated {
        return emit_validation(cli, "--elevated is available only for structured commands");
    }
    if let Some(device) = &args.device {
        validate_remote_text("device", device, 256)
            .map_err(|message| emit_validation_code(cli, &message))?;
        let idempotency_key = args.idempotency_key.as_deref().ok_or_else(|| {
            emit_validation_code(cli, "--idempotency-key is required for remote execution")
        })?;
        validate_remote_text("idempotency-key", idempotency_key, 256)
            .map_err(|message| emit_validation_code(cli, &message))?;
        if args.command.len() > MAX_REMOTE_ARGS {
            return emit_validation(cli, "remote execution accepts at most 64 argv values");
        }
        for value in &args.command {
            validate_remote_text("command argument", value, MAX_REMOTE_TEXT_BYTES)
                .map_err(|message| emit_validation_code(cli, &message))?;
        }
        if let Some(cwd) = &args.cwd {
            validate_remote_text("cwd", cwd, MAX_REMOTE_TEXT_BYTES)
                .map_err(|message| emit_validation_code(cli, &message))?;
        }

        let (tool, mut payload) = if args.raw_shell {
            if args.command.len() != 1 {
                return emit_validation(
                    cli,
                    "remote --raw-shell requires one exact command string after --",
                );
            }
            (
                "ownmesh_command_shell",
                json!({
                    "device_id": device,
                    "command": args.command[0],
                    "cwd": args.cwd,
                    "idempotency_key": idempotency_key,
                    "timeout_ms": args.timeout_ms,
                    "async": false,
                }),
            )
        } else {
            (
                "ownmesh_command_run",
                json!({
                    "device_id": device,
                    "program": args.command[0],
                    "args": &args.command[1..],
                    "cwd": args.cwd,
                    "idempotency_key": idempotency_key,
                    "timeout_ms": args.timeout_ms,
                    "elevated": args.elevated,
                    "async": false,
                }),
            )
        };
        if args.cwd.is_none() {
            payload
                .as_object_mut()
                .expect("payload object")
                .remove("cwd");
        }
        if args.timeout_ms.is_none() {
            payload
                .as_object_mut()
                .expect("payload object")
                .remove("timeout_ms");
        }
        let wait = Duration::from_millis(args.timeout_ms.unwrap_or(30_000).saturating_add(30_000));
        let value = call_remote(tool, device, payload, wait)?;
        return render_remote_exec(cli, tool, &value);
    }
    let program = args.command[0].clone();
    let rest = args.command[1..].to_vec();
    let params = json!({
        "program": program,
        "args": rest,
        "cwd": args.cwd,
        "kind": if args.raw_shell { "raw_shell" } else { "structured" },
        "timeout_ms": args.timeout_ms,
        "elevated": args.elevated,
        "idempotency_key": args.idempotency_key,
    });
    let value = call_local_daemon(methods::OPS_EXEC, Some(params))?;
    print_value(cli.json, &value, |v| {
        if v["approval_required"].as_bool() == Some(true) {
            println!(
                "approval required: {} (operation {})",
                v["approval_id"].as_str().unwrap_or("?"),
                v["operation_id"].as_str().unwrap_or("?")
            );
            println!("reason: {}", v["reason"].as_str().unwrap_or(""));
            println!("approve with: ownmesh approval approve <id>");
            return;
        }
        if let Some(result) = v.get("result") {
            if let Some(stdout) = result.get("stdout").and_then(|s| s.as_str()) {
                print!("{stdout}");
                if !stdout.ends_with('\n') && !stdout.is_empty() {
                    println!();
                }
            }
            if let Some(stderr) = result.get("stderr").and_then(|s| s.as_str()) {
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                    if !stderr.ends_with('\n') {
                        eprintln!();
                    }
                }
            }
            if result["replayed"].as_bool() == Some(true) || v["replayed"].as_bool() == Some(true) {
                eprintln!("(replayed from idempotency journal)");
            }
        }
    });
    if value["approval_required"].as_bool() == Some(true) {
        // Pending approval is not a hard failure; surface as authorization-ish wait.
        return Err(ExitCode::Authorization);
    }
    Ok(())
}

pub(super) fn call_remote_operation(
    cli: &Cli,
    tool: &str,
    device: &str,
    payload: Value,
    wait: Duration,
) -> Result<Value, ExitCode> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|error| {
            emit_mcp_error(
                cli,
                &McpClientError::new(ErrorCode::Internal, error.to_string()),
            )
        })?;
    runtime.block_on(async {
        let mut client = McpHttpClient::from_configured_auth()
            .await
            .map_err(|error| emit_mcp_error(cli, &error))?;
        client
            .call_tool_until_terminal(tool, payload, device, wait)
            .await
            .map_err(|error| emit_mcp_error(cli, &error))
    })
}

fn render_remote_exec(cli: &Cli, tool: &str, value: &Value) -> Result<(), ExitCode> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    if status == "approval_required" {
        let approval_url = value
            .get("approval_url")
            .and_then(Value::as_str)
            .unwrap_or("");
        if cli.json {
            println!(
                "{}",
                json!({ "schema_version": 1, "ok": false, "tool": tool, "result": value })
            );
        } else {
            eprintln!(
                "approval required for operation {}",
                value["operation_id"].as_str().unwrap_or("?")
            );
            if !approval_url.is_empty() {
                eprintln!("open: {approval_url}");
            }
        }
        return Err(ExitCode::Authorization);
    }
    if status != "completed" {
        return emit_remote_terminal_failure(cli, value);
    }
    if cli.json {
        println!(
            "{}",
            json!({ "schema_version": 1, "ok": true, "tool": tool, "result": value })
        );
        return Ok(());
    }
    let data = value.get("data").unwrap_or(&Value::Null);
    if let Some(stdout) = data.get("stdout").and_then(Value::as_str) {
        print!("{stdout}");
        if !stdout.is_empty() && !stdout.ends_with('\n') {
            println!();
        }
    }
    if let Some(stderr) = data.get("stderr").and_then(Value::as_str) {
        eprint!("{stderr}");
        if !stderr.is_empty() && !stderr.ends_with('\n') {
            eprintln!();
        }
    }
    Ok(())
}

pub(super) fn emit_remote_terminal_failure(cli: &Cli, value: &Value) -> Result<(), ExitCode> {
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("failed");
    let code = match status {
        "denied" => ErrorCode::PolicyDenied,
        "cancelled" => ErrorCode::Cancelled,
        "device_offline" => ErrorCode::DeviceOffline,
        _ => ErrorCode::Internal,
    };
    let message = value
        .pointer("/data/error/message")
        .and_then(Value::as_str)
        .or_else(|| value.get("summary").and_then(Value::as_str))
        .unwrap_or("remote operation failed");
    let failure = McpClientError::new(code, message);
    Err(emit_mcp_error(cli, &failure))
}

pub(super) fn validate_remote_text(
    name: &str,
    value: &str,
    max_bytes: usize,
) -> Result<(), String> {
    if value.is_empty()
        || value != value.trim()
        || value.len() > max_bytes
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(format!(
            "invalid {name}: expected a trimmed non-control string of at most {max_bytes} UTF-8 bytes"
        ));
    }
    Ok(())
}

fn emit_validation(cli: &Cli, message: &str) -> Result<(), ExitCode> {
    Err(emit_validation_code(cli, message))
}

pub(super) fn emit_validation_code(cli: &Cli, message: &str) -> ExitCode {
    emit_mcp_error(
        cli,
        &McpClientError::new(ErrorCode::InvalidArgument, message),
    )
}

pub(super) fn emit_mcp_error(cli: &Cli, error: &McpClientError) -> ExitCode {
    let message = ownmesh_diagnostics::redact_text(&error.message);
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": false,
                "exit_code": error.code.exit_code().code(),
                "error": { "code": error.code.as_str(), "message": message },
            })
        );
    } else {
        eprintln!("{}: {message}", error.code.as_str());
        if let Some(hint) = error.hint {
            eprintln!("hint: {}", ownmesh_diagnostics::redact_text(hint));
        }
    }
    error.code.exit_code()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Commands;
    use clap::Parser;
    use std::cell::Cell;

    #[test]
    fn device_exec_routes_only_to_authenticated_remote_path() {
        let cli = Cli::try_parse_from([
            "ownmesh",
            "exec",
            "--device",
            "dev_remote",
            "--idempotency-key",
            "exec-1",
            "--",
            "echo",
            "hello",
        ])
        .expect("device exec arguments should parse");
        let Commands::Exec(args) = cli.command.as_ref().expect("exec command") else {
            panic!("expected exec command");
        };
        let local_daemon_attempted = Cell::new(false);
        let remote_attempted = Cell::new(false);

        let result = run_exec_with(
            &cli,
            args,
            |_, _| {
                local_daemon_attempted.set(true);
                Ok(json!({}))
            },
            |tool, device, payload, _| {
                remote_attempted.set(true);
                assert_eq!(tool, "ownmesh_command_run");
                assert_eq!(device, "dev_remote");
                assert_eq!(payload["program"], "echo");
                assert_eq!(payload["idempotency_key"], "exec-1");
                Ok(
                    json!({ "operation_id": "op_1", "status": "completed", "data": { "stdout": "hello\n" } }),
                )
            },
        );

        assert!(result.is_ok());
        assert!(!local_daemon_attempted.get());
        assert!(remote_attempted.get());
    }

    #[test]
    fn device_absent_reaches_injected_local_path() {
        let cli = Cli {
            json: false,
            lang: None,
            command: None,
        };
        let args = ExecArgs {
            device: None,
            cwd: None,
            idempotency_key: None,
            raw_shell: false,
            timeout_ms: None,
            elevated: true,
            command: vec!["echo".into(), "hi".into()],
        };
        let reached = Cell::new(false);
        let result = run_exec_with(
            &cli,
            &args,
            |method, params| {
                reached.set(true);
                assert_eq!(method, methods::OPS_EXEC);
                assert_eq!(params.unwrap()["elevated"], true);
                Ok(json!({"result": {"stdout": "hi\n", "stderr": ""}}))
            },
            |_, _, _, _| panic!("local execution must not use MCP"),
        );
        assert!(result.is_ok());
        assert!(reached.get());
    }

    #[test]
    fn remote_exec_requires_idempotency_before_routing() {
        let cli = Cli::try_parse_from(["ownmesh", "exec", "--device", "dev_remote", "--", "echo"])
            .expect("remote exec parses");
        let Commands::Exec(args) = cli.command.as_ref().unwrap() else {
            panic!("exec command");
        };
        let remote_attempted = Cell::new(false);
        let result = run_exec_with(
            &cli,
            args,
            |_, _| panic!("remote exec must not use local IPC"),
            |_, _, _, _| {
                remote_attempted.set(true);
                Ok(json!({}))
            },
        );
        assert_eq!(result, Err(ExitCode::UsageConfig));
        assert!(!remote_attempted.get());
    }
}
