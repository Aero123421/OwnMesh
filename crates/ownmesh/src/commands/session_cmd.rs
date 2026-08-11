//! `ownmesh session` commands wired to ownmeshd session.* IPC.

use crate::cli::{Cli, SessionCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};
use std::time::Duration;

pub fn dispatch_session(cli: &Cli, cmd: &SessionCmd) -> Result<(), ExitCode> {
    dispatch_session_with(
        cli,
        cmd,
        |method, params| call_daemon(cli, method, params),
        |tool, device, payload, wait| {
            super::exec::call_remote_operation(cli, tool, device, payload, wait)
        },
    )
}

// Each match arm directly mirrors one session IPC operation; keeping them together makes
// command-to-method auditing straightforward.
#[allow(clippy::too_many_lines)]
fn dispatch_session_with<Local, Remote>(
    cli: &Cli,
    cmd: &SessionCmd,
    call_local_daemon: Local,
    call_remote: Remote,
) -> Result<(), ExitCode>
where
    Local: Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
    Remote: Fn(&str, &str, Value, Duration) -> Result<Value, ExitCode>,
{
    match cmd {
        SessionCmd::Open {
            device: Some(device),
            idempotency_key,
            command,
        } => {
            super::exec::validate_remote_text("device", device, 256)
                .map_err(|message| super::exec::emit_validation_code(cli, &message))?;
            let idempotency_key = idempotency_key.as_deref().ok_or_else(|| {
                super::exec::emit_validation_code(
                    cli,
                    "--idempotency-key is required when opening a remote session",
                )
            })?;
            super::exec::validate_remote_text("idempotency-key", idempotency_key, 256)
                .map_err(|message| super::exec::emit_validation_code(cli, &message))?;
            if command.len() > 64 {
                return Err(super::exec::emit_validation_code(
                    cli,
                    "remote session accepts at most 64 argv values",
                ));
            }
            for value in command {
                super::exec::validate_remote_text("command argument", value, 4096)
                    .map_err(|message| super::exec::emit_validation_code(cli, &message))?;
            }
            let program = command.first().cloned();
            let args = command.get(1..).unwrap_or_default();
            let mut payload = json!({
                "device_id": device,
                "title": "cli",
                "program": program,
                "args": args,
                "adapter_mode": "pty",
                "idempotency_key": idempotency_key,
            });
            if program.is_none() {
                payload
                    .as_object_mut()
                    .expect("payload object")
                    .remove("program");
            }
            let value = call_remote(
                "ownmesh_session_open",
                device,
                payload,
                Duration::from_secs(60),
            )?;
            if value.get("status").and_then(Value::as_str) == Some("approval_required") {
                if cli.json {
                    println!(
                        "{}",
                        json!({
                            "schema_version": 1,
                            "ok": false,
                            "exit_code": ExitCode::Authorization.code(),
                            "error": {
                                "code": "OWNMESH_E_APPROVAL_REQUIRED",
                                "message": "the session is queued and needs an approval decision",
                            },
                            "tool": "ownmesh_session_open",
                            "result": value,
                        })
                    );
                    crate::commands::fail::note_envelope_emitted();
                } else {
                    eprintln!(
                        "approval required: {}",
                        value
                            .get("approval_url")
                            .and_then(Value::as_str)
                            .unwrap_or("open the approval URL from operation status")
                    );
                }
                return Err(ExitCode::Authorization);
            }
            if value.get("status").and_then(Value::as_str) != Some("completed") {
                return super::exec::emit_remote_terminal_failure(cli, &value);
            }
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "ok": true,
                        "tool": "ownmesh_session_open",
                        "result": value,
                    })
                );
            } else {
                let session_id = value
                    .get("session_id")
                    .and_then(Value::as_str)
                    .or_else(|| value.pointer("/data/session_id").and_then(Value::as_str))
                    .or_else(|| value.pointer("/data/id").and_then(Value::as_str))
                    .unwrap_or("?");
                println!("opened remote session {session_id} on {device}");
            }
            Ok(())
        }
        SessionCmd::Open {
            device: None,
            idempotency_key: _,
            command,
        } => {
            // Principal is bound server-side to the authenticated IPC client identity.
            // Never send a client-chosen principal label.
            let value = call_local_daemon(
                "session.open",
                Some(json!({
                    "title": "cli",
                    "kind": "pty",
                    "command": command,
                })),
            )?;
            print_value(cli.json, &value, |v| {
                println!(
                    "session {} state={}",
                    v["id"].as_str().unwrap_or("?"),
                    v["state"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        SessionCmd::List => {
            let value = call_local_daemon("session.list", None)?;
            print_value(cli.json, &value, |v| {
                let sessions = v["sessions"].as_array().cloned().unwrap_or_default();
                if sessions.is_empty() {
                    println!("(no sessions)");
                } else {
                    for s in sessions {
                        println!(
                            "{}  {}  controller={}",
                            s["id"].as_str().unwrap_or("?"),
                            s["state"].as_str().unwrap_or("?"),
                            s["controller"]["principal_id"].as_str().unwrap_or("-")
                        );
                    }
                }
            });
            Ok(())
        }
        SessionCmd::Show { id } => {
            let value = call_local_daemon("session.show", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            });
            Ok(())
        }
        SessionCmd::Attach { id, read_only } => {
            // Principal is bound server-side.
            let value = call_local_daemon(
                "session.attach",
                Some(json!({
                    "id": id,
                    "read_only": read_only,
                })),
            )?;
            print_value(cli.json, &value, |v| {
                println!(
                    "attached {} read_only={}",
                    v["session"]["id"].as_str().unwrap_or(id),
                    read_only
                );
            });
            Ok(())
        }
        SessionCmd::Claim { id } => {
            let value = call_local_daemon("session.claim", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!(
                    "claimed lease={}",
                    v["lease"]["lease_id"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        SessionCmd::Release { id } => {
            let value = call_local_daemon("session.release", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |_| println!("released {id}"));
            Ok(())
        }
        SessionCmd::Give { id, to } => {
            // `from` is bound server-side to the authenticated IPC client identity.
            let value = call_local_daemon(
                "session.give",
                Some(json!({
                    "id": id,
                    "to": to,
                })),
            )?;
            print_value(cli.json, &value, |v| {
                println!(
                    "gave controller to {}",
                    v["lease"]["principal_id"].as_str().unwrap_or(to)
                );
            });
            Ok(())
        }
        SessionCmd::Close { id } => {
            let value = call_local_daemon("session.close", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |_| println!("closed {id}"));
            Ok(())
        }
        SessionCmd::Terminate { id, all } => {
            let params = if *all {
                json!({ "all": true })
            } else {
                json!({ "id": id, "all": false })
            };
            let value = call_local_daemon("session.terminate", Some(params))?;
            print_value(cli.json, &value, |v| {
                println!("terminated {}", v["terminated"]);
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use clap::Parser;
    use std::cell::Cell;

    #[test]
    fn remote_session_routes_only_to_authenticated_remote_path() {
        let cli = Cli::try_parse_from([
            "ownmesh",
            "session",
            "open",
            "dev_remote",
            "--idempotency-key",
            "session-1",
            "--",
            "echo",
            "hello",
        ])
        .expect("remote session arguments should parse");
        let Commands::Session(cmd) = cli.command.as_ref().expect("session command") else {
            panic!("expected session command");
        };
        let local_daemon_attempted = Cell::new(false);
        let remote_attempted = Cell::new(false);

        let result = dispatch_session_with(
            &cli,
            cmd,
            |_, _| {
                local_daemon_attempted.set(true);
                Ok(json!({}))
            },
            |tool, device, payload, _| {
                remote_attempted.set(true);
                assert_eq!(tool, "ownmesh_session_open");
                assert_eq!(device, "dev_remote");
                assert_eq!(payload["idempotency_key"], "session-1");
                assert_eq!(payload["program"], "echo");
                Ok(json!({
                    "operation_id": "op_1",
                    "status": "completed",
                    "session_id": "ses_remote_1",
                    "data": {},
                }))
            },
        );

        assert!(result.is_ok());
        assert!(!local_daemon_attempted.get());
        assert!(remote_attempted.get());
    }

    #[test]
    fn remote_session_requires_idempotency_before_routing() {
        let cli = Cli::try_parse_from(["ownmesh", "session", "open", "dev_remote"])
            .expect("remote session parses");
        let Commands::Session(cmd) = cli.command.as_ref().unwrap() else {
            panic!("session command");
        };
        let remote_attempted = Cell::new(false);
        let result = dispatch_session_with(
            &cli,
            cmd,
            |_, _| panic!("remote session must not use local IPC"),
            |_, _, _, _| {
                remote_attempted.set(true);
                Ok(json!({}))
            },
        );
        assert_eq!(result, Err(ExitCode::UsageConfig));
        assert!(!remote_attempted.get());
    }
}
