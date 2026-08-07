//! `ownmesh session` commands wired to ownmeshd session.* IPC.

use crate::cli::{Cli, SessionCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};

pub fn dispatch_session(cli: &Cli, cmd: &SessionCmd) -> Result<(), ExitCode> {
    dispatch_session_with(cli, cmd, call_daemon)
}

// Each match arm directly mirrors one session IPC operation; keeping them together makes
// command-to-method auditing straightforward.
#[allow(clippy::too_many_lines)]
fn dispatch_session_with(
    cli: &Cli,
    cmd: &SessionCmd,
    call_local_daemon: impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
) -> Result<(), ExitCode> {
    match cmd {
        SessionCmd::Open {
            device: Some(device),
            ..
        } => {
            // Remote device routing is unsupported. Fail closed: never fall back
            // to the local daemon when the operator targeted another device.
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "status": "not_implemented",
                        "command": "session open <device>",
                        "device": device,
                        "message": "remote session routing is unsupported; local execution refused",
                    })
                );
            } else {
                eprintln!(
                    "session open <device>: remote device {device} is unsupported; refusing local execution"
                );
            }
            Err(super::unsupported_exit("session open <device>"))
        }
        SessionCmd::Open {
            device: None,
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
    fn remote_session_fails_without_attempting_local_daemon() {
        let cli = Cli::try_parse_from([
            "ownmesh",
            "session",
            "open",
            "dev_remote",
            "--",
            "echo",
            "hello",
        ])
        .expect("remote session arguments should parse");
        let Commands::Session(cmd) = cli.command.as_ref().expect("session command") else {
            panic!("expected session command");
        };
        let local_daemon_attempted = Cell::new(false);

        let result = dispatch_session_with(&cli, cmd, |_, _| {
            local_daemon_attempted.set(true);
            Ok(json!({}))
        });

        assert_eq!(result, Err(ExitCode::ProfileUnavailable));
        assert!(!local_daemon_attempted.get());
    }
}
