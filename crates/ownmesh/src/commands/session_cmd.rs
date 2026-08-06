//! `ownmesh session` commands wired to ownmeshd session.* IPC.

use crate::cli::{Cli, SessionCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::json;

pub fn dispatch_session(cli: &Cli, cmd: &SessionCmd) -> Result<(), ExitCode> {
    match cmd {
        SessionCmd::Open { device: _, command } => {
            let value = call_daemon(
                "session.open",
                Some(json!({
                    "title": "cli",
                    "kind": "pty",
                    "command": command,
                    "principal": "prin_local",
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
            let value = call_daemon("session.list", None)?;
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
                            s["controller"]["principal_id"]
                                .as_str()
                                .unwrap_or("-")
                        );
                    }
                }
            });
            Ok(())
        }
        SessionCmd::Show { id } => {
            let value = call_daemon("session.show", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            });
            Ok(())
        }
        SessionCmd::Attach { id, read_only } => {
            let value = call_daemon(
                "session.attach",
                Some(json!({
                    "id": id,
                    "read_only": read_only,
                    "principal": "prin_local",
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
            let value = call_daemon(
                "session.claim",
                Some(json!({ "id": id, "principal": "prin_local" })),
            )?;
            print_value(cli.json, &value, |v| {
                println!(
                    "claimed lease={}",
                    v["lease"]["lease_id"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        SessionCmd::Release { id } => {
            let value = call_daemon(
                "session.release",
                Some(json!({ "id": id, "principal": "prin_local" })),
            )?;
            print_value(cli.json, &value, |_| println!("released {id}"));
            Ok(())
        }
        SessionCmd::Give { id, to } => {
            let value = call_daemon(
                "session.give",
                Some(json!({
                    "id": id,
                    "to": to,
                    "from": "prin_local",
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
            let value = call_daemon("session.close", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |_| println!("closed {id}"));
            Ok(())
        }
        SessionCmd::Terminate { id, all } => {
            let params = if *all {
                json!({ "all": true })
            } else {
                json!({ "id": id, "all": false })
            };
            let value = call_daemon("session.terminate", Some(params))?;
            print_value(cli.json, &value, |v| {
                println!("terminated {}", v["terminated"]);
            });
            Ok(())
        }
    }
}
