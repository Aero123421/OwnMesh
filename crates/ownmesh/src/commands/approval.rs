//! `ownmesh approval` — local approval queue via ownmeshd.

use crate::cli::{ApprovalCmd, Cli};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{human_operator_disabled_message, methods};
use serde_json::json;

fn human_operator_unavailable(cli: &Cli, command: &str) -> Result<(), ExitCode> {
    let message = human_operator_disabled_message();
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": false,
                "command": command,
                "error": "human_presence_unavailable",
                "message": message,
            })
        );
    } else {
        eprintln!("{command}: {message}");
    }
    Err(ExitCode::UsageConfig)
}

pub fn dispatch_approval(cli: &Cli, cmd: &ApprovalCmd) -> Result<(), ExitCode> {
    match cmd {
        ApprovalCmd::List => {
            let value = call_daemon(methods::APPROVAL_LIST, None)?;
            print_value(cli.json, &value, |v| {
                let Some(list) = v["approvals"].as_array() else {
                    println!("(no approvals)");
                    return;
                };
                if list.is_empty() {
                    println!("(no approvals)");
                    return;
                }
                for a in list {
                    println!(
                        "{id}  {state}  {cap}  op={op}  {reason}",
                        id = a["id"].as_str().unwrap_or("?"),
                        state = a["state"].as_str().unwrap_or("?"),
                        cap = a["capability"].as_str().unwrap_or("?"),
                        op = a["operation_id"].as_str().unwrap_or("?"),
                        reason = a["reason"].as_str().unwrap_or(""),
                    );
                }
            });
            Ok(())
        }
        ApprovalCmd::Show { id } => {
            let value = call_daemon(methods::APPROVAL_SHOW, Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            });
            Ok(())
        }
        ApprovalCmd::Approve {
            id,
            grant,
            grant_seconds,
        } => {
            let _ = (id, grant, grant_seconds);
            // No distinct OS/UI user-presence proof is bound to approve yet. Ordinary
            // local IPC (including this CLI path) is fail-closed — same-UID sockets are
            // forgeable and must not be treated as human presence.
            human_operator_unavailable(cli, "approval approve")
        }
        ApprovalCmd::Deny { id } => {
            let _ = id;
            human_operator_unavailable(cli, "approval deny")
        }
        ApprovalCmd::Watch => super::unsupported(
            cli,
            "approval watch",
            "live approval watching is unsupported; use `ownmesh approval list` for a one-shot query",
        ),
    }
}
