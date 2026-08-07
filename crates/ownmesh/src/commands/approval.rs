//! `ownmesh approval` — local approval queue via ownmeshd.

use crate::cli::{ApprovalCmd, Cli};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use serde_json::json;

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
            let value = call_daemon(
                methods::APPROVAL_APPROVE,
                Some(json!({
                    "id": id,
                    "temporary_grant": grant,
                    "grant_seconds": grant_seconds,
                })),
            )?;
            print_value(cli.json, &value, |v| {
                println!(
                    "approved {} (operation {})",
                    v["approval_id"].as_str().unwrap_or(id),
                    v["operation_id"].as_str().unwrap_or("?")
                );
                if let Some(result) = v.get("result") {
                    println!(
                        "result: {}",
                        serde_json::to_string_pretty(result).unwrap_or_default()
                    );
                }
            });
            Ok(())
        }
        ApprovalCmd::Deny { id } => {
            let value = call_daemon(methods::APPROVAL_DENY, Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!(
                    "denied {} (operation {})",
                    v["approval_id"].as_str().unwrap_or(id),
                    v["operation_id"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        ApprovalCmd::Watch => super::unsupported(
            cli,
            "approval watch",
            "live approval watching is unsupported; use `ownmesh approval list` for a one-shot query",
        ),
    }
}
