//! `ownmesh grants` — list, show, revoke, and mint device-local grants.

use crate::cli::{Cli, GrantsCmd};
use crate::commands::admin_flow::run_admin_operation;
use crate::commands::ipc_util::{
    call_daemon_recoverable, emit_ipc_err, ipc_exit_code, print_value,
};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use serde_json::json;

pub fn dispatch_grants(cli: &Cli, cmd: &GrantsCmd) -> Result<(), ExitCode> {
    match cmd {
        GrantsCmd::List => match call_daemon_recoverable(cli, methods::GRANTS_LIST, None) {
            Ok(value) => {
                print_value(cli.json, &value, |v| {
                    let bounded = v["bounded_tool"].as_u64().unwrap_or(0);
                    let temporary = v["temporary"].as_u64().unwrap_or(0);
                    println!("bounded_tool: {bounded}");
                    println!("temporary: {temporary}");
                    if let Some(grants) = v["grants"].as_array() {
                        for grant in grants {
                            if let Some(id) = grant.get("id").and_then(|v| v.as_str()) {
                                let kind = grant
                                    .get("grant_type")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("temporary");
                                println!("{id} ({kind})");
                            }
                        }
                    }
                });
                Ok(())
            }
            Err(err) => Err(emit_ipc_err(cli, &err)),
        },
        GrantsCmd::Show { id } => {
            match call_daemon_recoverable(cli, methods::GRANTS_SHOW, Some(json!({ "id": id }))) {
                Ok(value) => {
                    print_value(cli.json, &value, |v| println!("{v}"));
                    Ok(())
                }
                Err(err) => Err(emit_ipc_err(cli, &err)),
            }
        }
        GrantsCmd::Revoke { id } => {
            match call_daemon_recoverable(cli, methods::GRANTS_REVOKE, Some(json!({ "id": id }))) {
                Ok(value) => {
                    print_value(cli.json, &value, |v| {
                        println!("revoked {}", v["revoked"].as_str().unwrap_or(id));
                    });
                    Ok(())
                }
                Err(err) if ipc_exit_code(&err) == ExitCode::DeviceOffline => {
                    Err(emit_ipc_err(cli, &err))
                }
                Err(err) => Err(emit_ipc_err(cli, &err)),
            }
        }
        GrantsCmd::Mint {
            tools,
            ttl_seconds,
            max_uses,
            workspace_id,
            idempotency_key,
        } => {
            let mut payload = json!({
                "tools": tools,
                "ttl_seconds": ttl_seconds,
                "max_uses": max_uses,
                "workspace_id": workspace_id,
                "idempotency_key": idempotency_key,
            });
            if let Some(object) = payload.as_object_mut() {
                object.retain(|_, value| !value.is_null());
            }
            run_admin_operation(
                cli,
                "ownmesh_grants_mint",
                payload,
                "bounded tool grant minted",
                false,
            )
        }
    }
}
