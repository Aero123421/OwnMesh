//! `ownmesh workspace` commands wired to ownmeshd ops.workspace.* IPC.

use crate::cli::{Cli, WorkspaceCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::json;

pub fn dispatch_workspace(cli: &Cli, cmd: &WorkspaceCmd) -> Result<(), ExitCode> {
    match cmd {
        WorkspaceCmd::List => {
            let value = call_daemon(cli, "ops.workspace.list", None)?;
            print_value(cli.json, &value, |v| {
                let list = v["workspaces"].as_array().cloned().unwrap_or_default();
                if list.is_empty() {
                    println!("(no workspaces)");
                } else {
                    for w in list {
                        println!(
                            "{}  {}  {}",
                            w["id"].as_str().unwrap_or("?"),
                            w["root"].as_str().unwrap_or("?"),
                            w["label"].as_str().unwrap_or("-")
                        );
                    }
                }
            });
            Ok(())
        }
        WorkspaceCmd::Show { id } => {
            let value = call_daemon(cli, "ops.workspace.show", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            });
            Ok(())
        }
        WorkspaceCmd::Add { path, id, label } => {
            let mut params = json!({ "path": path });
            if let Some(id) = id {
                params["id"] = json!(id);
            }
            if let Some(label) = label {
                params["label"] = json!(label);
            }
            let value = call_daemon(cli, "ops.workspace.add", Some(params))?;
            print_value(cli.json, &value, |v| {
                println!(
                    "workspace {} root={}",
                    v["id"].as_str().unwrap_or("?"),
                    v["root"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        WorkspaceCmd::Update { id, path, label } => {
            let mut params = json!({ "id": id });
            if let Some(path) = path {
                params["path"] = json!(path);
            }
            if let Some(label) = label {
                params["label"] = json!(label);
            }
            let value = call_daemon(cli, "ops.workspace.update", Some(params))?;
            print_value(cli.json, &value, |v| {
                println!(
                    "updated {} root={}",
                    v["id"].as_str().unwrap_or("?"),
                    v["root"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        WorkspaceCmd::Remove { id } => {
            let value = call_daemon(cli, "ops.workspace.remove", Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!("removed {}", v["id"].as_str().unwrap_or("?"));
            });
            Ok(())
        }
    }
}
