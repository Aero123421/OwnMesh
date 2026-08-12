//! `ownmesh logs` commands wired to ownmeshd `ops.logs.*` IPC.
//!
//! The daemon has always implemented log query across audit, journald, Windows
//! Event Log, Docker/Podman, file, and process providers, but no public surface
//! reached it — the capability was only callable by hand-crafting IPC. These
//! commands expose it, and `ownmesh_query_logs` exposes the same contract over
//! MCP.
//!
//! Query is a read: the provider runs on the device and returns one bounded
//! page. Log bodies are not uploaded anywhere by querying them.

use crate::cli::{Cli, LogsCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::json;

pub fn dispatch_logs(cli: &Cli, cmd: &LogsCmd) -> Result<(), ExitCode> {
    match cmd {
        LogsCmd::Providers => {
            let value = call_daemon(cli, "ops.logs.list_providers", None)?;
            print_value(cli.json, &value, |v| {
                let providers = v["providers"].as_array().cloned().unwrap_or_default();
                if providers.is_empty() {
                    println!("(no log providers available on this device)");
                } else {
                    for provider in providers {
                        println!("{}", provider.as_str().unwrap_or("?"));
                    }
                }
            });
            Ok(())
        }
        LogsCmd::Query {
            provider,
            cursor,
            limit,
            unit,
            channel,
            container,
        } => {
            let mut params = json!({ "provider": provider });
            if let Some(cursor) = cursor {
                params["cursor_offset"] = json!(cursor);
            }
            if let Some(limit) = limit {
                params["limit"] = json!(limit);
            }
            if let Some(unit) = unit {
                params["unit"] = json!(unit);
            }
            if let Some(channel) = channel {
                params["channel"] = json!(channel);
            }
            if let Some(container) = container {
                params["container"] = json!(container);
            }
            let value = call_daemon(cli, "ops.logs.query", Some(params))?;
            print_value(cli.json, &value, |v| {
                let entries = v["entries"].as_array().cloned().unwrap_or_default();
                if entries.is_empty() {
                    println!("(no entries)");
                }
                for entry in entries {
                    // Providers agree on `message`; timestamp/level are best effort.
                    let timestamp = entry["timestamp"].as_str().unwrap_or("");
                    let level = entry["level"].as_str().unwrap_or("");
                    let message = entry["message"].as_str().unwrap_or("");
                    match (timestamp.is_empty(), level.is_empty()) {
                        (true, true) => println!("{message}"),
                        (true, false) => println!("[{level}] {message}"),
                        (false, true) => println!("{timestamp}  {message}"),
                        (false, false) => println!("{timestamp}  [{level}] {message}"),
                    }
                }
                if v["truncated"].as_bool().unwrap_or(false) {
                    if let Some(next) = v["next_cursor"].as_u64() {
                        println!("(truncated; resume with --cursor {next})");
                    } else {
                        println!("(truncated)");
                    }
                }
            });
            Ok(())
        }
    }
}
