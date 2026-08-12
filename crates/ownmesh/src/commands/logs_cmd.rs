//! `ownmesh logs` commands wired to ownmeshd `ops.logs.*` IPC.
//!
//! The daemon has always implemented log query across audit, journald, Windows
//! Event Log, Docker/Podman, file, and process providers, but no public surface
//! reached it — the capability was only callable by hand-crafting IPC. These
//! commands expose it over authenticated local IPC.
//!
//! Query is a read: the provider runs on the device and returns one bounded
//! page. This command has no remote MCP route, so log bodies stay on the device.

use crate::cli::{Cli, LogsCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};

fn page_view(value: &Value) -> (Vec<String>, Option<u64>) {
    let lines = value["lines"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|line| line["text"].as_str().map(ToOwned::to_owned))
        .collect();
    let next = if value["exhausted"].as_bool() == Some(false) {
        value["next_cursor"]["offset"].as_u64()
    } else {
        None
    };
    (lines, next)
}

fn terminal_safe_log_line(line: &str) -> String {
    line.chars().fold(String::new(), |mut rendered, ch| {
        if ch.is_control() {
            rendered.extend(ch.escape_default());
        } else {
            rendered.push(ch);
        }
        rendered
    })
}

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
                let (lines, next) = page_view(v);
                if lines.is_empty() {
                    println!("(no entries)");
                }
                for line in lines {
                    println!("{}", terminal_safe_log_line(&line));
                }
                if let Some(next) = next {
                    println!("(more entries; resume with --cursor {next})");
                }
            });
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn daemon_log_page_contract_renders_text_and_cursor() {
        let value = json!({
            "lines": [
                { "line_no": 1, "text": "first", "cursor_after": { "provider": "audit", "offset": 1 } },
                { "line_no": 2, "text": "second", "cursor_after": { "provider": "audit", "offset": 2 } }
            ],
            "next_cursor": { "provider": "audit", "offset": 2 },
            "exhausted": false
        });
        assert_eq!(
            page_view(&value),
            (vec!["first".into(), "second".into()], Some(2))
        );
    }

    #[test]
    fn human_log_output_escapes_terminal_controls() {
        assert_eq!(
            terminal_safe_log_line("ok\u{1b}[31m\r\n日本語"),
            "ok\\u{1b}[31m\\r\\n日本語"
        );
    }
}
