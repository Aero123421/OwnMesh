//! `ownmesh process` backed by the existing bounded `session.*` IPC contract.
//!
//! A process is a daemon-owned PTY session titled `process`. Passing argv as a
//! JSON array keeps execution shell-free; status, replay, and terminate reuse
//! the session ACL and lifecycle instead of creating a second process manager.

use crate::cli::{Cli, ProcessCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};

const PROCESS_TITLE: &str = "process";
const MAX_PROCESS_ARGC: usize = 256;
const MAX_PROCESS_ARG_BYTES: usize = 64 * 1024;
const MAX_PROCESS_SINGLE_ARG_BYTES: usize = 32 * 1024;
const LOG_PAGE_CHUNKS: usize = 64;
const LOG_PAGE_BYTES: usize = 64 * 1024;

pub fn dispatch_process(cli: &Cli, cmd: &ProcessCmd) -> Result<(), ExitCode> {
    dispatch_process_with(cli, cmd, &|method, params| call_daemon(cli, method, params))
}

fn dispatch_process_with(
    cli: &Cli,
    cmd: &ProcessCmd,
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
) -> Result<(), ExitCode> {
    match cmd {
        ProcessCmd::Start { command } => {
            if command.is_empty() {
                eprintln!("process start: command is required");
                return Err(ExitCode::UsageConfig);
            }
            let total_bytes = command
                .iter()
                .try_fold(0usize, |total, arg| total.checked_add(arg.len()))
                .ok_or(ExitCode::UsageConfig)?;
            if command.len() > MAX_PROCESS_ARGC
                || total_bytes > MAX_PROCESS_ARG_BYTES
                || command
                    .iter()
                    .any(|arg| arg.len() > MAX_PROCESS_SINGLE_ARG_BYTES || arg.contains('\0'))
            {
                eprintln!(
                    "process start: argv exceeds the bounded command contract ({MAX_PROCESS_ARGC} args / {MAX_PROCESS_ARG_BYTES} bytes)"
                );
                return Err(ExitCode::UsageConfig);
            }
            let value = call_local_daemon(
                "session.open",
                Some(json!({
                    "title": PROCESS_TITLE,
                    "kind": "pty",
                    "command": command,
                })),
            )?;
            print_value(cli.json, &value, |v| {
                println!(
                    "process {} state={}",
                    v["id"].as_str().unwrap_or("?"),
                    v["state"].as_str().unwrap_or("?")
                );
            });
            Ok(())
        }
        ProcessCmd::Status { id } => {
            let value = process_snapshot(call_local_daemon, id)?;
            print_value(cli.json, &value, |v| {
                println!(
                    "{} state={} pid={}",
                    id,
                    v["state"].as_str().unwrap_or("?"),
                    v["host_pid"]
                        .as_u64()
                        .map_or_else(|| "-".to_owned(), |pid| pid.to_string())
                );
            });
            Ok(())
        }
        ProcessCmd::Logs { id } => {
            // One explicit bounded page. The response retains next_seq/truncated
            // so JSON callers never mistake a partial page for complete output.
            let _ = process_snapshot(call_local_daemon, id)?;
            let value = call_local_daemon(
                "session.replay",
                Some(json!({
                    "id": id,
                    "from_seq": 1,
                    "limit": LOG_PAGE_CHUNKS,
                    "max_bytes": LOG_PAGE_BYTES,
                })),
            )?;
            print_value(cli.json, &value, |v| {
                if let Some(chunks) = v["chunks"].as_array() {
                    for chunk in chunks {
                        let data = chunk["data"].as_str().unwrap_or("");
                        if chunk["stream"].as_str() == Some("stderr") {
                            eprint!("{data}");
                        } else {
                            print!("{data}");
                        }
                    }
                }
                if v["truncated"].as_bool() == Some(true) {
                    eprintln!(
                        "\n(output truncated; next_seq={})",
                        v["next_seq"].as_u64().unwrap_or(0)
                    );
                }
            });
            Ok(())
        }
        ProcessCmd::Stop { id } => {
            let before = process_snapshot(call_local_daemon, id)?;
            if before["state"].as_str() == Some("closed") {
                print_stop(cli, id, true);
                return Ok(());
            }
            match call_local_daemon("session.terminate", Some(json!({ "id": id, "all": false }))) {
                Ok(value) => {
                    print_value(cli.json, &value, |_| println!("stopped {id}"));
                    Ok(())
                }
                Err(ExitCode::Conflict) => {
                    // Close/terminate can win between the snapshot and mutation.
                    // Reconcile once; an observed terminal state makes stop
                    // idempotent without retrying a side effect.
                    let after = process_snapshot(call_local_daemon, id)?;
                    if after["state"].as_str() == Some("closed") {
                        print_stop(cli, id, true);
                        Ok(())
                    } else {
                        Err(ExitCode::Conflict)
                    }
                }
                Err(err) => Err(err),
            }
        }
    }
}

fn process_snapshot(
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
    id: &str,
) -> Result<Value, ExitCode> {
    let value = call_local_daemon("session.show", Some(json!({ "id": id })))?;
    if value["title"].as_str() != Some(PROCESS_TITLE) {
        eprintln!("process {id}: id belongs to a non-process session");
        return Err(ExitCode::UsageConfig);
    }
    Ok(value)
}

fn print_stop(cli: &Cli, id: &str, replayed: bool) {
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "process_id": id,
                "stopped": true,
                "replayed": replayed,
            })
        );
    } else if replayed {
        println!("process {id} already stopped");
    } else {
        println!("stopped {id}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    fn cli() -> Cli {
        Cli {
            json: true,
            lang: None,
            command: None,
        }
    }

    #[test]
    fn start_passes_exact_argv_without_shell() {
        let calls = RefCell::new(Vec::new());
        let cmd = ProcessCmd::Start {
            command: vec!["tool".into(), "arg with spaces".into()],
        };
        dispatch_process_with(&cli(), &cmd, &|method, params| {
            calls.borrow_mut().push((method.to_owned(), params));
            Ok(json!({ "id": "ses_1", "state": "running" }))
        })
        .expect("start");

        let calls = calls.borrow();
        assert_eq!(calls[0].0, "session.open");
        assert_eq!(calls[0].1.as_ref().unwrap()["kind"], "pty");
        assert_eq!(
            calls[0].1.as_ref().unwrap()["command"],
            json!(["tool", "arg with spaces"])
        );
        assert!(calls[0].1.as_ref().unwrap().get("shell").is_none());
    }

    #[test]
    fn logs_request_is_explicitly_bounded() {
        let calls = RefCell::new(Vec::new());
        let cmd = ProcessCmd::Logs { id: "ses_1".into() };
        dispatch_process_with(&cli(), &cmd, &|method, params| {
            calls.borrow_mut().push((method.to_owned(), params));
            if method == "session.show" {
                Ok(json!({ "id": "ses_1", "title": PROCESS_TITLE, "state": "running" }))
            } else {
                Ok(json!({ "chunks": [], "truncated": false }))
            }
        })
        .expect("logs");

        let calls = calls.borrow();
        assert_eq!(calls[1].0, "session.replay");
        let params = calls[1].1.as_ref().unwrap();
        assert_eq!(params["limit"], json!(LOG_PAGE_CHUNKS));
        assert_eq!(params["max_bytes"], json!(LOG_PAGE_BYTES));
    }

    #[test]
    fn oversized_start_is_rejected_before_ipc() {
        use std::cell::Cell;

        let called = Cell::new(false);
        let cmd = ProcessCmd::Start {
            command: vec!["x".repeat(MAX_PROCESS_SINGLE_ARG_BYTES + 1)],
        };
        let result = dispatch_process_with(&cli(), &cmd, &|_, _| {
            called.set(true);
            Ok(json!({}))
        });
        assert_eq!(result, Err(ExitCode::UsageConfig));
        assert!(!called.get());
    }
}
