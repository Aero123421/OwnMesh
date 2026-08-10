//! `ownmesh approval` — local approval queue via ownmeshd.

use crate::cli::{ApprovalCmd, Cli};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{human_operator_disabled_message, methods};
use serde_json::{json, Value};
use std::time::Duration;

const WATCH_INTERVAL: Duration = Duration::from_secs(2);

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
    dispatch_approval_with(cli, cmd, &call_daemon)
}

fn dispatch_approval_with(
    cli: &Cli,
    cmd: &ApprovalCmd,
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
) -> Result<(), ExitCode> {
    match cmd {
        ApprovalCmd::List => {
            let value = call_local_daemon(methods::APPROVAL_LIST, None)?;
            print_approval_snapshot(cli.json, &value);
            Ok(())
        }
        ApprovalCmd::Show { id } => {
            let value = call_local_daemon(methods::APPROVAL_SHOW, Some(json!({ "id": id })))?;
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
        ApprovalCmd::Watch => {
            watch_approval_changes(call_local_daemon, None, &std::thread::sleep, |value| {
                print_approval_snapshot(cli.json, value);
            })
        }
    }
}

fn print_approval_snapshot(json_mode: bool, value: &Value) {
    print_value(json_mode, value, |v| {
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
}

fn watch_approval_changes(
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
    max_iterations: Option<usize>,
    wait: &impl Fn(Duration),
    mut on_change: impl FnMut(&Value),
) -> Result<(), ExitCode> {
    let mut previous = None;
    let mut iteration = 0usize;
    loop {
        if max_iterations.is_some_and(|limit| iteration >= limit) {
            return Ok(());
        }

        let value = call_local_daemon(methods::APPROVAL_LIST, None)?;
        let Some(approvals) = value.get("approvals").and_then(Value::as_array) else {
            eprintln!("approval watch: approval.list returned an invalid result");
            return Err(ExitCode::Internal);
        };
        // Compare a stable id-ordered queue so inconsequential response ordering
        // and future wrapper metadata cannot generate noisy watch events.
        let mut canonical = approvals.clone();
        canonical.sort_by(|left, right| {
            left.get("id")
                .and_then(Value::as_str)
                .cmp(&right.get("id").and_then(Value::as_str))
        });
        let canonical = Value::Array(canonical);
        if previous.as_ref() != Some(&canonical) {
            on_change(&value);
            previous = Some(canonical);
        }

        iteration += 1;
        if max_iterations.is_some_and(|limit| iteration >= limit) {
            return Ok(());
        }
        wait(WATCH_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn watch_emits_only_changed_canonical_queues() {
        let responses = [
            json!({ "approvals": [{ "id": "apr_1", "state": "pending" }, { "id": "apr_2", "state": "pending" }] }),
            json!({ "approvals": [{ "id": "apr_2", "state": "pending" }, { "id": "apr_1", "state": "pending" }] }),
            json!({ "approvals": [{ "id": "apr_1", "state": "approved" }, { "id": "apr_2", "state": "pending" }] }),
        ];
        let index = Cell::new(0usize);
        let emitted = RefCell::new(Vec::new());

        watch_approval_changes(
            &|method, params| {
                assert_eq!(method, methods::APPROVAL_LIST);
                assert!(params.is_none());
                let current = index.get();
                index.set(current + 1);
                Ok(responses[current].clone())
            },
            Some(responses.len()),
            &|_| {},
            |value| emitted.borrow_mut().push(value.clone()),
        )
        .expect("bounded watch");

        let emitted = emitted.borrow();
        assert_eq!(emitted.len(), 2);
        assert_eq!(emitted[0]["approvals"][0]["id"], "apr_1");
        assert_eq!(emitted[1]["approvals"][0]["state"], "approved");
    }
}
