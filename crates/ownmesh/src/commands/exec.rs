//! `ownmesh exec` — policy-gated command execution via ownmeshd.

use crate::cli::{Cli, ExecArgs};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use serde_json::{json, Value};

pub fn run_exec(cli: &Cli, args: &ExecArgs) -> Result<(), ExitCode> {
    run_exec_with(cli, args, call_daemon)
}

fn run_exec_with(
    cli: &Cli,
    args: &ExecArgs,
    call_local_daemon: impl FnOnce(&str, Option<Value>) -> Result<Value, ExitCode>,
) -> Result<(), ExitCode> {
    if args.command.is_empty() {
        eprintln!("exec: command is required");
        return Err(ExitCode::UsageConfig);
    }
    if let Some(device) = &args.device {
        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "status": "not_implemented",
                    "command": "exec --device",
                    "device": device,
                    "message": "remote execution is unsupported; local execution refused",
                })
            );
        } else {
            eprintln!("exec: --device routing is not implemented; refusing local execution");
        }
        return Err(super::unsupported_exit("exec --device"));
    }
    let program = args.command[0].clone();
    let rest = args.command[1..].to_vec();
    let params = json!({
        "program": program,
        "args": rest,
        "cwd": args.cwd,
        "kind": if args.raw_shell { "raw_shell" } else { "structured" },
        "timeout_ms": args.timeout_ms,
        "idempotency_key": args.idempotency_key,
    });
    let value = call_local_daemon(methods::OPS_EXEC, Some(params))?;
    print_value(cli.json, &value, |v| {
        if v["approval_required"].as_bool() == Some(true) {
            println!(
                "approval required: {} (operation {})",
                v["approval_id"].as_str().unwrap_or("?"),
                v["operation_id"].as_str().unwrap_or("?")
            );
            println!("reason: {}", v["reason"].as_str().unwrap_or(""));
            println!("approve with: ownmesh approval approve <id>");
            return;
        }
        if let Some(result) = v.get("result") {
            if let Some(stdout) = result.get("stdout").and_then(|s| s.as_str()) {
                print!("{stdout}");
                if !stdout.ends_with('\n') && !stdout.is_empty() {
                    println!();
                }
            }
            if let Some(stderr) = result.get("stderr").and_then(|s| s.as_str()) {
                if !stderr.is_empty() {
                    eprint!("{stderr}");
                    if !stderr.ends_with('\n') {
                        eprintln!();
                    }
                }
            }
            if result["replayed"].as_bool() == Some(true) || v["replayed"].as_bool() == Some(true) {
                eprintln!("(replayed from idempotency journal)");
            }
        }
    });
    if value["approval_required"].as_bool() == Some(true) {
        // Pending approval is not a hard failure; surface as authorization-ish wait.
        return Err(ExitCode::Authorization);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::Commands;
    use clap::Parser;
    use std::cell::Cell;

    #[test]
    fn device_exec_fails_without_attempting_local_daemon() {
        let cli = Cli::try_parse_from([
            "ownmesh",
            "exec",
            "--device",
            "dev_remote",
            "--",
            "echo",
            "hello",
        ])
        .expect("device exec arguments should parse");
        let Commands::Exec(args) = cli.command.as_ref().expect("exec command") else {
            panic!("expected exec command");
        };
        let local_daemon_attempted = Cell::new(false);

        let result = run_exec_with(&cli, args, |_, _| {
            local_daemon_attempted.set(true);
            Ok(json!({}))
        });

        assert_eq!(result, Err(ExitCode::ProfileUnavailable));
        assert!(!local_daemon_attempted.get());
    }
}
