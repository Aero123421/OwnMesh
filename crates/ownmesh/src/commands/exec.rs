//! `ownmesh exec` — policy-gated command execution via ownmeshd.

use crate::cli::{Cli, ExecArgs};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use serde_json::json;

pub fn run_exec(cli: &Cli, args: &ExecArgs) -> Result<(), ExitCode> {
    if args.command.is_empty() {
        eprintln!("exec: command is required");
        return Err(ExitCode::UsageConfig);
    }
    if args.device.is_some() {
        eprintln!("exec: --device routing is not implemented yet; using local daemon");
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
    let value = call_daemon(methods::OPS_EXEC, Some(params))?;
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
            if result["replayed"].as_bool() == Some(true) || v["replayed"].as_bool() == Some(true)
            {
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
