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
    // Remote device routing is not implemented. Fail closed: never fall back to
    // the local daemon when the operator explicitly targeted another device.
    reject_unimplemented_device(args.device.as_deref())?;
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

/// Reject `--device` without contacting the local daemon.
///
/// Extracted so unit tests can assert fail-closed behavior without IPC.
pub(crate) fn reject_unimplemented_device(device: Option<&str>) -> Result<(), ExitCode> {
    if let Some(device) = device {
        eprintln!(
            "exec: --device routing is not implemented yet (requested device: {device}); refusing to run on local daemon"
        );
        return Err(ExitCode::UsageConfig);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_flag_is_hard_error_not_local_fallback() {
        let err =
            reject_unimplemented_device(Some("dev_remote")).expect_err("--device must hard-error");
        assert_eq!(err, ExitCode::UsageConfig);
        assert_ne!(err.code(), 0);
    }

    #[test]
    fn device_absent_allows_local_path() {
        assert!(reject_unimplemented_device(None).is_ok());
    }

    #[test]
    fn run_exec_with_device_never_reaches_daemon() {
        // Construct minimal args; call_daemon would panic/fail if reached without a daemon.
        let cli = Cli {
            json: false,
            lang: None,
            command: None,
        };
        let args = ExecArgs {
            device: Some("dev_x".into()),
            cwd: None,
            idempotency_key: None,
            raw_shell: false,
            timeout_ms: None,
            command: vec!["echo".into(), "hi".into()],
        };
        let err = run_exec(&cli, &args).expect_err("must not fall back to local daemon");
        assert_eq!(err, ExitCode::UsageConfig);
        assert_ne!(err.code(), 0);
    }
}
