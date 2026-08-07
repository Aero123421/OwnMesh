//! `ownmesh lockdown` / `unlock` / `tokens revoke`.

use crate::cli::{Cli, TokensCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::{canonicalize_principal_key, methods};
use serde_json::json;

pub fn run_lockdown(cli: &Cli) -> Result<(), ExitCode> {
    let value = call_daemon(methods::DAEMON_LOCKDOWN, None)?;
    print_value(cli.json, &value, |_| {
        println!("lockdown enabled — new operations denied");
        println!("recover locally with: ownmesh unlock");
    });
    Ok(())
}

pub fn run_unlock(cli: &Cli) -> Result<(), ExitCode> {
    let _ = cli;
    // Unlock is a human-operator method. No distinct OS/UI presence proof is available
    // on ordinary local IPC; fail closed rather than treating same-UID as human.
    let message = ownmesh_ipc::human_operator_disabled_message();
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "ok": false,
                "command": "unlock",
                "error": "human_presence_unavailable",
                "message": message,
            })
        );
    } else {
        eprintln!("unlock: {message}");
    }
    Err(ExitCode::UsageConfig)
}

pub fn dispatch_tokens(cli: &Cli, cmd: &TokensCmd) -> Result<(), ExitCode> {
    match cmd {
        TokensCmd::Revoke { principal } => {
            let canonical = canonicalize_principal_key(principal);
            if canonical.is_empty() || canonical != principal.as_str() {
                eprintln!(
                    "--principal must be the canonical server-assigned principal (got {principal:?}; canonical form is {canonical:?})"
                );
                return Err(ExitCode::UsageConfig);
            }
            let _ = canonical;
            let message = ownmesh_ipc::human_operator_disabled_message();
            if cli.json {
                println!(
                    "{}",
                    json!({
                        "schema_version": 1,
                        "ok": false,
                        "command": "tokens revoke",
                        "error": "human_presence_unavailable",
                        "message": message,
                    })
                );
            } else {
                eprintln!("tokens revoke: {message}");
            }
            Err(ExitCode::UsageConfig)
        }
    }
}
