//! `ownmesh lockdown` / `unlock` / `tokens revoke`.

use crate::cli::{Cli, TokensCmd, UnlockArgs};
use crate::commands::admin_flow::run_admin_operation;
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

pub fn run_unlock(cli: &Cli, args: &UnlockArgs) -> Result<(), ExitCode> {
    run_admin_operation(
        cli,
        "ownmesh_daemon_unlock",
        json!({ "idempotency_key": args.idempotency_key }),
        "lockdown lifted",
        false,
    )
}

pub fn dispatch_tokens(cli: &Cli, cmd: &TokensCmd) -> Result<(), ExitCode> {
    match cmd {
        TokensCmd::Revoke {
            principal,
            idempotency_key,
        } => {
            let canonical = canonicalize_principal_key(principal);
            if canonical.is_empty() || canonical != principal.as_str() {
                eprintln!(
                    "--principal must be the canonical server-assigned principal (got {principal:?}; canonical form is {canonical:?})"
                );
                return Err(ExitCode::UsageConfig);
            }
            run_admin_operation(
                cli,
                "ownmesh_token_revoke",
                json!({
                    "target_principal": canonical,
                    "idempotency_key": idempotency_key,
                }),
                "principal revoked",
                false,
            )
        }
    }
}
