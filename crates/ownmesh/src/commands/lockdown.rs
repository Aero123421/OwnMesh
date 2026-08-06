//! `ownmesh lockdown` / `unlock` / `tokens revoke`.

use crate::cli::{Cli, TokensCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
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
    let value = call_daemon(methods::DAEMON_UNLOCK, None)?;
    print_value(cli.json, &value, |_| {
        println!("lockdown cleared");
    });
    Ok(())
}

pub fn dispatch_tokens(cli: &Cli, cmd: &TokensCmd) -> Result<(), ExitCode> {
    match cmd {
        TokensCmd::Revoke { client } => {
            let value = call_daemon(methods::TOKEN_REVOKE, Some(json!({ "client": client })))?;
            print_value(cli.json, &value, |v| {
                println!("revoked client {}", v["revoked"].as_str().unwrap_or(client));
            });
            Ok(())
        }
    }
}
