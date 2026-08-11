//! Command dispatch.

mod admin_flow;
mod approval;
mod config_cmd;
pub(crate) mod device_cmd;
mod doctor;
mod exec;
pub(crate) mod fail;
mod instance_cmd;
mod ipc_util;
mod lockdown;
pub(crate) mod login;
mod mcp;
mod mcp_client;
mod policy_cmd;
mod privileged;
mod process_cmd;
mod profile_cmd;
mod service;
mod session_cmd;
mod setup;
mod status;
mod transfer;
mod update_cmd;
mod workspace_cmd;

use crate::cli::{
    Cli, Commands, DeviceCmd, McpCmd, PrivilegedCmd, ServiceCmd, SessionCmd, TransferCmd,
    WorkspaceCmd,
};
use clap::CommandFactory;
use clap_complete::{generate, shells};
use ownmesh_domain::ExitCode;
use std::io::IsTerminal;

pub use fail::emit_fallback_envelope;
pub use status::run_status;

/// Canonical registry for CLI surfaces that hard-fail as unsupported.
///
/// `release/SUPPORTED_SURFACES.json` is statically checked against this list.
/// Keep this registry authoritative instead of counting function-call text.
///
/// v1.1.0 removed: setup, doctor, service lifecycle, and signed update surfaces.
#[allow(dead_code)]
pub const EXPLICIT_UNSUPPORTED_CLI_SURFACES: &[&str] = &[];

/// Additional hard-error unsupported surfaces beyond the explicit stub registry.
///
/// Each entry is paired with a real dispatch/handler hard-error path (not a
/// soft fallback). Canonical names only — descriptive notes live in the
/// release manifest.
#[allow(dead_code)]
pub const ADDITIONAL_UNSUPPORTED_CLI_SURFACES: &[&str] = &[];

/// Dispatch a parsed CLI invocation.
pub fn dispatch(cli: &Cli) -> Result<(), ExitCode> {
    match &cli.command {
        None => run_tui_launch(cli),
        Some(Commands::Status) => run_status(cli),
        Some(Commands::Setup(args)) => setup::run_setup(cli, args),
        Some(Commands::Login(args)) => login::run_login(cli, args),
        Some(Commands::Logout) => login::run_logout(cli),
        Some(Commands::Doctor(args)) => doctor::run_doctor_cmd(cli, args),
        Some(Commands::Lockdown) => lockdown::run_lockdown(cli),
        Some(Commands::Unlock(args)) => lockdown::run_unlock(cli, args),
        Some(Commands::Tokens(cmd)) => lockdown::dispatch_tokens(cli, cmd),
        Some(Commands::Config(cmd)) => config_cmd::dispatch_config(cli, cmd),
        Some(Commands::Instance(cmd)) => instance_cmd::dispatch_instance(cli, cmd),
        Some(Commands::Device(cmd)) => dispatch_device(cli, cmd),
        Some(Commands::Workspace(cmd)) => dispatch_workspace(cli, cmd),
        Some(Commands::Exec(args)) => exec::run_exec(cli, args),
        Some(Commands::Process(cmd)) => process_cmd::dispatch_process(cli, cmd),
        Some(Commands::Session(cmd)) => dispatch_session(cli, cmd),
        Some(Commands::Profile(cmd)) => profile_cmd::dispatch_profile(cli, cmd),
        Some(Commands::Approval(cmd)) => approval::dispatch_approval(cli, cmd),
        Some(Commands::Policy(cmd)) => policy_cmd::dispatch_policy(cli, cmd),
        Some(Commands::Transfer(cmd)) => dispatch_transfer(cli, cmd),
        Some(Commands::Service(cmd)) => dispatch_service(cli, cmd),
        Some(Commands::Privileged(cmd)) => dispatch_privileged(cli, cmd),
        Some(Commands::Update(cmd)) => update_cmd::dispatch_update(cli, cmd),
        Some(Commands::Mcp(cmd)) => dispatch_mcp(cli, cmd),
        Some(Commands::Completion(args)) => run_completion(args),
    }
}

fn run_tui_launch(cli: &Cli) -> Result<(), ExitCode> {
    if cli.json || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Err(fail::fail(
            cli,
            "OWNMESH_E_INTERACTIVE_TERMINAL_REQUIRED",
            "no subcommand: launching the TUI needs an interactive terminal",
            Some("run an explicit subcommand, e.g. `ownmesh status`"),
            ExitCode::UsageConfig,
        ));
    }

    let current = std::env::current_exe().map_err(|err| {
        fail::fail_with(
            cli,
            format!("ownmesh: cannot locate the installed executable: {err}"),
            None,
            ExitCode::Internal,
        )
    })?;
    let tui = current.with_file_name(format!("ownmesh-tui{}", std::env::consts::EXE_SUFFIX));
    if !tui.is_file() {
        return Err(fail::fail_with(
            cli,
            format!("ownmesh: bundled TUI not found at {}", tui.display()),
            Some("reinstall OwnMesh, or run an explicit subcommand"),
            ExitCode::ProfileUnavailable,
        ));
    }
    // The TUI renders its own chrome, so `--lang` has to reach it as an
    // argument: it is not otherwise propagated to the child process.
    let mut command = std::process::Command::new(&tui);
    if let Some(lang) = &cli.lang {
        command.arg("--lang").arg(lang);
    }
    let status = command.status().map_err(|err| {
        fail::fail_with(
            cli,
            format!("ownmesh: failed to launch {}: {err}", tui.display()),
            None,
            ExitCode::Internal,
        )
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(fail::fail_with(
            cli,
            format!("ownmesh: TUI exited unsuccessfully ({status})"),
            None,
            ExitCode::Internal,
        ))
    }
}

fn run_completion(args: &crate::cli::CompletionArgs) -> Result<(), ExitCode> {
    let mut command = Cli::command();
    let mut stdout = std::io::stdout();
    match args.shell {
        crate::cli::CompletionShell::Bash => {
            generate(shells::Bash, &mut command, "ownmesh", &mut stdout);
        }
        crate::cli::CompletionShell::Zsh => {
            generate(shells::Zsh, &mut command, "ownmesh", &mut stdout);
        }
        crate::cli::CompletionShell::Fish => {
            generate(shells::Fish, &mut command, "ownmesh", &mut stdout);
        }
        crate::cli::CompletionShell::Powershell => {
            generate(shells::PowerShell, &mut command, "ownmesh", &mut stdout);
        }
        crate::cli::CompletionShell::Elvish => {
            generate(shells::Elvish, &mut command, "ownmesh", &mut stdout);
        }
    }
    Ok(())
}

fn dispatch_device(cli: &Cli, cmd: &DeviceCmd) -> Result<(), ExitCode> {
    device_cmd::dispatch_device(cli, cmd)
}

fn dispatch_workspace(cli: &Cli, cmd: &WorkspaceCmd) -> Result<(), ExitCode> {
    workspace_cmd::dispatch_workspace(cli, cmd)
}

fn dispatch_session(cli: &Cli, cmd: &SessionCmd) -> Result<(), ExitCode> {
    session_cmd::dispatch_session(cli, cmd)
}

fn dispatch_transfer(cli: &Cli, cmd: &TransferCmd) -> Result<(), ExitCode> {
    transfer::dispatch_transfer(cli, cmd)
}

fn dispatch_service(cli: &Cli, cmd: &ServiceCmd) -> Result<(), ExitCode> {
    service::dispatch_service(cli, cmd)
}

fn dispatch_privileged(cli: &Cli, cmd: &PrivilegedCmd) -> Result<(), ExitCode> {
    privileged::dispatch_privileged(cli, cmd)
}

fn dispatch_mcp(cli: &Cli, cmd: &McpCmd) -> Result<(), ExitCode> {
    mcp::dispatch_mcp(cli, cmd)
}

#[cfg(test)]
mod registry_tests {
    use super::{ADDITIONAL_UNSUPPORTED_CLI_SURFACES, EXPLICIT_UNSUPPORTED_CLI_SURFACES};
    use serde_json::Value;
    use std::collections::HashSet;

    fn manifest() -> Value {
        let raw = include_str!("../../../../release/SUPPORTED_SURFACES.json");
        serde_json::from_str(raw).expect("SUPPORTED_SURFACES.json must parse")
    }

    fn string_list<'a>(value: &'a Value, key: &str) -> Vec<&'a str> {
        value[key]
            .as_array()
            .unwrap_or_else(|| panic!("{key} must be an array"))
            .iter()
            .map(|v| {
                v.as_str()
                    .unwrap_or_else(|| panic!("{key} entries must be strings"))
            })
            .collect()
    }

    #[test]
    fn registries_match_supported_surfaces_manifest() {
        let manifest = manifest();
        let explicit = string_list(&manifest, "explicit_unsupported_surfaces");
        let additional = string_list(&manifest, "additional_unsupported");

        assert_eq!(
            manifest["explicit_unsupported_count"].as_u64(),
            Some(explicit.len() as u64)
        );
        assert_eq!(
            explicit.len(),
            EXPLICIT_UNSUPPORTED_CLI_SURFACES.len(),
            "explicit unsupported count must match registry"
        );
        assert_eq!(
            additional.len(),
            ADDITIONAL_UNSUPPORTED_CLI_SURFACES.len(),
            "additional unsupported count must match registry"
        );
        assert_eq!(
            manifest["total_unsupported_surfaces"].as_u64(),
            Some((explicit.len() + additional.len()) as u64)
        );
        assert_eq!(
            manifest["explicit_unsupported_count"].as_u64(),
            Some(EXPLICIT_UNSUPPORTED_CLI_SURFACES.len() as u64),
        );

        assert_eq!(
            EXPLICIT_UNSUPPORTED_CLI_SURFACES,
            explicit.as_slice(),
            "explicit registry must match manifest order and contents exactly"
        );
        assert_eq!(
            ADDITIONAL_UNSUPPORTED_CLI_SURFACES,
            additional.as_slice(),
            "additional registry must match manifest order and contents exactly"
        );

        let explicit_set: HashSet<_> = EXPLICIT_UNSUPPORTED_CLI_SURFACES.iter().copied().collect();
        let additional_set: HashSet<_> = ADDITIONAL_UNSUPPORTED_CLI_SURFACES
            .iter()
            .copied()
            .collect();
        assert_eq!(
            explicit_set.len(),
            EXPLICIT_UNSUPPORTED_CLI_SURFACES.len(),
            "explicit registry must not contain duplicates"
        );
        assert_eq!(
            additional_set.len(),
            ADDITIONAL_UNSUPPORTED_CLI_SURFACES.len(),
            "additional registry must not contain duplicates"
        );
        assert!(
            explicit_set.is_disjoint(&additional_set),
            "explicit and additional registries must not overlap"
        );
    }
}
