//! Command dispatch.

mod approval;
mod config_cmd;
pub(crate) mod device_cmd;
mod doctor;
mod exec;
mod instance_cmd;
mod ipc_util;
mod lockdown;
pub(crate) mod login;
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
use serde_json::json;
use std::io::IsTerminal;

pub use status::run_status;

/// Canonical registry for CLI surfaces that hard-fail as unsupported.
///
/// `release/SUPPORTED_SURFACES.json` is statically checked against this list.
/// Keep this registry authoritative instead of counting function-call text.
///
/// v1.1.0 removed: setup, doctor, service lifecycle, and signed update surfaces.
pub const EXPLICIT_UNSUPPORTED_CLI_SURFACES: &[&str] = &[
    "approval approve",
    "approval deny",
    "policy preset",
    "unlock",
    "tokens revoke",
    "mcp serve",
];

/// Additional hard-error unsupported surfaces beyond the explicit stub registry.
///
/// Each entry is paired with a real dispatch/handler hard-error path (not a
/// soft fallback). Canonical names only — descriptive notes live in the
/// release manifest.
pub const ADDITIONAL_UNSUPPORTED_CLI_SURFACES: &[&str] = &[
    "device rename",
    "device labels",
    "exec --device",
    "session open <device>",
    "policy rule mutation",
];

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
        Some(Commands::Unlock) => lockdown::run_unlock(cli),
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
        if cli.json {
            println!(
                "{}",
                json!({
                    "schema_version": 1,
                    "ok": false,
                    "error": "interactive_terminal_required",
                    "message": "run an explicit subcommand when stdin/stdout is not an interactive terminal",
                })
            );
        } else {
            eprintln!(
                "ownmesh: no subcommand; an interactive terminal is required to launch the TUI"
            );
        }
        return Err(ExitCode::UsageConfig);
    }

    let current = std::env::current_exe().map_err(|err| {
        eprintln!("ownmesh: cannot locate the installed executable: {err}");
        ExitCode::Internal
    })?;
    let tui = current.with_file_name(format!("ownmesh-tui{}", std::env::consts::EXE_SUFFIX));
    if !tui.is_file() {
        eprintln!(
            "ownmesh: bundled TUI not found at {}; reinstall OwnMesh or run an explicit subcommand",
            tui.display()
        );
        return Err(ExitCode::ProfileUnavailable);
    }
    let status = std::process::Command::new(&tui).status().map_err(|err| {
        eprintln!("ownmesh: failed to launch {}: {err}", tui.display());
        ExitCode::Internal
    })?;
    if status.success() {
        Ok(())
    } else {
        eprintln!("ownmesh: TUI exited unsuccessfully ({status})");
        Err(ExitCode::Internal)
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
    match cmd {
        McpCmd::Serve { stdio } => stub(cli, "mcp serve", &format!("stdio={stdio}")),
    }
}

fn stub(cli: &Cli, command: &str, detail: &str) -> Result<(), ExitCode> {
    unsupported(cli, command, detail)
}

pub(crate) fn unsupported_exit(command: &str) -> ExitCode {
    // Registry membership is enforced in every build (not debug_assert-only).
    let registered = EXPLICIT_UNSUPPORTED_CLI_SURFACES.contains(&command)
        || ADDITIONAL_UNSUPPORTED_CLI_SURFACES.contains(&command);
    if registered {
        ExitCode::ProfileUnavailable
    } else {
        eprintln!(
            "internal error: unsupported CLI surface is absent from the canonical registry: {command}"
        );
        ExitCode::Internal
    }
}

pub(crate) fn unsupported(cli: &Cli, command: &str, detail: &str) -> Result<(), ExitCode> {
    let exit = unsupported_exit(command);
    if exit == ExitCode::Internal {
        return Err(exit);
    }
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "status": "not_implemented",
                "command": command,
                "message": detail,
            })
        );
    } else {
        eprintln!("ownmesh {command}: not implemented yet — {detail}");
    }
    Err(exit)
}

#[cfg(test)]
mod registry_tests {
    use super::{
        unsupported, unsupported_exit, ADDITIONAL_UNSUPPORTED_CLI_SURFACES,
        EXPLICIT_UNSUPPORTED_CLI_SURFACES,
    };
    use crate::cli::Cli;
    use clap::Parser;
    use ownmesh_domain::ExitCode;
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

    #[test]
    fn unregistered_unsupported_command_is_hard_error() {
        let cli = Cli::try_parse_from(["ownmesh", "status"]).expect("status parses");
        let err = unsupported(&cli, "not a registered surface", "should fail")
            .expect_err("unregistered surface must hard-error");
        assert_eq!(err, ExitCode::Internal);
        assert_eq!(
            unsupported_exit("an arbitrary string"),
            ExitCode::Internal,
            "custom hard-error handlers must also reject unregistered strings"
        );
    }

    #[test]
    fn registered_additional_surface_is_not_internal_error() {
        let cli = Cli::try_parse_from(["ownmesh", "status"]).expect("status parses");
        let err = unsupported(&cli, "device rename", "rename unavailable")
            .expect_err("registered additional surface still returns not-implemented");
        assert_eq!(err, ExitCode::ProfileUnavailable);
    }
}
