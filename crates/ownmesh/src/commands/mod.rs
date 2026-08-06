//! Command dispatch.

mod approval;
mod exec;
mod ipc_util;
mod lockdown;
mod policy_cmd;
mod privileged;
mod session_cmd;
mod status;

use crate::cli::{
    Cli, Commands, ConfigCmd, DeviceCmd, InstanceCmd, McpCmd, PrivilegedCmd, ProcessCmd,
    ProfileCmd, ServiceCmd, SessionCmd, TransferCmd, UpdateCmd, WorkspaceCmd,
};
use ownmesh_domain::ExitCode;
use serde_json::json;

pub use status::run_status;

/// Dispatch a parsed CLI invocation.
pub fn dispatch(cli: &Cli) -> Result<(), ExitCode> {
    match &cli.command {
        None => run_tui_launch(cli),
        Some(Commands::Status) => run_status(cli),
        Some(Commands::Setup) => stub(cli, "setup", "Interactive setup arrives in a later chapter."),
        Some(Commands::Login(args)) => stub(
            cli,
            "login",
            &format!(
                "OAuth login arrives in chapter 5 (device_flow={}).",
                args.device
            ),
        ),
        Some(Commands::Logout) => stub(cli, "logout", "Logout arrives with OAuth in chapter 5."),
        Some(Commands::Doctor) => stub(cli, "doctor", "Doctor diagnostics expand in later chapters."),
        Some(Commands::Lockdown) => lockdown::run_lockdown(cli),
        Some(Commands::Unlock) => lockdown::run_unlock(cli),
        Some(Commands::Tokens(cmd)) => lockdown::dispatch_tokens(cli, cmd),
        Some(Commands::Config(cmd)) => dispatch_config(cli, cmd),
        Some(Commands::Instance(cmd)) => dispatch_instance(cli, cmd),
        Some(Commands::Device(cmd)) => dispatch_device(cli, cmd),
        Some(Commands::Workspace(cmd)) => dispatch_workspace(cli, cmd),
        Some(Commands::Exec(args)) => exec::run_exec(cli, args),
        Some(Commands::Process(cmd)) => dispatch_process(cli, cmd),
        Some(Commands::Session(cmd)) => dispatch_session(cli, cmd),
        Some(Commands::Profile(cmd)) => dispatch_profile(cli, cmd),
        Some(Commands::Approval(cmd)) => approval::dispatch_approval(cli, cmd),
        Some(Commands::Policy(cmd)) => policy_cmd::dispatch_policy(cli, cmd),
        Some(Commands::Transfer(cmd)) => dispatch_transfer(cli, cmd),
        Some(Commands::Service(cmd)) => dispatch_service(cli, cmd),
        Some(Commands::Privileged(cmd)) => dispatch_privileged(cli, cmd),
        Some(Commands::Update(cmd)) => dispatch_update(cli, cmd),
        Some(Commands::Mcp(cmd)) => dispatch_mcp(cli, cmd),
        Some(Commands::Completion(args)) => stub(
            cli,
            "completion",
            &format!("completion for {:?} (later)", args.shell),
        ),
    }
}

fn run_tui_launch(cli: &Cli) -> Result<(), ExitCode> {
    // TUI binary is separate; CLI without args documents the hand-off.
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "status": "not_implemented",
                "command": "tui",
                "message": "Launch `ownmesh-tui` or install the combined entrypoint (chapter 13).",
            })
        );
    } else {
        println!(
            "OwnMesh TUI launches here in a later chapter. For now run `ownmesh-tui` or `ownmesh status`."
        );
    }
    Err(ExitCode::ProfileUnavailable)
}

fn dispatch_config(cli: &Cli, cmd: &ConfigCmd) -> Result<(), ExitCode> {
    match cmd {
        ConfigCmd::Get { key } => stub(cli, "config get", &format!("key={key}")),
        ConfigCmd::Set { key, value } => {
            // Never echo secret-looking values.
            let safe = if looks_secret(key) || looks_secret(value) {
                "[REDACTED]"
            } else {
                value.as_str()
            };
            stub(cli, "config set", &format!("key={key} value={safe}"))
        }
        ConfigCmd::Edit => stub(cli, "config edit", "editor integration later"),
        ConfigCmd::Validate => {
            match ownmesh_config::OwnMeshPaths::discover()
                .and_then(|p| ownmesh_config::load_config(&p).map(|c| (p, c)))
            {
                Ok((paths, cfg)) => {
                    if let Err(err) = cfg.validate() {
                        eprintln!("config invalid: {err}");
                        return Err(ExitCode::UsageConfig);
                    }
                    if let Err(err) = ownmesh_config::load_policy(&paths) {
                        eprintln!("policy invalid: {err}");
                        return Err(ExitCode::UsageConfig);
                    }
                    if cli.json {
                        println!(
                            "{}",
                            json!({"schema_version": 1, "ok": true, "config": paths.config_file()})
                        );
                    } else {
                        println!("config ok: {}", paths.config_file().display());
                    }
                    Ok(())
                }
                Err(err) => {
                    eprintln!("config error: {err}");
                    Err(ExitCode::UsageConfig)
                }
            }
        }
    }
}

fn dispatch_instance(cli: &Cli, cmd: &InstanceCmd) -> Result<(), ExitCode> {
    match cmd {
        InstanceCmd::Add { id, base_url } => {
            stub(cli, "instance add", &format!("{id} -> {base_url}"))
        }
        InstanceCmd::List => stub(cli, "instance list", "chapter 5"),
        InstanceCmd::Use { id } => stub(cli, "instance use", id),
        InstanceCmd::Remove { id } => stub(cli, "instance remove", id),
    }
}

fn dispatch_device(cli: &Cli, cmd: &DeviceCmd) -> Result<(), ExitCode> {
    match cmd {
        DeviceCmd::Enroll => stub(cli, "device enroll", "chapter 5"),
        DeviceCmd::List => stub(cli, "device list", "chapter 5"),
        DeviceCmd::Show { id } => stub(cli, "device show", id),
        DeviceCmd::Rename { id, name } => stub(cli, "device rename", &format!("{id} -> {name}")),
        DeviceCmd::Labels { id, labels } => {
            stub(cli, "device labels", &format!("{id} {labels:?}"))
        }
        DeviceCmd::RotateKey => stub(cli, "device rotate-key", "chapter 5"),
        DeviceCmd::Revoke { id } => stub(cli, "device revoke", id),
    }
}

fn dispatch_workspace(cli: &Cli, cmd: &WorkspaceCmd) -> Result<(), ExitCode> {
    match cmd {
        WorkspaceCmd::Add { path } => stub(cli, "workspace add", path),
        WorkspaceCmd::List => stub(cli, "workspace list", "chapter 6"),
        WorkspaceCmd::Show { id } => stub(cli, "workspace show", id),
        WorkspaceCmd::Update { id } => stub(cli, "workspace update", id),
        WorkspaceCmd::Remove { id } => stub(cli, "workspace remove", id),
    }
}

fn dispatch_process(cli: &Cli, cmd: &ProcessCmd) -> Result<(), ExitCode> {
    match cmd {
        ProcessCmd::Start { command } => stub(cli, "process start", &format!("{command:?}")),
        ProcessCmd::Status { id } => stub(cli, "process status", id),
        ProcessCmd::Logs { id } => stub(cli, "process logs", id),
        ProcessCmd::Stop { id } => stub(cli, "process stop", id),
    }
}

fn dispatch_session(cli: &Cli, cmd: &SessionCmd) -> Result<(), ExitCode> {
    session_cmd::dispatch_session(cli, cmd)
}

fn dispatch_profile(cli: &Cli, cmd: &ProfileCmd) -> Result<(), ExitCode> {
    match cmd {
        ProfileCmd::Scan => stub(cli, "profile scan", "chapter 11"),
        ProfileCmd::List => stub(cli, "profile list", "chapter 11"),
        ProfileCmd::Show { id } => stub(cli, "profile show", id),
        ProfileCmd::Login { id } => stub(cli, "profile login", id),
        ProfileCmd::Test { id } => stub(cli, "profile test", id),
        ProfileCmd::Start { id } => stub(cli, "profile start", id),
        ProfileCmd::Resume { id, native_id } => {
            stub(cli, "profile resume", &format!("{id} {native_id}"))
        }
    }
}

fn dispatch_transfer(cli: &Cli, cmd: &TransferCmd) -> Result<(), ExitCode> {
    match cmd {
        TransferCmd::Plan { source, dest } => {
            stub(cli, "transfer plan", &format!("{source} -> {dest}"))
        }
        TransferCmd::Send { source, dest } => {
            stub(cli, "transfer send", &format!("{source} -> {dest}"))
        }
        TransferCmd::List => stub(cli, "transfer list", "chapter 12"),
        TransferCmd::Status { id } => stub(cli, "transfer status", id),
        TransferCmd::Cancel { id } => stub(cli, "transfer cancel", id),
    }
}

fn dispatch_service(cli: &Cli, cmd: &ServiceCmd) -> Result<(), ExitCode> {
    match cmd {
        ServiceCmd::Install => stub(cli, "service install", "later"),
        ServiceCmd::Start => stub(cli, "service start", "later"),
        ServiceCmd::Stop => stub(cli, "service stop", "later"),
        ServiceCmd::Restart => stub(cli, "service restart", "later"),
        ServiceCmd::Status => stub(cli, "service status", "later"),
        ServiceCmd::Uninstall => stub(cli, "service uninstall", "later"),
    }
}

fn dispatch_privileged(cli: &Cli, cmd: &PrivilegedCmd) -> Result<(), ExitCode> {
    privileged::dispatch_privileged(cli, cmd)
}

fn dispatch_update(cli: &Cli, cmd: &UpdateCmd) -> Result<(), ExitCode> {
    match cmd {
        UpdateCmd::Check => stub(cli, "update check", "chapter 14"),
        UpdateCmd::Download => stub(cli, "update download", "chapter 14"),
        UpdateCmd::Apply => stub(cli, "update apply", "chapter 14"),
        UpdateCmd::Channel { name } => stub(cli, "update channel", &format!("{name:?}")),
    }
}

fn dispatch_mcp(cli: &Cli, cmd: &McpCmd) -> Result<(), ExitCode> {
    match cmd {
        McpCmd::Serve { stdio } => stub(cli, "mcp serve", &format!("stdio={stdio}")),
    }
}

fn stub(cli: &Cli, command: &str, detail: &str) -> Result<(), ExitCode> {
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
    Err(ExitCode::ProfileUnavailable)
}

fn looks_secret(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.contains("token")
        || lower.contains("secret")
        || lower.contains("password")
        || lower.contains("private")
}
