//! `OwnMesh` device agent (`ownmeshd`) entrypoint.

#![forbid(unsafe_code)]
#![allow(
    clippy::assigning_clones,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::io_other_error,
    clippy::items_after_statements,
    clippy::manual_let_else,
    clippy::map_unwrap_or,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::single_match_else,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::unnecessary_wraps,
    clippy::unnested_or_patterns,
    clippy::unused_async,
    clippy::unused_self
)]

pub mod agent_transport;
mod daemon;
mod runtime;
pub mod transfer_crypto;

use clap::{Parser, Subcommand};
use ownmesh_domain::ExitCode;
use std::process::ExitCode as StdExitCode;

/// `OwnMesh` user-level device agent.
#[derive(Debug, Parser)]
#[command(
    name = "ownmeshd",
    version,
    about = "OwnMesh device agent — user-level daemon"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

/// Explicit layout binding for `ownmeshd run`.
///
/// A service descriptor must pin the daemon to the directories validated at
/// install time. Windows Scheduled Task actions cannot carry environment
/// variables safely, so the binding travels as typed arguments instead of an
/// injection-prone `cmd /c set ... &&` wrapper (#148). These take precedence
/// over `OWNMESH_*` environment variables.
#[derive(Debug, Default, clap::Args)]
// The `_dir` suffixes are the CLI contract: clap derives `--config-dir`,
// `--state-dir`, and `--runtime-dir` from these names, and they mirror
// `ownmesh_config::PathOverrides`.
#[allow(clippy::struct_field_names)]
struct PathArgs {
    /// Absolute configuration directory to bind this daemon to.
    #[arg(long, value_name = "DIR")]
    config_dir: Option<std::path::PathBuf>,
    /// Absolute durable-state directory to bind this daemon to.
    #[arg(long, value_name = "DIR")]
    state_dir: Option<std::path::PathBuf>,
    /// Absolute runtime directory (IPC endpoint) to bind this daemon to.
    #[arg(long, value_name = "DIR")]
    runtime_dir: Option<std::path::PathBuf>,
}

impl PathArgs {
    fn into_overrides(self) -> ownmesh_config::PathOverrides {
        ownmesh_config::PathOverrides {
            config_dir: self.config_dir,
            state_dir: self.state_dir,
            runtime_dir: self.runtime_dir,
        }
    }
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the daemon in the foreground (default).
    Run {
        #[command(flatten)]
        paths: PathArgs,
    },
    /// Print version and exit.
    Version,
    /// Show whether a local daemon appears reachable.
    Status,
    /// Manage cooperative-client credentials through the running daemon.
    Credentials {
        #[command(subcommand)]
        command: CredentialCommands,
    },
}

#[derive(Debug, Subcommand)]
enum CredentialCommands {
    /// Provision a client and print its one-time credential secret.
    ///
    /// The running daemon derives a namespaced principal and binds the attested OS user.
    Provision {
        /// Stable client id used for later rotate/revoke operations.
        client_id: String,
    },
    /// Rotate a client secret and print the replacement secret.
    Rotate {
        /// Stable client id to rotate.
        client_id: String,
    },
    /// Revoke a client credential and erase its persisted secret.
    Revoke {
        /// Stable client id to revoke.
        client_id: String,
    },
}

fn main() -> StdExitCode {
    init_tracing();
    let cli = Cli::parse();
    let code = match cli.command.unwrap_or_else(|| Commands::Run {
        paths: PathArgs::default(),
    }) {
        Commands::Run { paths } => {
            // Bind the layout before anything resolves it, so every later
            // `OwnMeshPaths::discover()` in this process agrees with the
            // descriptor that launched it.
            match ownmesh_config::install_path_overrides(&paths.into_overrides()) {
                Ok(()) => run_daemon(),
                Err(error) => {
                    tracing::error!(error = %error, "invalid path arguments");
                    ExitCode::UsageConfig
                }
            }
        }
        Commands::Version => {
            println!(
                "{name} {version}",
                name = env!("CARGO_PKG_NAME"),
                version = env!("CARGO_PKG_VERSION")
            );
            ExitCode::Success
        }
        Commands::Status => match daemon::probe_status() {
            Ok(()) => ExitCode::Success,
            Err(code) => code,
        },
        Commands::Credentials { command } => match command {
            CredentialCommands::Provision { client_id } => {
                match daemon::provision_client_credential(&client_id) {
                    Ok(secret) => {
                        // Intentional one-time delivery to the invoking administrator;
                        // the secret is never sent to tracing/log output.
                        println!("{secret}");
                        ExitCode::Success
                    }
                    Err(code) => code,
                }
            }
            CredentialCommands::Rotate { client_id } => {
                match daemon::rotate_client_credential(&client_id) {
                    Ok(secret) => {
                        // Intentional one-time delivery, not diagnostic logging.
                        println!("{secret}");
                        ExitCode::Success
                    }
                    Err(code) => code,
                }
            }
            CredentialCommands::Revoke { client_id } => {
                match daemon::revoke_client_credential(&client_id) {
                    Ok(()) => ExitCode::Success,
                    Err(code) => code,
                }
            }
        },
    };
    let status = u8::try_from(code.code()).unwrap_or(u8::MAX);
    StdExitCode::from(status)
}

fn run_daemon() -> ExitCode {
    #[cfg(windows)]
    {
        match ownmesh_ipc::run_ownmesh_daemon_service_dispatcher(run_foreground_exit) {
            Ok(ownmesh_ipc::WindowsServiceDispatcherOutcome::Dispatched) => ExitCode::Success,
            Ok(ownmesh_ipc::WindowsServiceDispatcherOutcome::NotService) => {
                match daemon::run_foreground() {
                    Ok(()) => ExitCode::Success,
                    Err(code) => code,
                }
            }
            Err(error) => {
                tracing::error!(error = %error, "Windows service dispatcher failed");
                ExitCode::Internal
            }
        }
    }
    #[cfg(not(windows))]
    {
        match daemon::run_foreground() {
            Ok(()) => ExitCode::Success,
            Err(code) => code,
        }
    }
}

#[cfg(windows)]
fn run_foreground_exit() -> Result<(), i32> {
    daemon::run_foreground().map_err(ownmesh_domain::ExitCode::code)
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    /// #148: a service descriptor binds the daemon's layout through typed
    /// arguments, so `ownmeshd run` must accept them and carry them into the
    /// process-wide overrides verbatim.
    #[test]
    fn run_accepts_a_typed_layout_binding() {
        let cli = Cli::try_parse_from([
            "ownmeshd",
            "run",
            "--config-dir",
            "/opt/profile/config",
            "--state-dir",
            "/opt/profile/state",
            "--runtime-dir",
            "/opt/profile/run",
        ])
        .expect("run must accept the descriptor's layout arguments");
        let Some(Commands::Run { paths }) = cli.command else {
            panic!("expected the run subcommand");
        };
        let overrides = paths.into_overrides();
        assert_eq!(
            overrides.config_dir.as_deref(),
            Some(std::path::Path::new("/opt/profile/config"))
        );
        assert_eq!(
            overrides.state_dir.as_deref(),
            Some(std::path::Path::new("/opt/profile/state"))
        );
        assert_eq!(
            overrides.runtime_dir.as_deref(),
            Some(std::path::Path::new("/opt/profile/run"))
        );
    }

    /// The arguments stay optional: a bare `run`, and the implicit default
    /// subcommand, must keep discovering the platform layout.
    #[test]
    fn run_without_a_layout_binding_stays_unbound() {
        let cli = Cli::try_parse_from(["ownmeshd", "run"]).unwrap();
        let Some(Commands::Run { paths }) = cli.command else {
            panic!("expected the run subcommand");
        };
        assert!(paths.into_overrides().is_empty());
        assert!(Cli::try_parse_from(["ownmeshd"]).unwrap().command.is_none());
    }

    #[test]
    fn cli_help_has_run() {
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("run") || help.contains("Run"));
    }

    #[test]
    fn credential_lifecycle_commands_have_no_identity_override_flags() {
        for args in [
            vec!["ownmeshd", "credentials", "provision", "agent-a"],
            vec!["ownmeshd", "credentials", "rotate", "agent-a"],
            vec!["ownmeshd", "credentials", "revoke", "agent-a"],
        ] {
            Cli::try_parse_from(args).unwrap();
        }
        for forbidden in ["--principal", "--user-id"] {
            assert!(Cli::try_parse_from([
                "ownmeshd",
                "credentials",
                "provision",
                "agent-a",
                forbidden,
                "attacker-chosen",
            ])
            .is_err());
        }
    }
}
