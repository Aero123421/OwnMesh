//! `OwnMesh` device agent (`ownmeshd`) entrypoint.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod daemon;
mod runtime;

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

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the daemon in the foreground (default).
    Run,
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
    let code = match cli.command.unwrap_or(Commands::Run) {
        Commands::Run => match daemon::run_foreground() {
            Ok(()) => ExitCode::Success,
            Err(code) => code,
        },
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
    StdExitCode::from(code.code() as u8)
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
