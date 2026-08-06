//! OwnMesh CLI entrypoint.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate
)]

mod auth;
mod cli;
mod commands;

use clap::Parser;
use cli::Cli;
use ownmesh_domain::ExitCode;
use std::process::ExitCode as StdExitCode;

fn main() -> StdExitCode {
    init_tracing();
    let cli = Cli::parse();
    match commands::dispatch(&cli) {
        Ok(()) => StdExitCode::from(ExitCode::Success.code() as u8),
        Err(code) => StdExitCode::from(code.code() as u8),
    }
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[test]
    fn help_renders() {
        let mut cmd = Cli::command();
        let help = cmd.render_long_help().to_string().to_ascii_lowercase();
        for needle in [
            "login",
            "device",
            "session",
            "doctor",
            "transfer",
            "status",
            "policy",
            "privileged",
            "completion",
            "approval",
            "lockdown",
            "unlock",
            "tokens",
        ] {
            assert!(
                help.contains(needle),
                "missing {needle} in help/registration"
            );
        }
        let approval_help = cmd
            .find_subcommand_mut("approval")
            .expect("approval")
            .render_long_help()
            .to_string()
            .to_ascii_lowercase();
        assert!(approval_help.contains("approve"));
        assert!(approval_help.contains("deny"));
    }

    #[test]
    fn all_top_level_commands_parse() {
        let samples = [
            vec!["ownmesh", "status"],
            vec!["ownmesh", "login"],
            vec!["ownmesh", "login", "--device"],
            vec!["ownmesh", "logout"],
            vec!["ownmesh", "doctor"],
            vec!["ownmesh", "lockdown"],
            vec!["ownmesh", "unlock"],
            vec![
                "ownmesh",
                "tokens",
                "revoke",
                "--principal",
                "user:1000:exe:/usr/bin/ownmesh",
            ],
            vec!["ownmesh", "setup"],
            vec!["ownmesh", "config", "validate"],
            vec!["ownmesh", "config", "get", "lang"],
            vec!["ownmesh", "config", "set", "lang", "ja-JP"],
            vec!["ownmesh", "config", "edit"],
            vec!["ownmesh", "instance", "list"],
            vec!["ownmesh", "instance", "add", "home", "https://example.test"],
            vec!["ownmesh", "instance", "use", "home"],
            vec!["ownmesh", "instance", "remove", "home"],
            vec!["ownmesh", "device", "enroll"],
            vec!["ownmesh", "device", "list"],
            vec!["ownmesh", "device", "show", "dev_x"],
            vec!["ownmesh", "device", "rename", "dev_x", "laptop"],
            vec!["ownmesh", "device", "labels", "dev_x", "a=b"],
            vec!["ownmesh", "device", "rotate-key"],
            vec!["ownmesh", "device", "revoke", "dev_x"],
            vec!["ownmesh", "workspace", "list"],
            vec!["ownmesh", "workspace", "add", "/tmp/ws"],
            vec!["ownmesh", "workspace", "show", "ws_x"],
            vec!["ownmesh", "workspace", "update", "ws_x"],
            vec!["ownmesh", "workspace", "remove", "ws_x"],
            vec!["ownmesh", "exec", "--", "echo", "hi"],
            vec!["ownmesh", "process", "start", "sleep", "1"],
            vec!["ownmesh", "process", "status", "op_x"],
            vec!["ownmesh", "process", "logs", "op_x"],
            vec!["ownmesh", "process", "stop", "op_x"],
            vec!["ownmesh", "session", "list"],
            vec!["ownmesh", "session", "open"],
            vec!["ownmesh", "session", "show", "sess_x"],
            vec!["ownmesh", "session", "attach", "sess_x", "--read-only"],
            vec!["ownmesh", "session", "claim", "sess_x"],
            vec!["ownmesh", "session", "release", "sess_x"],
            vec!["ownmesh", "session", "give", "sess_x", "--to", "prin_x"],
            vec!["ownmesh", "session", "close", "sess_x"],
            vec!["ownmesh", "session", "terminate", "--all"],
            vec!["ownmesh", "profile", "scan"],
            vec!["ownmesh", "profile", "list"],
            vec!["ownmesh", "profile", "show", "codex"],
            vec!["ownmesh", "profile", "login", "codex"],
            vec!["ownmesh", "profile", "test", "codex"],
            vec!["ownmesh", "profile", "start", "codex"],
            vec!["ownmesh", "profile", "resume", "codex", "native_1"],
            vec!["ownmesh", "approval", "list"],
            vec!["ownmesh", "approval", "show", "apr_x"],
            vec!["ownmesh", "approval", "approve", "apr_x"],
            vec!["ownmesh", "approval", "approve", "apr_x", "--grant"],
            vec!["ownmesh", "approval", "deny", "apr_x"],
            vec!["ownmesh", "approval", "watch"],
            vec!["ownmesh", "policy", "show"],
            vec!["ownmesh", "policy", "preset", "recommended"],
            vec!["ownmesh", "policy", "rule", "allow-all"],
            vec!["ownmesh", "policy", "validate"],
            vec!["ownmesh", "policy", "explain", "exec"],
            vec!["ownmesh", "transfer", "plan", "a", "b"],
            vec!["ownmesh", "transfer", "send", "a", "b"],
            vec!["ownmesh", "transfer", "list"],
            vec!["ownmesh", "transfer", "status", "tr_x"],
            vec!["ownmesh", "transfer", "cancel", "tr_x"],
            vec!["ownmesh", "service", "install"],
            vec!["ownmesh", "service", "start"],
            vec!["ownmesh", "service", "stop"],
            vec!["ownmesh", "service", "restart"],
            vec!["ownmesh", "service", "status"],
            vec!["ownmesh", "service", "uninstall"],
            vec!["ownmesh", "privileged", "install"],
            vec!["ownmesh", "privileged", "status"],
            vec!["ownmesh", "privileged", "uninstall"],
            vec!["ownmesh", "update", "check"],
            vec!["ownmesh", "update", "download"],
            vec!["ownmesh", "update", "apply"],
            vec!["ownmesh", "update", "channel"],
            vec!["ownmesh", "mcp", "serve", "--stdio"],
            vec!["ownmesh", "completion", "bash"],
        ];

        for args in samples {
            Cli::try_parse_from(&args).unwrap_or_else(|err| {
                panic!("failed to parse {args:?}: {err}");
            });
        }
    }

    #[test]
    fn token_revoke_help_requires_server_assigned_principal() {
        let mut cmd = Cli::command();
        let tokens = cmd.find_subcommand_mut("tokens").expect("tokens");
        let revoke = tokens.find_subcommand_mut("revoke").expect("revoke");
        let help = revoke.render_long_help().to_string().to_ascii_lowercase();
        assert!(help.contains("--principal"), "{help}");
        assert!(help.contains("server-assigned"), "{help}");
        assert!(!help.contains("--client"), "{help}");
        assert!(!help.contains("e.g. chatgpt"), "{help}");
    }

    #[test]
    fn token_revoke_rejects_noncanonical_alias_before_ipc() {
        let cli = Cli {
            json: false,
            lang: None,
            command: Some(cli::Commands::Tokens(cli::TokensCmd::Revoke {
                principal: " ChatGPT ".into(),
            })),
        };
        assert_eq!(commands::dispatch(&cli), Err(ExitCode::UsageConfig));
    }

    #[test]
    fn approval_approve_registered_in_help() {
        let mut cmd = Cli::command();
        let approval = cmd
            .find_subcommand_mut("approval")
            .expect("approval command");
        let help = approval.render_help().to_string();
        assert!(help.contains("approve"));
        assert!(help.contains("deny"));
    }

    #[test]
    fn forward_http_deps_link() {
        // Ensure forward-declared auth/HTTP crates remain linked for om-04+.
        let _ = reqwest::Client::builder();
        let _ = url::Url::parse("https://example.test/").expect("url");
        let _ = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"x");
        let _ = uuid::Uuid::new_v4();
        let _ = webbrowser::Browser::Default;
        let _ = std::any::type_name::<oauth2::ClientId>();
        let _ = std::any::type_name::<sha2::Sha256>();
    }
}
