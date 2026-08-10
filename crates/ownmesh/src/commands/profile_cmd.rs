//! `ownmesh profile` commands backed by profile discovery and session IPC.

use crate::cli::{Cli, ProfileCmd};
use crate::commands::ipc_util::{call_daemon, print_value};
use ownmesh_domain::ExitCode;
use ownmesh_ipc::methods;
use serde_json::{json, Value};

const PROFILE_PAGE_LIMIT: usize = 64;

pub fn dispatch_profile(cli: &Cli, cmd: &ProfileCmd) -> Result<(), ExitCode> {
    dispatch_profile_with(cli, cmd, &call_daemon)
}

fn dispatch_profile_with(
    cli: &Cli,
    cmd: &ProfileCmd,
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
) -> Result<(), ExitCode> {
    match cmd {
        ProfileCmd::Scan | ProfileCmd::List => {
            let method = if matches!(cmd, ProfileCmd::Scan) {
                methods::PROFILE_SCAN
            } else {
                methods::PROFILE_LIST
            };
            let value = call_local_daemon(method, Some(json!({ "limit": PROFILE_PAGE_LIMIT })))?;
            print_value(cli.json, &value, |v| {
                let profiles = v["profiles"].as_array().cloned().unwrap_or_default();
                if profiles.is_empty() {
                    println!("(no profiles)");
                } else {
                    for profile in profiles {
                        println!(
                            "{}  {}  {}",
                            profile["id"].as_str().unwrap_or("?"),
                            if profile["detected"].as_bool() == Some(true) {
                                "installed"
                            } else {
                                "not found"
                            },
                            profile["binary_path"].as_str().unwrap_or("-")
                        );
                    }
                }
            });
            Ok(())
        }
        ProfileCmd::Show { id } => {
            let value = call_local_daemon(methods::PROFILE_SHOW, Some(json!({ "id": id })))?;
            print_value(cli.json, &value, |v| {
                println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
            });
            Ok(())
        }
        ProfileCmd::Start { id } => open_profile(cli, call_local_daemon, id, None),
        ProfileCmd::Resume { id, native_id } => {
            open_profile(cli, call_local_daemon, id, Some(native_id.as_str()))
        }
        ProfileCmd::Login { id } => unavailable(
            cli,
            "profile login",
            id,
            "ownmeshd exposes no credential-safe profile login IPC method",
        ),
        ProfileCmd::Test { id } => unavailable(
            cli,
            "profile test",
            id,
            "ownmeshd exposes no profile conformance-test IPC method",
        ),
    }
}

fn open_profile(
    cli: &Cli,
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
    profile_id: &str,
    native_session_id: Option<&str>,
) -> Result<(), ExitCode> {
    let value = call_local_daemon(
        "session.open",
        Some(json!({
            "title": format!("profile:{profile_id}"),
            "kind": "profile_agent",
            "profile_id": profile_id,
            "native_session_id": native_session_id,
            "adapter_mode": "auto",
        })),
    )?;
    print_value(cli.json, &value, |v| {
        println!(
            "profile {} session={} state={}",
            profile_id,
            v["id"].as_str().unwrap_or("?"),
            v["state"].as_str().unwrap_or("?")
        );
    });
    Ok(())
}

fn unavailable(cli: &Cli, command: &str, profile_id: &str, message: &str) -> Result<(), ExitCode> {
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "status": "unsupported",
                "code": "OWNMESH_E_PROFILE_METHOD_UNAVAILABLE",
                "command": command,
                "profile_id": profile_id,
                "message": message,
            })
        );
    } else {
        eprintln!("{command} {profile_id}: {message}");
    }
    Err(ExitCode::ProfileUnavailable)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    fn cli() -> Cli {
        Cli {
            json: true,
            lang: None,
            command: None,
        }
    }

    #[test]
    fn resume_uses_profile_session_contract() {
        let calls = RefCell::new(Vec::new());
        let cmd = ProfileCmd::Resume {
            id: "codex".into(),
            native_id: "native-7".into(),
        };
        dispatch_profile_with(&cli(), &cmd, &|method, params| {
            calls.borrow_mut().push((method.to_owned(), params));
            Ok(json!({ "id": "ses_1", "state": "running" }))
        })
        .expect("resume");

        let calls = calls.borrow();
        assert_eq!(calls[0].0, "session.open");
        let params = calls[0].1.as_ref().unwrap();
        assert_eq!(params["kind"], "profile_agent");
        assert_eq!(params["profile_id"], "codex");
        assert_eq!(params["native_session_id"], "native-7");
        assert_eq!(params["adapter_mode"], "auto");
    }

    #[test]
    fn login_fails_without_calling_daemon() {
        let called = Cell::new(false);
        let cmd = ProfileCmd::Login { id: "codex".into() };
        let result = dispatch_profile_with(&cli(), &cmd, &|_, _| {
            called.set(true);
            Ok(json!({}))
        });
        assert_eq!(result, Err(ExitCode::ProfileUnavailable));
        assert!(!called.get());
    }
}
