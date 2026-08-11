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
        ProfileCmd::Login { id } => open_profile_login(cli, call_local_daemon, id),
        ProfileCmd::Test { id } => test_profile(cli, call_local_daemon, id),
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

fn open_profile_login(
    cli: &Cli,
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
    profile_id: &str,
) -> Result<(), ExitCode> {
    // Login remains inside the profile's own interactive PTY. OwnMesh neither
    // reads nor copies the profile's credentials.
    let value = call_local_daemon(
        "session.open",
        Some(json!({
            "title": format!("profile-login:{profile_id}"),
            "kind": "profile_agent",
            "profile_id": profile_id,
            "adapter_mode": "pty",
        })),
    )?;
    let Some(session_id) = value.get("id").and_then(Value::as_str) else {
        eprintln!("profile login: session.open returned no session id");
        return Err(ExitCode::Internal);
    };
    let attach_command = format!("ownmesh session attach {session_id}");
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "profile_id": profile_id,
                "session_id": session_id,
                "state": value.get("state"),
                "adapter_mode": "pty",
                "attach_command": attach_command,
                "session": value,
            })
        );
    } else {
        println!(
            "profile {profile_id} login session={session_id} state={}",
            value["state"].as_str().unwrap_or("?")
        );
        println!("attach with: {attach_command}");
    }
    Ok(())
}

fn test_profile(
    cli: &Cli,
    call_local_daemon: &impl Fn(&str, Option<Value>) -> Result<Value, ExitCode>,
    profile_id: &str,
) -> Result<(), ExitCode> {
    // profile.show performs one bounded, read-only PATH/version probe. It does
    // not inspect or export credentials.
    let value = call_local_daemon(methods::PROFILE_SHOW, Some(json!({ "id": profile_id })))?;
    let Some(status) = value.get("status") else {
        eprintln!("profile test: profile.show returned no status");
        return Err(ExitCode::Internal);
    };
    let (Some(detected), Some(state)) = (
        status.get("detected").and_then(Value::as_bool),
        status.get("state").and_then(Value::as_str),
    ) else {
        eprintln!("profile test: profile.show returned an invalid status");
        return Err(ExitCode::Internal);
    };
    let passed = detected && state != "unsupported_version";
    if cli.json {
        println!(
            "{}",
            json!({
                "schema_version": 1,
                "profile_id": profile_id,
                "status": if passed { "pass" } else { "fail" },
                "detected": detected,
                "profile_state": state,
                "details": status,
            })
        );
    } else if passed {
        println!("PASS  {profile_id}  state={state}");
    } else {
        eprintln!("FAIL  {profile_id}  detected={detected} state={state}");
    }

    if passed {
        Ok(())
    } else {
        Err(ExitCode::ProfileUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

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
    fn login_opens_an_explicit_profile_pty() {
        let calls = RefCell::new(Vec::new());
        let cmd = ProfileCmd::Login { id: "codex".into() };
        dispatch_profile_with(&cli(), &cmd, &|method, params| {
            calls.borrow_mut().push((method.to_owned(), params));
            Ok(json!({ "id": "ses_login", "state": "running" }))
        })
        .expect("login PTY");

        let calls = calls.borrow();
        assert_eq!(calls[0].0, "session.open");
        let params = calls[0].1.as_ref().unwrap();
        assert_eq!(params["kind"], "profile_agent");
        assert_eq!(params["profile_id"], "codex");
        assert_eq!(params["adapter_mode"], "pty");
        assert!(params.get("prompt").is_none());
    }

    #[test]
    fn profile_test_rejects_an_unsupported_detected_version() {
        let cmd = ProfileCmd::Test { id: "codex".into() };
        let result = dispatch_profile_with(&cli(), &cmd, &|method, _| {
            assert_eq!(method, methods::PROFILE_SHOW);
            Ok(json!({
                "status": {
                    "detected": true,
                    "state": "unsupported_version"
                }
            }))
        });
        assert_eq!(result, Err(ExitCode::ProfileUnavailable));
    }
}
