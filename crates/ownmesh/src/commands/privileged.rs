//! `ownmesh privileged` — install / status / uninstall for the networkless broker.

use crate::cli::{Cli, PrivilegedCmd};
use crate::commands::ipc_util::print_value;
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::Command;

pub fn dispatch_privileged(cli: &Cli, cmd: &PrivilegedCmd) -> Result<(), ExitCode> {
    match cmd {
        PrivilegedCmd::Install => run_install(cli),
        PrivilegedCmd::Status => run_status(cli),
        PrivilegedCmd::Uninstall => run_uninstall(cli),
    }
}

fn state_base() -> Result<PathBuf, String> {
    let paths = ownmesh_config::OwnMeshPaths::discover().map_err(|err| format!("paths: {err}"))?;
    paths
        .ensure_layout()
        .map_err(|err| format!("paths: failed to create state layout: {err}"))?;
    Ok(paths.state_dir.clone())
}

/// Structured JSON error body for privileged install/uninstall failures (`--json`).
fn privileged_failure_json(command: &str, message: &str) -> Value {
    json!({
        "schema_version": 1,
        "status": "error",
        "command": command,
        "message": message,
    })
}

fn emit_privileged_failure(cli: &Cli, command: &str, message: &str) {
    if cli.json {
        println!("{}", privileged_failure_json(command, message));
    } else {
        eprintln!("{message}");
    }
}

fn run_install(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base().map_err(|message| {
        emit_privileged_failure(cli, "privileged broker install", &message);
        ExitCode::UsageConfig
    })?;
    match invoke_broker(&["install", "--state-dir", &base.display().to_string()]) {
        Ok(0) => {
            let st = read_status_json(&base);
            if !st["installed"].as_bool().unwrap_or(false) {
                let message = "broker install did not establish a verified native service";
                emit_privileged_failure(cli, "privileged broker install", message);
                return Err(super::unsupported_exit("privileged broker install"));
            }
            print_value(cli.json, &st, |v| {
                println!(
                    "privileged broker installed endpoint={} kind={}",
                    v["endpoint"].as_str().unwrap_or("-"),
                    v["endpoint_kind"].as_str().unwrap_or("-")
                );
            });
            Ok(())
        }
        Ok(code) => {
            let message = format!(
                "broker service installation failed (exit {code}); no installed state recorded"
            );
            emit_privileged_failure(cli, "privileged broker install", &message);
            Err(super::unsupported_exit("privileged broker install"))
        }
        Err(()) => {
            let message = "ownmesh-broker is unavailable; broker service was not installed";
            emit_privileged_failure(cli, "privileged broker install", message);
            Err(super::unsupported_exit("privileged broker install"))
        }
    }
}

fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base().map_err(|message| {
        if cli.json {
            println!("{}", privileged_failure_json("privileged status", &message));
        } else {
            eprintln!("{message}");
        }
        ExitCode::UsageConfig
    })?;
    if !cli.json {
        if let Ok(0) = invoke_broker(&["status", "--state-dir", &base.display().to_string()]) {
            return Ok(());
        }
    }
    let st = read_status_json(&base);
    print_value(cli.json, &st, |v| {
        println!(
            "privileged status={} network={} endpoint={}",
            if v["installed"].as_bool().unwrap_or(false) {
                "installed"
            } else {
                "idle"
            },
            v["network"].as_str().unwrap_or("disabled"),
            v["endpoint"].as_str().unwrap_or("-")
        );
    });
    Ok(())
}

fn run_uninstall(cli: &Cli) -> Result<(), ExitCode> {
    let base = state_base().map_err(|message| {
        emit_privileged_failure(cli, "privileged broker uninstall", &message);
        ExitCode::UsageConfig
    })?;
    match invoke_broker(&["uninstall", "--state-dir", &base.display().to_string()]) {
        Ok(0) => {
            let message =
                "broker command returned success, but native service absence is not independently verified";
            emit_privileged_failure(cli, "privileged broker uninstall", message);
            Err(super::unsupported_exit("privileged broker uninstall"))
        }
        Ok(code) => {
            let message = format!(
                "broker service uninstall could not verify native service removal (exit {code})"
            );
            emit_privileged_failure(cli, "privileged broker uninstall", &message);
            Err(super::unsupported_exit("privileged broker uninstall"))
        }
        Err(()) => {
            let message = "ownmesh-broker is unavailable; native service removal was not attempted";
            emit_privileged_failure(cli, "privileged broker uninstall", message);
            Err(super::unsupported_exit("privileged broker uninstall"))
        }
    }
}

fn invoke_broker(args: &[&str]) -> Result<i32, ()> {
    let candidates = ["ownmesh-broker", "ownmesh-broker.exe"];
    for name in candidates {
        if let Ok(out) = Command::new(name).args(args).status() {
            return Ok(out.code().unwrap_or(1));
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in ["ownmesh-broker", "ownmesh-broker.exe"] {
                let path = dir.join(name);
                if path.exists() {
                    if let Ok(out) = Command::new(&path).args(args).status() {
                        return Ok(out.code().unwrap_or(1));
                    }
                }
            }
        }
    }
    Err(())
}

fn read_status_json(base: &std::path::Path) -> serde_json::Value {
    let path = base.join("broker").join("broker-install.json");
    if let Ok(raw) = std::fs::read_to_string(path) {
        if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(&raw) {
            // Historical markers and generated templates are not native service probes.
            value["installed"] = json!(false);
            value["network"] = json!("disabled");
            value["notes"] =
                json!(["native broker service state is unverified; reporting not installed"]);
            return value;
        }
    }
    json!({
        "installed": false,
        "network": "disabled",
        "endpoint": null,
        "endpoint_kind": "",
        "secret_present": base.join("broker").join("broker.secret").exists(),
        "notes": ["not installed; native service management is unsupported"],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_failure_payload_is_structured() {
        let v = privileged_failure_json(
            "privileged broker install",
            "broker service installation failed (exit 1); no installed state recorded",
        );
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["status"], "error");
        assert_eq!(v["command"], "privileged broker install");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("installation failed"),
            "{v}"
        );
    }

    #[test]
    fn json_uninstall_failure_payload_includes_command() {
        let v = privileged_failure_json(
            "privileged broker uninstall",
            "broker command returned success, but native service absence is not independently verified",
        );
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["status"], "error");
        assert_eq!(v["command"], "privileged broker uninstall");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("native service absence is not independently verified"),
            "{v}"
        );
    }
}
