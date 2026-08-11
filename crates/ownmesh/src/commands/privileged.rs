//! `ownmesh privileged` — native broker lifecycle front-end.
//!
//! The actual authority stays in the root-owned `ownmesh-broker` program; this
//! command only locates that program and relays its verified lifecycle result.

use crate::cli::{Cli, PrivilegedCmd};
use ownmesh_domain::ExitCode;
use serde_json::{json, Value};
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos", windows))]
use std::process::Command;

pub fn dispatch_privileged(cli: &Cli, cmd: &PrivilegedCmd) -> Result<(), ExitCode> {
    match cmd {
        PrivilegedCmd::Install => run_install(cli),
        PrivilegedCmd::Status => run_status(cli),
        PrivilegedCmd::Uninstall => run_uninstall(cli),
    }
}

#[allow(dead_code)]
fn lifecycle_failure_json(command: &str, message: &str) -> Value {
    json!({
        "schema_version": 1,
        "status": "error",
        "command": command,
        "message": message,
        "broker": { "installed": false, "support": "unsupported", "network": "disabled" },
    })
}

fn run_install(cli: &Cli) -> Result<(), ExitCode> {
    run_native_backend(cli, "privileged broker install", &["install"])
}

fn run_status(cli: &Cli) -> Result<(), ExitCode> {
    run_native_backend(cli, "privileged broker status", &["status"])
}

fn run_uninstall(cli: &Cli) -> Result<(), ExitCode> {
    run_native_backend(cli, "privileged broker uninstall", &["uninstall"])
}

fn run_native_backend(cli: &Cli, command: &str, args: &[&str]) -> Result<(), ExitCode> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        if !effective_uid_is_root() {
            let message = "native privileged lifecycle requires root; re-run with sudo";
            if cli.json {
                println!("{}", lifecycle_failure_json(command, message));
            } else {
                eprintln!("{message}");
            }
            return Err(ExitCode::UsageConfig);
        }
        let broker = broker_binary().map_err(|e| {
            eprintln!("{e}");
            ExitCode::UsageConfig
        })?;
        let output = Command::new(broker).args(args).output().map_err(|e| {
            eprintln!("run native broker backend: {e}");
            ExitCode::UsageConfig
        })?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        if output.status.success() {
            Ok(())
        } else {
            Err(ExitCode::UsageConfig)
        }
    }
    #[cfg(windows)]
    {
        let _ = (cli, command);
        let broker = broker_binary().map_err(|e| {
            eprintln!("{e}");
            ExitCode::UsageConfig
        })?;
        let output = Command::new(broker).args(args).output().map_err(|e| {
            eprintln!("run native broker backend: {e}");
            ExitCode::UsageConfig
        })?;
        print!("{}", String::from_utf8_lossy(&output.stdout));
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
        if output.status.success() {
            Ok(())
        } else {
            Err(ExitCode::UsageConfig)
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let message =
            "unsupported: native privileged broker lifecycle is unavailable on this platform";
        if cli.json {
            println!("{}", lifecycle_failure_json(command, message));
        } else {
            eprintln!("{message}");
        }
        Err(ExitCode::UsageConfig)
    }
}

#[cfg(target_os = "linux")]
fn effective_uid_is_root() -> bool {
    std::fs::read_to_string("/proc/self/status").is_ok_and(|status| {
        status
            .lines()
            .find(|line| line.starts_with("Uid:"))
            .and_then(|line| line.split_whitespace().nth(2))
            .is_some_and(|uid| uid == "0")
    })
}

#[cfg(target_os = "macos")]
fn effective_uid_is_root() -> bool {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .is_ok_and(|output| output.status.success() && output.stdout == b"0\n")
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
fn broker_binary() -> Result<PathBuf, String> {
    #[cfg(windows)]
    {
        if let Some(program_files) = std::env::var_os("ProgramFiles") {
            let installed = PathBuf::from(program_files)
                .join("OwnMesh")
                .join("ownmesh-broker.exe");
            if installed.is_file() {
                return Ok(installed);
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        let installed = PathBuf::from("/usr/lib/ownmesh/ownmesh-broker");
        if installed.is_file() {
            return Ok(installed);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let installed =
            PathBuf::from("/Library/PrivilegedHelperTools/dev.ownmesh.privileged-broker");
        if installed.is_file() {
            return Ok(installed);
        }
    }
    let ownmesh =
        std::env::current_exe().map_err(|e| format!("resolve ownmesh executable: {e}"))?;
    let sibling = ownmesh.with_file_name(if cfg!(windows) {
        "ownmesh-broker.exe"
    } else {
        "ownmesh-broker"
    });
    if sibling.is_file() {
        Ok(sibling)
    } else {
        Err(
            "ownmesh-broker was not found beside ownmesh or at the fixed native installation path"
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_failure_payload_is_structured() {
        let v = lifecycle_failure_json("privileged broker install", "needs elevation");
        assert_eq!(v["schema_version"], 1);
        assert_eq!(v["status"], "error");
        assert_eq!(v["command"], "privileged broker install");
        assert!(
            v["message"].as_str().unwrap_or("").contains("elevation"),
            "{v}"
        );
        assert_eq!(v["broker"]["installed"], false);
    }

    #[test]
    fn json_uninstall_failure_payload_includes_command() {
        let v = lifecycle_failure_json(
            "privileged broker uninstall",
            "native service absence is not independently verified",
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
