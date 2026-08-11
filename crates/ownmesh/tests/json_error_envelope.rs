//! `--json` failure contract.
//!
//! Every failing command must put exactly one parseable JSON object on stdout
//! carrying `schema_version`, `ok: false`, `exit_code`, and `error.code`.
//!
//! This used to hold for only a handful of commands: `status` omitted `ok` and
//! `exit_code`, `device list` printed plain text to stderr with no JSON at all,
//! and the codes came from three unrelated vocabularies. Automation could not
//! distinguish success from failure without parsing prose.

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;

/// Path to the `ownmesh` binary built alongside this test.
fn ownmesh_bin() -> PathBuf {
    // target/<profile>/deps/<test-exe> → target/<profile>/ownmesh
    let mut path = std::env::current_exe().expect("test executable path");
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join(format!("ownmesh{}", std::env::consts::EXE_SUFFIX))
}

/// An isolated, never-configured `OwnMesh` root so every command fails.
fn isolated_root() -> tempfile::TempDir {
    tempfile::tempdir().expect("temp dir")
}

fn run_json(root: &tempfile::TempDir, args: &[&str]) -> (i32, String, String) {
    let base = root.path();
    let output = Command::new(ownmesh_bin())
        .arg("--json")
        .args(args)
        .env("HOME", base)
        .env("USERPROFILE", base)
        .env("OWNMESH_CONFIG_DIR", base.join("config"))
        .env("OWNMESH_STATE_DIR", base.join("state"))
        .env("OWNMESH_RUNTIME_DIR", base.join("run"))
        // Keep the probe local: no control plane is configured in this root.
        .env_remove("OWNMESH_IPC_CLIENT_CREDENTIAL")
        .output()
        .expect("run ownmesh");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

/// Commands that cannot succeed on an unconfigured machine with no daemon.
const FAILING_COMMANDS: &[&[&str]] = &[
    &["status"],
    &["device", "list"],
    &["device", "show", "dev_missing"],
    &["workspace", "list"],
    &["session", "list"],
    &["approval", "list"],
    &["profile", "list"],
    &["process", "status", "op_missing"],
    &["transfer", "status", "tr_missing"],
    &["transfer", "list"],
    &["instance", "use", "not-configured"],
    &["config", "get", "definitely_not_a_key"],
    &["exec", "--device", "dev_missing", "--", "ls"],
    &["lockdown"],
    &["update", "channel", "not-a-channel"],
];

#[test]
fn every_failing_command_emits_exactly_one_conforming_envelope() {
    let bin = ownmesh_bin();
    assert!(
        bin.is_file(),
        "ownmesh binary not found at {}",
        bin.display()
    );

    for args in FAILING_COMMANDS {
        let root = isolated_root();
        let (code, stdout, stderr) = run_json(&root, args);
        let label = args.join(" ");

        assert_ne!(
            code, 0,
            "`{label}` unexpectedly succeeded\n{stdout}{stderr}"
        );

        let trimmed = stdout.trim();
        assert!(
            !trimmed.is_empty(),
            "`{label}` produced no JSON on stdout under --json (stderr: {stderr})"
        );

        let value: Value = serde_json::from_str(trimmed).unwrap_or_else(|err| {
            panic!("`{label}` stdout is not a single JSON object ({err}):\n{stdout}")
        });

        assert_eq!(
            value.get("ok").and_then(Value::as_bool),
            Some(false),
            "`{label}` must report ok=false:\n{stdout}"
        );
        assert_eq!(
            value.get("exit_code").and_then(Value::as_i64),
            Some(i64::from(code)),
            "`{label}` exit_code must match the process exit status:\n{stdout}"
        );
        assert!(
            value
                .get("schema_version")
                .and_then(Value::as_u64)
                .is_some(),
            "`{label}` must carry schema_version:\n{stdout}"
        );

        let error_code = value
            .get("error")
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("`{label}` must carry error.code:\n{stdout}"));
        assert!(
            error_code.starts_with("OWNMESH_"),
            "`{label}` error.code `{error_code}` must use the OWNMESH_* vocabulary"
        );

        let message = value
            .get("error")
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        assert!(
            !message.is_empty(),
            "`{label}` must carry a non-empty error.message:\n{stdout}"
        );
    }
}

/// Failure output must stay on stdout as JSON, never leak a second object.
#[test]
fn json_failures_do_not_print_two_envelopes() {
    let root = isolated_root();
    let (_, stdout, _) = run_json(&root, &["status"]);
    assert_eq!(
        stdout.trim().matches("\"schema_version\"").count(),
        1,
        "exactly one envelope expected:\n{stdout}"
    );
}

/// A command with a documented offline fallback must not emit a failure
/// envelope before succeeding.
///
/// `policy show` reads the local policy file when the daemon is unreachable.
/// Eager error emission printed an `ok: false` envelope immediately followed by
/// the successful payload — two JSON objects, exit status 0.
#[test]
fn recoverable_offline_fallback_emits_one_success_payload() {
    let root = isolated_root();
    for command in [
        &["policy", "show"][..],
        &["policy", "validate"][..],
        &["policy", "explain", "filesystem.read"][..],
    ] {
        let (code, stdout, stderr) = run_json(&root, command);
        let label = command.join(" ");
        assert_eq!(code, 0, "`{label}` should fall back cleanly:\n{stderr}");
        assert_eq!(
            stdout.trim().matches("\"schema_version\"").count(),
            1,
            "`{label}` must print exactly one object:\n{stdout}"
        );
        let value: Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|err| panic!("`{label}` stdout is not one JSON object ({err})"));
        assert_ne!(
            value.get("ok").and_then(Value::as_bool),
            Some(false),
            "`{label}` succeeded, so it must not report ok=false:\n{stdout}"
        );
    }
}

/// Without `--json`, failures stay human-readable on stderr and stdout is quiet.
#[test]
fn text_mode_keeps_diagnostics_on_stderr() {
    let root = isolated_root();
    let base = root.path();
    let output = Command::new(ownmesh_bin())
        .args(["status"])
        .env("HOME", base)
        .env("USERPROFILE", base)
        .env("OWNMESH_CONFIG_DIR", base.join("config"))
        .env("OWNMESH_STATE_DIR", base.join("state"))
        .env("OWNMESH_RUNTIME_DIR", base.join("run"))
        .output()
        .expect("run ownmesh");
    assert!(!output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stdout.trim().is_empty(),
        "stdout should stay quiet:\n{stdout}"
    );
    assert!(
        stderr.contains("ownmeshd"),
        "stderr should explain the failure:\n{stderr}"
    );
    assert!(
        stderr.contains("ownmesh service start"),
        "stderr should point at the supported service lifecycle:\n{stderr}"
    );
}
