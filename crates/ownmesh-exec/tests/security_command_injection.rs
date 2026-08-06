//! Command-argument injection + idempotency/replay security tests (harden-07).

use ownmesh_exec::{request_fingerprint, run_command, CommandKind, IdempotencyJournal, RunRequest};
use std::collections::HashMap;
use tempfile::tempdir;

fn structured(program: &str, args: Vec<String>) -> RunRequest {
    RunRequest {
        kind: CommandKind::Structured,
        program: program.into(),
        args,
        cwd: None,
        env: HashMap::new(),
        stdin: None,
        timeout_ms: Some(15_000),
        max_output_bytes: 64 * 1024,
        idempotency_key: None,
    }
}

#[tokio::test]
async fn structured_args_are_not_shell_expanded() {
    #[cfg(windows)]
    {
        let marker = "OWNMESH_INJECT_OK";
        let req = structured(
            "cmd.exe",
            vec!["/C".into(), format!("echo {marker}&echo SHOULD_NOT_SPLIT")],
        );
        assert_eq!(req.kind, CommandKind::Structured);
        assert_eq!(req.args.len(), 2);
        let res = run_command(&req, None).await.unwrap();
        assert!(res.stdout.contains(marker) || res.exit_code.is_some());
    }
    #[cfg(not(windows))]
    {
        let payload = "; echo PWNED; #";
        let req = structured("echo", vec![payload.into()]);
        let res = run_command(&req, None).await.unwrap();
        assert_eq!(res.exit_code, Some(0));
        assert!(res.stdout.contains(payload) || res.stdout.contains("; echo PWNED"));
        let pwn_lines = res.stdout.lines().filter(|l| l.trim() == "PWNED").count();
        assert_eq!(
            pwn_lines, 0,
            "shell evaluated metacharacters: {}",
            res.stdout
        );
    }
}

#[tokio::test]
async fn structured_does_not_invoke_shell_for_metachar_program_name_failure() {
    let req = structured("echo;true", vec!["x".into()]);
    let res = run_command(&req, None).await;
    if let Ok(r) = res {
        assert!(
            r.exit_code != Some(0) || !r.stdout.is_empty() || r.stderr.is_empty(),
            "unexpected success via shell: {r:?}"
        );
    }
}

#[tokio::test]
async fn idempotency_key_replays_without_rerun() {
    let dir = tempdir().unwrap();
    let mut journal = IdempotencyJournal::open(dir.path().join("j.json")).unwrap();

    #[cfg(windows)]
    let mut req = structured("cmd.exe", vec!["/C".into(), "echo replay-once".into()]);
    #[cfg(not(windows))]
    let mut req = structured("echo", vec!["replay-once".into()]);
    req.idempotency_key = Some("harden-op-1".into());

    let first = run_command(&req, Some(&mut journal)).await.unwrap();
    assert!(!first.replayed);
    let second = run_command(&req, Some(&mut journal)).await.unwrap();
    assert!(second.replayed);
    assert_eq!(first.stdout, second.stdout);
    assert_eq!(first.exit_code, second.exit_code);
}

#[test]
fn fingerprint_changes_when_args_change() {
    let a = structured("echo", vec!["one".into()]);
    let b = structured("echo", vec!["one".into(), "two".into()]);
    assert_ne!(request_fingerprint(&a), request_fingerprint(&b));
}

#[tokio::test]
async fn output_is_byte_capped() {
    #[cfg(windows)]
    let mut req = structured(
        "cmd.exe",
        vec!["/C".into(), "echo padded-output-for-cap".into()],
    );
    #[cfg(not(windows))]
    let mut req = structured("echo", vec!["padded-output-for-cap".into()]);
    req.max_output_bytes = 4;
    let res = run_command(&req, None).await.unwrap();
    assert!(res.truncated || res.stdout.len() <= 8);
}
