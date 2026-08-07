use ownmesh_exec::{
    run_command, CommandKind, ExecError, IdempotencyJournal, RunRequest, RunResult,
};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn result(stdout: &str) -> RunResult {
    RunResult {
        exit_code: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
        timed_out: false,
        duration_ms: 1,
        truncated: false,
        replayed: false,
    }
}

fn marker_request(marker: &Path, key: &str) -> RunRequest {
    #[cfg(windows)]
    let (program, args) = (
        "cmd.exe".to_owned(),
        vec!["/C".into(), format!("echo ran>{}", marker.display())],
    );
    #[cfg(not(windows))]
    let (program, args) = (
        "/usr/bin/touch".to_owned(),
        vec![marker.to_string_lossy().into_owned()],
    );
    RunRequest {
        kind: CommandKind::Structured,
        program,
        args,
        cwd: None,
        env: HashMap::new(),
        stdin: None,
        timeout_ms: Some(10_000),
        max_output_bytes: 64 * 1024,
        idempotency_key: Some(key.into()),
    }
}

#[test]
fn legacy_untagged_completed_result_still_replays() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("legacy-journal.json");
    fs::write(
        &path,
        br#"{
            "legacy-key": {
                "exit_code": 0,
                "stdout": "legacy",
                "stderr": "",
                "timed_out": false,
                "duration_ms": 1,
                "truncated": false,
                "replayed": false
            }
        }"#,
    )
    .unwrap();

    let journal = IdempotencyJournal::open(path).unwrap();
    assert_eq!(journal.get("legacy-key"), Some(&result("legacy")));
    assert!(!journal.is_in_progress("legacy-key"));
}

#[test]
fn failed_persist_preserves_complete_memory_and_cannot_leak_later() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("journal.json");
    let blocked_original = dir.path().join("journal.fault-injection-original.json");
    let mut journal = IdempotencyJournal::open(&path).unwrap();

    let original = result("original");
    let untouched = result("untouched");
    journal.put("existing".into(), original.clone()).unwrap();
    journal.put("untouched".into(), untouched.clone()).unwrap();

    // Retain the committed file nearby and make the destination a non-empty directory.
    // This faults atomic replacement without guessing a per-operation temp name.
    fs::rename(&path, &blocked_original).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("blocker"), b"keep directory non-empty").unwrap();

    let insert_error = journal
        .put("uncommitted".into(), result("must-not-stick"))
        .expect_err("fault-injected persistence must fail");
    assert!(insert_error
        .to_string()
        .contains("failed to persist journal"));
    assert!(journal.get("uncommitted").is_none());
    assert_eq!(journal.get("existing"), Some(&original));
    assert_eq!(journal.get("untouched"), Some(&untouched));

    let replacement_error = journal
        .put("existing".into(), result("replacement-must-not-stick"))
        .expect_err("fault-injected replacement must fail");
    assert!(replacement_error
        .to_string()
        .contains("failed to persist journal"));
    assert_eq!(journal.get("existing"), Some(&original));
    assert_eq!(journal.get("untouched"), Some(&untouched));

    // A later successful flush must be based on the rolled-back snapshot, not
    // on either failed mutation.
    fs::remove_dir_all(&path).unwrap();
    fs::rename(&blocked_original, &path).unwrap();
    let committed_later = result("committed-later");
    journal
        .put("committed-later".into(), committed_later.clone())
        .unwrap();

    let reopened = IdempotencyJournal::open(&path).unwrap();
    assert_eq!(reopened.get("existing"), Some(&original));
    assert_eq!(reopened.get("untouched"), Some(&untouched));
    assert_eq!(reopened.get("committed-later"), Some(&committed_later));
    assert!(reopened.get("uncommitted").is_none());
}

#[test]
fn adversarial_directory_target_surfaces_error_without_mutating_memory() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("blocked-journal.json");
    let mut journal = IdempotencyJournal::open(&path).unwrap();

    // The path becomes invalid only after open, simulating an adversarial
    // filesystem change between loading and committing the journal.
    fs::create_dir(&path).unwrap();
    fs::write(path.join("blocker"), b"x").unwrap();

    let error = journal
        .put("never-committed".into(), result("nope"))
        .expect_err("a directory cannot be replaced by the journal file");
    assert!(error.to_string().contains("failed to persist journal"));
    assert!(journal.get("never-committed").is_none());
    assert!(path.is_dir());
}

#[tokio::test]
async fn run_command_does_not_spawn_when_pre_execution_marker_cannot_persist() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("run-journal.json");
    let marker = dir.path().join("process-ran");
    let mut journal = IdempotencyJournal::open(&path).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("blocker"), b"x").unwrap();

    let req = marker_request(&marker, "pre-execution-failure");
    let err = run_command(&req, Some(&mut journal))
        .await
        .expect_err("marker persist must fail before spawn");
    assert!(err.to_string().contains("failed to persist journal"));
    assert!(
        !marker.exists(),
        "process must not spawn before durable marker"
    );
    assert!(!journal.is_in_progress("pre-execution-failure"));

    fs::remove_dir_all(&path).unwrap();
    let result = run_command(&req, Some(&mut journal))
        .await
        .expect("retry is safe after pre-execution persist recovers");
    assert!(!result.replayed);
    assert!(marker.exists());
}

#[tokio::test]
async fn persisted_in_progress_marker_rejects_process_retry() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("uncertain-journal.json");
    fs::write(
        &path,
        br#"{"uncertain-key":{"__ownmesh_idempotency_state":"in_progress"}}"#,
    )
    .unwrap();
    let marker = dir.path().join("must-not-run");
    let req = marker_request(&marker, "uncertain-key");

    let mut journal = IdempotencyJournal::open(&path).unwrap();
    assert!(journal.is_in_progress("uncertain-key"));
    let err = run_command(&req, Some(&mut journal))
        .await
        .expect_err("uncertain key must reject retry");
    assert!(matches!(err, ExecError::IdempotencyConflict(ref key) if key == "uncertain-key"));
    assert!(!marker.exists());

    let reopened = IdempotencyJournal::open(&path).unwrap();
    assert!(reopened.is_in_progress("uncertain-key"));
}

#[test]
fn failed_completion_persist_restores_in_progress_memory_and_disk_marker() {
    let dir = tempdir().unwrap();
    let path = dir.path().join("completion-journal.json");
    let backup = dir.path().join("durable-in-progress.json");
    fs::write(
        &path,
        br#"{"uncertain-key":{"__ownmesh_idempotency_state":"in_progress"}}"#,
    )
    .unwrap();
    let mut journal = IdempotencyJournal::open(&path).unwrap();

    fs::rename(&path, &backup).unwrap();
    fs::create_dir(&path).unwrap();
    fs::write(path.join("blocker"), b"x").unwrap();
    let err = journal
        .put("uncertain-key".into(), result("completed-but-not-durable"))
        .expect_err("completion persist must fail");
    assert!(err.to_string().contains("failed to persist journal"));
    assert!(journal.is_in_progress("uncertain-key"));
    assert!(journal.get("uncertain-key").is_none());

    fs::remove_dir_all(&path).unwrap();
    fs::rename(&backup, &path).unwrap();
    let reopened = IdempotencyJournal::open(&path).unwrap();
    assert!(reopened.is_in_progress("uncertain-key"));
}
