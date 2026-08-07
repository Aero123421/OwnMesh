//! Adversarial persistence-failure tests for runtime dispatch handlers.
//!
//! Pre-execution persistence failures roll back completely. Once an external
//! operation starts, finalization failures must retain a durable non-retriable
//! marker while still returning the persistence error.

#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::doc_markdown,
    clippy::manual_let_else,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::type_complexity,
    clippy::unnested_or_patterns
)]

#[allow(dead_code)]
#[path = "../src/runtime.rs"]
mod runtime;

use ownmesh_config::OwnMeshPaths;
use ownmesh_ipc::{app_error, methods, ClientIdentity, IpcError};
use ownmesh_policy::{preset_document, AccessPreset};
use runtime::{session_methods, DaemonRuntime};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use tempfile::tempdir;

fn client(name: &str) -> ClientIdentity {
    ClientIdentity::new(name, "0.1.0")
}

fn block_path_as_dir(path: &Path) {
    if path.exists() {
        if path.is_file() {
            fs::remove_file(path).unwrap();
        } else {
            fs::remove_dir_all(path).unwrap();
        }
    }
    fs::create_dir_all(path).unwrap();
    fs::write(path.join(".keep"), b"block").unwrap();
}

fn fault_original_path(path: &Path) -> std::path::PathBuf {
    let mut original = path.as_os_str().to_os_string();
    original.push(".fault-injection-original");
    original.into()
}

fn block_atomic_write(path: &Path) {
    let original = fault_original_path(path);
    assert!(!original.exists(), "fault-injection backup already exists");
    if path.is_file() {
        fs::rename(path, &original).unwrap();
    }
    // A unique temp can still be created, but replacing this non-empty directory fails.
    block_path_as_dir(path);
}

fn unblock_atomic_write(path: &Path) {
    let original = fault_original_path(path);
    if path.is_dir() {
        fs::remove_dir_all(path).unwrap();
    }
    if original.is_file() {
        fs::rename(original, path).unwrap();
    }
}

fn assert_internal(err: IpcError, persisted: &str) {
    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INTERNAL, "unexpected message: {message}");
            assert!(
                message.to_ascii_lowercase().contains(persisted)
                    || message.to_ascii_lowercase().contains("persist"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error shape: {other:?}"),
    }
}

async fn enqueue_write(rt: &mut DaemonRuntime, key: Option<&str>) -> String {
    let mut params = json!({ "path": "approval.txt", "content": "approved" });
    if let Some(key) = key {
        params["idempotency_key"] = json!(key);
    }
    let queued = rt
        .dispatch(methods::OPS_FS_WRITE, Some(params), &client("local"))
        .await
        .expect("enqueue approval");
    assert_eq!(queued["approval_required"], true);
    queued["approval_id"].as_str().unwrap().to_owned()
}

async fn open_session(rt: &mut DaemonRuntime, who: &str, title: &str) -> String {
    rt.dispatch(
        session_methods::OPEN,
        Some(json!({ "title": title })),
        &client(who),
    )
    .await
    .expect("session.open")["id"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn corrupt_op_journal_fails_closed_on_runtime_open() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    fs::write(
        paths.state_dir.join("op-journal.json"),
        br#"{"uncertain":{"__ownmesh_operation_state":"in_progress""#,
    )
    .unwrap();

    let err = match DaemonRuntime::open(&paths) {
        Ok(_) => panic!("corrupt journal must not be forgotten"),
        Err(err) => err,
    };
    assert!(err.contains("operation journal"), "{err}");
}

#[tokio::test]
async fn policy_preset_persist_failure_keeps_complete_in_memory_policy() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let before = rt
        .dispatch(methods::POLICY_SHOW, None, &client("local"))
        .await
        .unwrap();
    let enforced_before = rt.enforces_workspace_for_test();

    block_atomic_write(&paths.policy_file());
    let err = rt
        .dispatch(
            methods::POLICY_PRESET,
            Some(json!({ "name": "full_access" })),
            &client("local"),
        )
        .await
        .expect_err("policy persist must fail");
    assert_internal(err, "policy");

    let after = rt
        .dispatch(methods::POLICY_SHOW, None, &client("local"))
        .await
        .unwrap();
    assert_eq!(after, before, "policy document must roll back");
    assert_eq!(
        rt.enforces_workspace_for_test(),
        enforced_before,
        "workspace enforcement must roll back"
    );
}

#[tokio::test]
async fn approval_enqueue_persist_failure_removes_in_memory_approval() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    block_atomic_write(&paths.state_dir.join("approvals.json"));
    let err = rt
        .dispatch(
            methods::OPS_FS_WRITE,
            Some(json!({ "path": "blocked.txt", "content": "no" })),
            &client("local"),
        )
        .await
        .expect_err("approval enqueue persist must fail");
    assert_internal(err, "approval");

    let listed = rt
        .dispatch(methods::APPROVAL_LIST, None, &client("local"))
        .await
        .unwrap();
    assert_eq!(listed["approvals"], json!([]));
    assert!(!paths.state_dir.join("workspace/blocked.txt").exists());
}

#[tokio::test]
async fn approval_deny_persist_failure_restores_pending_record() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let id = enqueue_write(&mut rt, None).await;
    let before = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();

    block_atomic_write(&paths.state_dir.join("approvals.json"));
    let err = rt
        .dispatch(
            methods::APPROVAL_DENY,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .expect_err("approval deny persist must fail");
    assert_internal(err, "approval");

    let after = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(after, before, "entire approval record must roll back");
}

#[tokio::test]
async fn grant_persist_failure_through_approval_handler_restores_all_memory() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let key = "grant-failure-key";
    let id = enqueue_write(&mut rt, Some(key)).await;
    let approval_before = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();

    block_atomic_write(&paths.state_dir.join("grants.json"));
    let err = rt
        .dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id, "temporary_grant": true })),
            &client("local"),
        )
        .await
        .expect_err("grant persist must fail");
    assert_internal(err, "grant");

    let approval_after = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(approval_after, approval_before);
    assert!(rt.grants_for_test().is_empty());
    assert!(!rt.has_op_journal_key_for_test(key));
    assert!(!paths.state_dir.join("workspace/approval.txt").exists());
}

#[tokio::test]
async fn approval_journal_final_persist_failure_retains_executing_marker() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let key = "approval-journal-failure";
    let id = enqueue_write(&mut rt, Some(key)).await;

    // First journal persist commits in-progress before execution; fault only the
    // second persist that would replace it with the completed result.
    rt.fail_op_journal_persist_on_nth_call_for_test(2);
    let err = rt
        .dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id, "temporary_grant": true })),
            &client("local"),
        )
        .await
        .expect_err("approval journal final persist must fail");
    assert_internal(err, "journal");

    let approval_after = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(approval_after["state"], "executing");
    assert!(approval_after["result"].is_null());
    assert_eq!(rt.grants_for_test().len(), 1);
    assert!(rt.op_journal_key_is_in_progress_for_test(key));
    assert_eq!(
        fs::read_to_string(paths.state_dir.join("workspace/approval.txt")).unwrap(),
        "approved"
    );

    let retry = rt
        .dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .expect_err("executing approval must not be retried");
    match retry {
        IpcError::Remote { code, .. } => assert_eq!(code, app_error::CONFLICT),
        other => panic!("unexpected retry error: {other:?}"),
    }

    let operation_retry = rt
        .dispatch(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "approval.txt",
                "content": "must-not-run-again",
                "idempotency_key": key,
            })),
            &client("local"),
        )
        .await
        .expect_err("idempotency retry must see approval's uncertain marker");
    match operation_retry {
        IpcError::Remote { code, .. } => assert_eq!(code, app_error::CONFLICT),
        other => panic!("unexpected operation retry error: {other:?}"),
    }
    assert_eq!(
        fs::read_to_string(paths.state_dir.join("workspace/approval.txt")).unwrap(),
        "approved"
    );

    drop(rt);
    let mut reloaded = DaemonRuntime::open(&paths).expect("reload executing marker");
    let durable = reloaded
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(durable["state"], "executing");
}

#[tokio::test]
async fn approval_record_persist_failure_restores_all_related_memory() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let key = "approval-record-failure";
    let id = enqueue_write(&mut rt, Some(key)).await;
    let approval_before = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();

    block_atomic_write(&paths.state_dir.join("approvals.json"));
    let err = rt
        .dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id, "temporary_grant": true })),
            &client("local"),
        )
        .await
        .expect_err("approval persist must fail");
    assert_internal(err, "approval");

    let approval_after = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(approval_after, approval_before);
    assert!(rt.grants_for_test().is_empty());
    assert!(!rt.has_op_journal_key_for_test(key));
    assert!(
        !paths.state_dir.join("workspace/approval.txt").exists(),
        "pre-execution marker failure must prevent the write"
    );

    unblock_atomic_write(&paths.state_dir.join("approvals.json"));
    drop(rt);
    let mut reloaded = DaemonRuntime::open(&paths).expect("reload compensated state");
    let durable_approval = reloaded
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(durable_approval, approval_before);
    assert!(reloaded.grants_for_test().is_empty());
    assert!(!reloaded.has_op_journal_key_for_test(key));
}

#[tokio::test]
async fn approval_final_record_persist_failure_retains_durable_executing_marker() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let id = enqueue_write(&mut rt, None).await;

    // First future write persists `executing`; the second faults final `approved`.
    rt.fail_approvals_persist_on_nth_call_for_test(2);
    let err = rt
        .dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .expect_err("final approval persist must fail");
    assert_internal(err, "approval");
    assert_eq!(
        fs::read_to_string(paths.state_dir.join("workspace/approval.txt")).unwrap(),
        "approved"
    );

    let current = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(current["state"], "executing");
    assert!(current["result"].is_null());

    drop(rt);
    let mut reloaded = DaemonRuntime::open(&paths).expect("reload executing marker");
    let durable = reloaded
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(durable["state"], "executing");
    let retry = reloaded
        .dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .expect_err("durable executing marker must reject retry");
    match retry {
        IpcError::Remote { code, .. } => assert_eq!(code, app_error::CONFLICT),
        other => panic!("unexpected retry error: {other:?}"),
    }
}

#[tokio::test]
async fn approvals_survive_restart_with_pending_and_decided_state() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let id = {
        let mut rt = DaemonRuntime::open(&paths).expect("runtime");
        enqueue_write(&mut rt, None).await
    };

    {
        let mut rt = DaemonRuntime::open(&paths).expect("reload pending approval");
        let pending = rt
            .dispatch(
                methods::APPROVAL_SHOW,
                Some(json!({ "id": id })),
                &client("local"),
            )
            .await
            .unwrap();
        assert_eq!(pending["state"], "pending");
        rt.dispatch(
            methods::APPROVAL_DENY,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .expect("persist denial");
    }

    let mut rt = DaemonRuntime::open(&paths).expect("reload denied approval");
    let denied = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(denied["state"], "denied");
    assert!(denied["decided_at_unix"].is_number());
}

#[tokio::test]
async fn approved_result_grant_and_journal_survive_restart() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let key = "approved-restart-key";
    let id = {
        let mut rt = DaemonRuntime::open(&paths).expect("runtime");
        let id = enqueue_write(&mut rt, Some(key)).await;
        rt.dispatch(
            methods::APPROVAL_APPROVE,
            Some(json!({ "id": id, "temporary_grant": true })),
            &client("local"),
        )
        .await
        .expect("approve");
        id
    };

    let mut rt = DaemonRuntime::open(&paths).expect("reload approved state");
    let approved = rt
        .dispatch(
            methods::APPROVAL_SHOW,
            Some(json!({ "id": id })),
            &client("local"),
        )
        .await
        .unwrap();
    assert_eq!(approved["state"], "approved");
    assert!(approved["result"].is_object());
    assert_eq!(rt.grants_for_test().len(), 1);
    assert!(rt.has_op_journal_key_for_test(key));
}

#[tokio::test]
async fn direct_pre_execution_marker_persist_failure_is_rollback_safe() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    rt.set_policy_for_test(preset_document(AccessPreset::FullAccess));
    let key = "operation-handler-key";
    let target = paths.state_dir.join("workspace/direct-pre-marker.txt");

    block_atomic_write(&paths.state_dir.join("op-journal.json"));
    let err = rt
        .dispatch(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "direct-pre-marker.txt",
                "content": "must-run-once",
                "idempotency_key": key,
            })),
            &client("local"),
        )
        .await
        .expect_err("pre-execution op journal persist must fail");
    assert_internal(err, "journal");
    assert!(!rt.has_op_journal_key_for_test(key));
    assert!(
        !target.exists(),
        "operation must not run before marker commit"
    );

    unblock_atomic_write(&paths.state_dir.join("op-journal.json"));
    let retry = rt
        .dispatch(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "direct-pre-marker.txt",
                "content": "must-run-once",
                "idempotency_key": key,
            })),
            &client("local"),
        )
        .await
        .expect("retry after restoring pre-execution persistence");
    assert_eq!(retry["replayed"], false);
    assert_eq!(fs::read_to_string(target).unwrap(), "must-run-once");
}

#[tokio::test]
async fn direct_final_persist_failure_retains_durable_non_retriable_marker() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let key = "direct-final-failure";
    let victim = paths.state_dir.join("workspace/delete-once.txt");
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    rt.set_policy_for_test(preset_document(AccessPreset::FullAccess));
    fs::write(&victim, b"delete me").unwrap();
    // First persist commits in-progress; second (completion) is faulted.
    rt.fail_op_journal_persist_on_nth_call_for_test(2);
    let err = rt
        .dispatch(
            methods::OPS_FS_DELETE,
            Some(json!({ "path": "delete-once.txt", "idempotency_key": key })),
            &client("local"),
        )
        .await
        .expect_err("completion persist must fail after delete");
    assert_internal(err, "journal");
    assert!(!victim.exists(), "external side effect must have occurred");
    assert!(rt.has_op_journal_key_for_test(key));
    assert!(rt.op_journal_key_is_in_progress_for_test(key));

    let retry = rt
        .dispatch(
            methods::OPS_FS_DELETE,
            Some(json!({ "path": "delete-once.txt", "idempotency_key": key })),
            &client("local"),
        )
        .await
        .expect_err("uncertain direct operation must reject retry");
    match retry {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::CONFLICT);
            assert!(message.contains("uncertain"), "{message}");
        }
        other => panic!("unexpected retry error: {other:?}"),
    }

    drop(rt);
    let mut reloaded = DaemonRuntime::open(&paths).expect("reload durable op marker");
    assert!(reloaded.op_journal_key_is_in_progress_for_test(key));
    let retry = reloaded
        .dispatch(
            methods::OPS_FS_DELETE,
            Some(json!({ "path": "delete-once.txt", "idempotency_key": key })),
            &client("local"),
        )
        .await
        .expect_err("reloaded uncertain marker must reject retry");
    match retry {
        IpcError::Remote { code, .. } => assert_eq!(code, app_error::CONFLICT),
        other => panic!("unexpected retry error: {other:?}"),
    }
}

#[tokio::test]
async fn every_session_mutation_handler_restores_complete_manager_on_persist_failure() {
    #[derive(Clone, Copy, Debug)]
    enum Case {
        Open,
        AttachController,
        Claim,
        Release,
        Give,
        Close,
        TerminateOne,
        TerminateAll,
        PushOutput,
        Write,
        Resize,
    }

    let cases = [
        Case::Open,
        Case::AttachController,
        Case::Claim,
        Case::Release,
        Case::Give,
        Case::Close,
        Case::TerminateOne,
        Case::TerminateAll,
        Case::PushOutput,
        Case::Write,
        Case::Resize,
    ];

    for case in cases {
        let dir = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(dir.path());
        paths.ensure_layout().unwrap();
        let mut rt = DaemonRuntime::open(&paths).expect("runtime");
        let (method, params, who) = match case {
            Case::Open => (
                session_methods::OPEN,
                json!({ "title": "must-roll-back" }),
                "owner",
            ),
            Case::AttachController | Case::Claim => {
                let id = open_session(&mut rt, "owner", "released").await;
                rt.dispatch(
                    session_methods::GIVE,
                    Some(json!({ "id": id, "to": "observer" })),
                    &client("owner"),
                )
                .await
                .unwrap();
                rt.dispatch(
                    session_methods::RELEASE,
                    Some(json!({ "id": id })),
                    &client("observer"),
                )
                .await
                .unwrap();
                if matches!(case, Case::AttachController) {
                    (
                        session_methods::ATTACH,
                        json!({ "id": id, "read_only": false }),
                        "owner",
                    )
                } else {
                    (session_methods::CLAIM, json!({ "id": id }), "owner")
                }
            }
            Case::Release => {
                let id = open_session(&mut rt, "owner", "release").await;
                (session_methods::RELEASE, json!({ "id": id }), "owner")
            }
            Case::Give => {
                let id = open_session(&mut rt, "owner", "give").await;
                (
                    session_methods::GIVE,
                    json!({ "id": id, "to": "observer" }),
                    "owner",
                )
            }
            Case::Close => {
                let id = open_session(&mut rt, "owner", "close").await;
                (session_methods::CLOSE, json!({ "id": id }), "owner")
            }
            Case::TerminateOne => {
                let id = open_session(&mut rt, "owner", "terminate-one").await;
                (session_methods::TERMINATE, json!({ "id": id }), "owner")
            }
            Case::TerminateAll => {
                let _ = open_session(&mut rt, "owner", "terminate-all-1").await;
                let _ = open_session(&mut rt, "owner", "terminate-all-2").await;
                (session_methods::TERMINATE, json!({ "all": true }), "owner")
            }
            Case::PushOutput => {
                let id = open_session(&mut rt, "owner", "push").await;
                (
                    session_methods::PUSH_OUTPUT,
                    json!({ "id": id, "data": "must disappear" }),
                    "owner",
                )
            }
            Case::Write => {
                let id = open_session(&mut rt, "owner", "write").await;
                (
                    session_methods::WRITE,
                    json!({ "id": id, "data": "must disappear" }),
                    "owner",
                )
            }
            Case::Resize => {
                let id = open_session(&mut rt, "owner", "resize").await;
                (
                    session_methods::RESIZE,
                    json!({ "id": id, "cols": 211, "rows": 77 }),
                    "owner",
                )
            }
        };
        let before: Value = rt.session_state_for_test();
        let sessions_path = paths.state_dir.join("sessions/sessions.json");
        block_atomic_write(&sessions_path);

        let err = rt
            .dispatch(method, Some(params), &client(who))
            .await
            .expect_err("session persist must fail");
        assert_internal(err, "session");
        assert_eq!(
            rt.session_state_for_test(),
            before,
            "{case:?} must restore the complete session manager"
        );
    }
}

#[tokio::test]
async fn lockdown_persist_failure_rolls_back_memory_and_returns_error() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    assert!(!rt.is_lockdown());

    block_path_as_dir(&paths.state_dir.join("lockdown.flag"));
    let err = rt
        .dispatch(methods::DAEMON_LOCKDOWN, None, &client("local"))
        .await
        .expect_err("lockdown persist must fail");
    assert_internal(err, "lockdown");
    assert!(!rt.is_lockdown());
}

#[tokio::test]
async fn unlock_persist_failure_rolls_back_memory_and_returns_error() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    fs::write(paths.state_dir.join("lockdown.flag"), b"1").unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    assert!(rt.is_lockdown());

    block_path_as_dir(&paths.state_dir.join("lockdown.flag"));
    let err = rt
        .dispatch(methods::DAEMON_UNLOCK, None, &client("local"))
        .await
        .expect_err("unlock persist must fail");
    assert_internal(err, "lockdown");
    assert!(rt.is_lockdown());
}

#[tokio::test]
async fn revoke_persist_failure_rolls_back_memory_and_returns_error() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let principal = "agent-to-revoke";

    block_atomic_write(&paths.state_dir.join("revoked-clients.json"));
    let err = rt
        .dispatch(
            methods::TOKEN_REVOKE,
            Some(json!({ "client": principal })),
            &client("local"),
        )
        .await
        .expect_err("revoke persist must fail");
    assert_internal(err, "revoked");
    assert!(!rt
        .revoked_clients_handle()
        .read()
        .expect("lock")
        .contains(principal));
}

#[tokio::test]
async fn successful_lockdown_and_revoke_still_persist() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    let body = rt
        .dispatch(
            methods::TOKEN_REVOKE,
            Some(json!({ "client": "bad-agent" })),
            &client("local"),
        )
        .await
        .expect("revoke ok");
    assert_eq!(body["ok"], true);
    assert!(rt
        .revoked_clients_handle()
        .read()
        .unwrap()
        .contains("bad-agent"));
    let raw = fs::read_to_string(paths.state_dir.join("revoked-clients.json")).unwrap();
    assert!(raw.contains("bad-agent"));

    let body = rt
        .dispatch(methods::DAEMON_LOCKDOWN, None, &client("local"))
        .await
        .expect("lockdown ok");
    assert_eq!(body["lockdown"], true);
    assert!(rt.is_lockdown());
    assert!(paths.state_dir.join("lockdown.flag").is_file());
}
