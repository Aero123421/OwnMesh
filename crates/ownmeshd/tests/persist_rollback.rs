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

use ownmesh_config::{save_policy, OwnMeshPaths, PolicyFile};
use ownmesh_ipc::{app_error, methods, ClientIdentity, IpcError};
use ownmesh_policy::{preset_document, AccessPreset};
use runtime::{ops_methods, session_methods, DaemonRuntime};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
/// Owner-only tempdir: `tempfile` respects the process umask, and the daemon
/// custody attestation rejects group/world-writable ancestors, so tests pin
/// mode 0700 to stay umask-independent.
fn tempdir() -> std::io::Result<tempfile::TempDir> {
    let dir = tempfile::tempdir()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(dir)
}

fn client(name: &str) -> ClientIdentity {
    ClientIdentity::new(name, "0.1.0")
}

/// Direct-dispatch human principal for approval.approve/deny runtime gates.
fn human(name: &str) -> ClientIdentity {
    let principal = if name.starts_with("user:") {
        name.to_owned()
    } else {
        format!("user:{name}")
    };
    ClientIdentity::new(principal, "0.1.0")
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

async fn enqueue_approval_bridge(
    rt: &mut DaemonRuntime,
    target_approval_id: &str,
    operation_id: &str,
    key: &str,
) -> Result<Value, IpcError> {
    let remote = ClientIdentity::new("client:remote:ten_test:owner_test", "1.0");
    rt.dispatch_cancellable_bound_with_generation(
        methods::ADMIN_APPROVAL_BRIDGE_REQUEST,
        Some(json!({
            "approval_id": target_approval_id,
            "decision": "approve",
            "temporary_grant": false,
            "idempotency_key": key,
        })),
        &remote,
        None,
        Some(operation_id.into()),
        Some(i64::MAX),
        Some("a".repeat(64)),
        Some("dev_testbridge".into()),
        Some(1),
    )
    .await
}

#[tokio::test]
async fn bridge_outer_receipt_failure_never_reopens_completed_target() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let target_id = enqueue_write(&mut rt, Some("local-write-bridge-1")).await;
    let bridge = enqueue_approval_bridge(
        &mut rt,
        &target_id,
        "op_bridge_receipt_failure_1",
        "bridge-outer-1",
    )
    .await
    .expect("bridge queued");
    let bridge_id = bridge["approval_id"].as_str().unwrap().to_owned();

    // outer begin, target begin, target completion, then outer completion.
    rt.fail_op_journal_persist_on_nth_call_for_test(4);
    let err = rt
        .apply_control_plane_approval_decision(Some(json!({
            "approval_id": bridge_id,
            "target_operation_id": "op_bridge_receipt_failure_1",
            "decision": "approve",
            "target_payload_hash": "a".repeat(64),
            "approver_principal": "owner_test",
        })))
        .await
        .expect_err("outer receipt persist must fail");
    assert_internal(err, "op journal");
    assert_eq!(
        fs::read_to_string(paths.state_dir.join("workspace/approval.txt")).unwrap(),
        "approved"
    );

    let listed = rt
        .dispatch(methods::APPROVAL_LIST, None, &client("local"))
        .await
        .unwrap();
    let approvals = listed["approvals"].as_array().unwrap();
    assert_eq!(
        approvals
            .iter()
            .find(|record| record["id"] == target_id)
            .and_then(|record| record["state"].as_str()),
        Some("approved"),
        "completed target must remain terminal in memory"
    );

    let retry = enqueue_approval_bridge(
        &mut rt,
        &target_id,
        "op_bridge_receipt_failure_2",
        "bridge-outer-2",
    )
    .await
    .expect_err("a second bridge must not re-enter the completed target");
    assert!(matches!(
        retry,
        IpcError::Remote {
            code: app_error::CONFLICT,
            ..
        }
    ));

    drop(rt);
    let mut reopened = DaemonRuntime::open(&paths).expect("restart runtime");
    let retry_after_restart = enqueue_approval_bridge(
        &mut reopened,
        &target_id,
        "op_bridge_receipt_failure_3",
        "bridge-outer-3",
    )
    .await
    .expect_err("durable target state must stay terminal after restart");
    assert!(matches!(
        retry_after_restart,
        IpcError::Remote {
            code: app_error::CONFLICT,
            ..
        }
    ));
}

#[tokio::test]
async fn delegated_remote_mcp_executes_exact_bound_ask_without_local_approval() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    save_policy(
        &paths,
        &PolicyFile {
            schema_version: 1,
            preset: Some("recommended".into()),
            delegate_remote_mcp: true,
            rules: Vec::new(),
        },
    )
    .unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let remote = ClientIdentity::new("client:remote:oauth-principal", "1.0");

    let allowed = rt
        .dispatch_cancellable_bound(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "delegated.txt",
                "content": "exact-bound",
                "idempotency_key": "delegated-write-1",
            })),
            &remote,
            None,
            Some("op_delegated_1".into()),
            Some(i64::MAX),
            Some("a".repeat(64)),
            None,
        )
        .await
        .expect("delegated exact-bound write executes");
    assert_eq!(allowed["approval_required"], false);
    assert_eq!(
        fs::read_to_string(paths.state_dir.join("workspace").join("delegated.txt")).unwrap(),
        "exact-bound"
    );

    let unbound = rt
        .dispatch_cancellable_bound(
            methods::OPS_FS_WRITE,
            Some(json!({ "path": "unbound.txt", "content": "must-ask" })),
            &remote,
            None,
            Some("op_delegated_2".into()),
            None,
            None,
            None,
        )
        .await
        .expect("unbound write is queued instead of delegated");
    assert_eq!(unbound["approval_required"], true);
}

async fn open_session(rt: &mut DaemonRuntime, who: &str, title: &str) -> String {
    // Sessions require unrestricted access modes until OS confinement exists.
    rt.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
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

#[tokio::test]
async fn corrupt_op_journal_starts_degraded_read_only() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    fs::write(
        paths.state_dir.join("op-journal.json"),
        br#"{"uncertain":{"__ownmesh_operation_state":"in_progress""#,
    )
    .unwrap();

    let mut rt = DaemonRuntime::open(&paths).expect("corrupt journal must start degraded, not refuse startup");
    let diagnose = rt
        .dispatch(ops_methods::SYSTEM_DIAGNOSE, Some(json!({ "workspace_id": null })), &client("local"))
        .await
        .expect("diagnose stays up");
    let diagnosis = diagnose.get("result").unwrap_or(&diagnose);
    assert_eq!(diagnosis["overall"], "journal_degraded");
    assert_eq!(diagnosis["journals"]["op_journal"]["status"], "degraded");
    rt.dispatch(methods::POLICY_SHOW, None, &client("local"))
        .await
        .expect("policy.show stays up while journal is degraded");
    let err = rt
        .dispatch(
            methods::OPS_EXEC,
            Some(json!({ "program": "true", "idempotency_key": "k" })),
            &client("local"),
        )
        .await
        .expect_err("side effects must fail closed while degraded");
    match err {
        IpcError::Remote { message, .. } => {
            assert!(message.contains("OWNMESH_E_JOURNAL_DEGRADED"), "{message}");
        }
        other => panic!("{other:?}"),
    }
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
            &human("local"),
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
        rt.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
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

#[tokio::test]
async fn workspace_crud_roundtrip_persists_registry() {
    use runtime::ops_methods;
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let listed = rt
        .dispatch(ops_methods::WORKSPACE_LIST, None, &client("owner"))
        .await
        .expect("list");
    assert!(listed["count"].as_u64().unwrap() >= 1);

    let extra = dir.path().join("extra-ws");
    fs::create_dir_all(&extra).unwrap();
    let added = rt
        .dispatch(
            ops_methods::WORKSPACE_ADD,
            Some(json!({
                "path": extra.to_string_lossy(),
                "id": "ws_extra1",
                "label": "extra",
            })),
            &client("owner"),
        )
        .await
        .expect("add");
    assert_eq!(added["id"], "ws_extra1");

    let shown = rt
        .dispatch(
            ops_methods::WORKSPACE_SHOW,
            Some(json!({ "id": "ws_extra1" })),
            &client("owner"),
        )
        .await
        .expect("show");
    assert_eq!(shown["label"], "extra");

    let updated = rt
        .dispatch(
            ops_methods::WORKSPACE_UPDATE,
            Some(json!({ "id": "ws_extra1", "label": "extra-2" })),
            &client("owner"),
        )
        .await
        .expect("update");
    assert_eq!(updated["label"], "extra-2");

    // Survive restart.
    drop(rt);
    let mut rt = DaemonRuntime::open(&paths).expect("reopen");
    let listed = rt
        .dispatch(ops_methods::WORKSPACE_LIST, None, &client("owner"))
        .await
        .expect("list2");
    let ids: Vec<&str> = listed["workspaces"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|w| w["id"].as_str())
        .collect();
    assert!(ids.contains(&"ws_extra1"), "{ids:?}");

    let removed = rt
        .dispatch(
            ops_methods::WORKSPACE_REMOVE,
            Some(json!({ "id": "ws_extra1" })),
            &client("owner"),
        )
        .await
        .expect("remove");
    assert_eq!(removed["removed"], true);

    let err = rt
        .dispatch(
            ops_methods::WORKSPACE_REMOVE,
            Some(json!({ "id": "ws_default" })),
            &client("owner"),
        )
        .await
        .expect_err("default protected");
    match err {
        IpcError::Remote { message, .. } => assert!(message.contains("ws_default"), "{message}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn session_write_pending_after_final_persist_failure_is_at_most_once() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    rt.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
    let id = open_session(&mut rt, "owner", "pty-once").await;

    // Fail the finalize persist (2nd session persist in write path after open's persists).
    // open_session already persisted; write does: reserve commit (#1) then finalize commit (#2).
    rt.fail_sessions_persist_on_nth_call_for_test(2);
    let err = rt
        .dispatch(
            session_methods::WRITE,
            Some(json!({
                "id": id,
                "data": "once-only
            ",
                "input_seq": 1,
            })),
            &client("owner"),
        )
        .await
        .expect_err("finalize persist must fail");
    match &err {
        IpcError::Remote { message, .. } => {
            assert!(
                message.to_ascii_lowercase().contains("session")
                    || message.to_ascii_lowercase().contains("persist"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }

    // Clear fault. Retry same seq must NOT re-deliver (uncertain / at-most-once).
    rt.fail_sessions_persist_on_nth_call_for_test(0);
    // Resetting to 0 disables fault (fetch_update only fires when remaining > 0).
    let err2 = rt
        .dispatch(
            session_methods::WRITE,
            Some(json!({
                "id": id,
                "data": "once-only
            ",
                "input_seq": 1,
            })),
            &client("owner"),
        )
        .await
        .expect_err("retry pending must be uncertain");
    match err2 {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::CONFLICT, "{message}");
            let lower = message.to_ascii_lowercase();
            assert!(
                lower.contains("uncertain") || lower.contains("at-most-once"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn profile_list_detects_official_ids_without_credential_exfil() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let listed = rt
        .dispatch(methods::PROFILE_LIST, None, &client("local"))
        .await
        .expect("profile.list");
    assert_eq!(listed["official_count"], 9);
    assert_eq!(listed["total"], 9);
    let profiles = listed["profiles"].as_array().expect("profiles array");
    assert_eq!(profiles.len(), 9);
    let ids: Vec<&str> = profiles.iter().filter_map(|p| p["id"].as_str()).collect();
    assert!(ids.contains(&"codex"));
    assert!(ids.contains(&"claude-code"));
    assert!(ids.contains(&"pi"));
    // Status is local PATH detection only — never embeds secrets.
    let blob = listed.to_string().to_ascii_lowercase();
    assert!(!blob.contains("api_key"));
    assert!(!blob.contains("authorization"));
}

#[tokio::test]
async fn fs_patch_applies_bounded_unified_diff() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    rt.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));

    rt.dispatch(
        methods::OPS_FS_WRITE,
        Some(json!({
            "path": "patch-me.txt",
            "content": "one\ntwo\nthree\n",
            "idempotency_key": "seed-patch-file",
        })),
        &client("local"),
    )
    .await
    .expect("seed file");

    let diff = concat!(
        "--- a/patch-me.txt\n",
        "+++ b/patch-me.txt\n",
        "@@ -1,3 +1,3 @@\n",
        " one\n",
        "-two\n",
        "+TWO\n",
        " three\n",
    );
    let patched = rt
        .dispatch(
            methods::OPS_FS_WRITE,
            Some(json!({
                "path": "patch-me.txt",
                "content": diff,
                "patch_format": "unified",
                "idempotency_key": "unified-patch-1",
            })),
            &client("local"),
        )
        .await
        .expect("unified patch");
    assert_ne!(
        patched.get("approval_required"),
        Some(&json!(true)),
        "unexpected approval gate: {patched}"
    );
    let body = patched.get("result").unwrap_or(&patched);
    assert_eq!(body["patched"], true, "response={patched}");
    assert_eq!(body["patch_format"], "unified");

    let read = rt
        .dispatch(
            methods::OPS_FS_READ,
            Some(json!({ "path": "patch-me.txt", "max_bytes": 1024 })),
            &client("local"),
        )
        .await
        .expect("read patched");
    let read_body = read.get("result").unwrap_or(&read);
    assert_eq!(read_body["content"], "one\nTWO\nthree\n");
}

#[tokio::test]
async fn session_resize_without_live_host_fails_before_consuming_sequence() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let id = open_session(&mut rt, "owner", "resize-stale").await;

    // Simulate daemon recovery: metadata survives, live PTY does not.
    rt.stop_live_host_for_test(&id);

    let err = rt
        .dispatch(
            session_methods::RESIZE,
            Some(json!({
                "id": id,
                "cols": 120,
                "rows": 40,
                "resize_seq": 1,
            })),
            &client("owner"),
        )
        .await
        .expect_err("phantom resize must fail");
    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::CONFLICT, "{message}");
            assert!(
                message.to_ascii_lowercase().contains("no live pty"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }

    // Sequence must remain unconsumed so a later reattach can still use seq=1.
    // Re-open is not possible on same id; verify a second resize still fails the
    // same way (not "replayed" success).
    let err2 = rt
        .dispatch(
            session_methods::RESIZE,
            Some(json!({
                "id": id,
                "cols": 120,
                "rows": 40,
                "resize_seq": 1,
            })),
            &client("owner"),
        )
        .await
        .expect_err("still no live host");
    match err2 {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::CONFLICT, "{message}");
            assert!(
                message.to_ascii_lowercase().contains("no live pty"),
                "{message}"
            );
        }
        other => panic!("{other:?}"),
    }
}
