//! Session lease expiry enforcement (fix-6).
//!
//! Runtime must expire stale controller leases before session ACL decisions and
//! persist demotions. Expired controllers lose mutation/stdin rights (fail closed)
//! while remaining readers until/after demotion to observer.

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
use ownmesh_ipc::{app_error, ClientIdentity, IpcError};
use ownmesh_policy::{preset_document, AccessPreset};
use ownmesh_session::SessionManager;
use runtime::{session_methods, DaemonRuntime};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

fn client(name: &str) -> ClientIdentity {
    ClientIdentity::new(name, "0.1.0")
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn block_atomic_write(path: &Path) {
    if path.is_file() {
        let mut original = path.as_os_str().to_os_string();
        original.push(".fault-injection-original");
        fs::rename(path, std::path::PathBuf::from(original)).unwrap();
    }
    // Fault the replace destination rather than guessing the helper's unique temp name.
    fs::create_dir_all(path).unwrap();
    fs::write(path.join(".keep"), b"block").unwrap();
}

async fn open_session(rt: &mut DaemonRuntime, who: &str, title: &str) -> String {
    // Sessions require unrestricted access modes until OS confinement exists.
    rt.set_policy_for_test(preset_document(AccessPreset::FullUserAccess));
    let v = rt
        .dispatch(
            session_methods::OPEN,
            Some(json!({ "title": title })),
            &client(who),
        )
        .await
        .expect("session.open");
    v.get("id")
        .and_then(Value::as_str)
        .expect("session id")
        .to_string()
}

fn assert_denied(err: IpcError) {
    match err {
        IpcError::Remote { code, message } => {
            assert!(
                code == app_error::POLICY_DENIED
                    || code == app_error::CONFLICT
                    || code == app_error::UNAUTHORIZED,
                "unexpected denial code={code} message={message}"
            );
        }
        other => panic!("unexpected error shape: {other:?}"),
    }
}

#[tokio::test]
async fn expired_controller_loses_write_give_release_resize_and_close() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    let id = open_session(&mut rt, "ctrl", "lease-exp").await;

    // Seed an observer via give then reclaim so both are readers.
    rt.dispatch(
        session_methods::GIVE,
        Some(json!({ "id": id, "to": "obs" })),
        &client("ctrl"),
    )
    .await
    .expect("give to obs");
    rt.dispatch(
        session_methods::GIVE,
        Some(json!({ "id": id, "to": "ctrl" })),
        &client("obs"),
    )
    .await
    .expect("give back to ctrl");

    // Force lease into the past (strictly before wall clock used by runtime).
    let past = now_unix().saturating_sub(10);
    rt.set_session_controller_expiry_for_test(&id, past)
        .expect("set expiry");

    // Mutations / stdin must fail closed for the expired controller.
    // First touch: runtime expires+persists before auth, then denies control ops.
    let write_err = rt
        .dispatch(
            session_methods::WRITE,
            Some(json!({ "id": id, "data": "nope" })),
            &client("ctrl"),
        )
        .await
        .expect_err("write must fail after lease expiry");
    assert_denied(write_err);

    // After the first auth path, runtime should have demoted the stale lease.
    assert_eq!(
        rt.session_controller_for_test(&id),
        None,
        "expired lease must be removed/demoted by prepare_session_access"
    );

    let give_err = rt
        .dispatch(
            session_methods::GIVE,
            Some(json!({ "id": id, "to": "obs" })),
            &client("ctrl"),
        )
        .await
        .expect_err("give must fail after lease expiry");
    assert_denied(give_err);

    // release is idempotent once prepare_session_access already cleared the seat.
    rt.dispatch(
        session_methods::RELEASE,
        Some(json!({ "id": id })),
        &client("ctrl"),
    )
    .await
    .expect("release after demote is a no-op");
    assert_eq!(rt.session_controller_for_test(&id), None);

    let resize_err = rt
        .dispatch(
            session_methods::RESIZE,
            Some(json!({ "id": id, "cols": 100, "rows": 40 })),
            &client("ctrl"),
        )
        .await
        .expect_err("resize must fail after lease expiry");
    assert_denied(resize_err);

    let close_err = rt
        .dispatch(
            session_methods::CLOSE,
            Some(json!({ "id": id })),
            &client("ctrl"),
        )
        .await
        .expect_err("close must fail after lease expiry");
    assert_denied(close_err);

    let push_err = rt
        .dispatch(
            session_methods::PUSH_OUTPUT,
            Some(json!({ "id": id, "data": "x" })),
            &client("ctrl"),
        )
        .await
        .expect_err("push_output must fail after lease expiry");
    assert_denied(push_err);

    // Former controller remains a reader (observer) and may claim again.
    rt.dispatch(
        session_methods::SHOW,
        Some(json!({ "id": id })),
        &client("ctrl"),
    )
    .await
    .expect("former controller can still read");

    rt.dispatch(
        session_methods::REPLAY,
        Some(json!({ "id": id, "from_seq": 1 })),
        &client("obs"),
    )
    .await
    .expect("observer can replay");

    let claim = rt
        .dispatch(
            session_methods::CLAIM,
            Some(json!({ "id": id })),
            &client("obs"),
        )
        .await
        .expect("observer claims expired seat");
    assert_eq!(
        claim.pointer("/lease/principal_id").and_then(Value::as_str),
        Some("obs")
    );
}

#[tokio::test]
async fn renew_and_explicit_detach_are_exact_lease_bound_and_persisted() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");
    let id = open_session(&mut rt, "owner", "renew-detach").await;
    let shown = rt
        .dispatch(
            session_methods::SHOW,
            Some(json!({ "id": id })),
            &client("owner"),
        )
        .await
        .expect("show");
    let lease_id = shown
        .pointer("/controller/lease_id")
        .and_then(Value::as_str)
        .expect("lease id")
        .to_owned();
    let epoch = shown
        .pointer("/controller/epoch")
        .and_then(Value::as_u64)
        .expect("lease epoch");

    let renewed = rt
        .dispatch(
            session_methods::RENEW,
            Some(json!({ "id": id, "lease_id": lease_id, "controller_epoch": epoch, "ttl_secs": 60 })),
            &client("owner"),
        )
        .await
        .expect("renew exact active lease");
    assert_eq!(
        renewed.pointer("/lease/epoch").and_then(Value::as_u64),
        Some(epoch)
    );

    let stale = rt
        .dispatch(
            session_methods::RENEW,
            Some(json!({ "id": id, "lease_id": "old", "controller_epoch": epoch, "ttl_secs": 60 })),
            &client("owner"),
        )
        .await
        .expect_err("wrong lease must not renew");
    assert_denied(stale);

    rt.dispatch(
        session_methods::DETACH,
        Some(json!({ "id": id, "lease_id": lease_id, "controller_epoch": epoch })),
        &client("owner"),
    )
    .await
    .expect("explicit detach");
    assert_eq!(rt.session_controller_for_test(&id), None);
    let sessions_path = paths.state_dir.join("sessions").join("sessions.json");
    let loaded = SessionManager::load_from_path(&sessions_path).expect("reload sessions");
    let info = loaded.get(&id).expect("persisted session");
    assert!(info.controller.is_none());
    assert!(info.observers.iter().any(|principal| principal == "owner"));
}

#[tokio::test]
async fn prepare_session_access_persists_demoted_leases() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    let id = open_session(&mut rt, "owner", "persist-expiry").await;
    let past = now_unix().saturating_sub(5);
    rt.set_session_controller_expiry_for_test(&id, past)
        .expect("set expiry");

    // Touch a read path: must expire + persist before authorizing.
    rt.dispatch(
        session_methods::SHOW,
        Some(json!({ "id": id })),
        &client("owner"),
    )
    .await
    .expect("show after expiry");

    assert_eq!(rt.session_controller_for_test(&id), None);

    let sessions_path = paths.state_dir.join("sessions").join("sessions.json");
    let loaded = SessionManager::load_from_path(&sessions_path).expect("reload sessions");
    let info = loaded.get(&id).expect("session on disk");
    assert!(
        info.controller.is_none(),
        "demoted lease must be persisted to disk"
    );
    assert!(
        info.observers.iter().any(|o| o == "owner"),
        "former controller must be demoted to observer on disk"
    );
}

#[tokio::test]
async fn lease_expiry_persist_failure_through_show_restores_complete_session_state() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    let id = open_session(&mut rt, "owner", "expiry-rollback").await;
    rt.set_session_controller_expiry_for_test(&id, now_unix().saturating_sub(5))
        .expect("set expiry");
    let before = rt.session_state_for_test();
    block_atomic_write(&paths.state_dir.join("sessions/sessions.json"));

    let err = rt
        .dispatch(
            session_methods::SHOW,
            Some(json!({ "id": id })),
            &client("owner"),
        )
        .await
        .expect_err("lease demotion persist must fail");
    match err {
        IpcError::Remote { code, message } => {
            assert_eq!(code, app_error::INTERNAL);
            assert!(
                message.contains("session") || message.contains("persist"),
                "unexpected message: {message}"
            );
        }
        other => panic!("unexpected error shape: {other:?}"),
    }
    assert_eq!(
        rt.session_state_for_test(),
        before,
        "controller, observers, lease, lifecycle, and replay must all roll back"
    );
    assert_eq!(
        rt.session_controller_for_test(&id).as_deref(),
        Some("owner"),
        "expired controller must remain represented when demotion cannot persist"
    );
}

#[tokio::test]
async fn stranger_cannot_read_or_claim_after_expiry() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    let id = open_session(&mut rt, "owner", "acl").await;
    rt.set_session_controller_expiry_for_test(&id, now_unix().saturating_sub(1))
        .unwrap();

    let show_err = rt
        .dispatch(
            session_methods::SHOW,
            Some(json!({ "id": id })),
            &client("stranger"),
        )
        .await
        .expect_err("stranger show denied");
    assert_denied(show_err);

    let claim_err = rt
        .dispatch(
            session_methods::CLAIM,
            Some(json!({ "id": id })),
            &client("stranger"),
        )
        .await
        .expect_err("stranger claim denied");
    assert_denied(claim_err);

    let replay_err = rt
        .dispatch(
            session_methods::REPLAY,
            Some(json!({ "id": id })),
            &client("stranger"),
        )
        .await
        .expect_err("stranger replay denied");
    assert_denied(replay_err);
}

#[tokio::test]
async fn active_controller_still_authorized_before_expiry() {
    let dir = tempdir().unwrap();
    let paths = OwnMeshPaths::for_base(dir.path());
    paths.ensure_layout().unwrap();
    let mut rt = DaemonRuntime::open(&paths).expect("runtime");

    let id = open_session(&mut rt, "owner", "active").await;

    rt.dispatch(
        session_methods::WRITE,
        Some(json!({ "id": id, "data": "hello" })),
        &client("owner"),
    )
    .await
    .expect("active write");

    rt.dispatch(
        session_methods::RESIZE,
        Some(json!({ "id": id, "cols": 120, "rows": 40 })),
        &client("owner"),
    )
    .await
    .expect("active resize");

    rt.dispatch(
        session_methods::RELEASE,
        Some(json!({ "id": id })),
        &client("owner"),
    )
    .await
    .expect("active release");

    assert_eq!(rt.session_controller_for_test(&id), None);
}
