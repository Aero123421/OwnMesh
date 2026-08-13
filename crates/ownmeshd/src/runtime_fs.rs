//! Filesystem operation handlers for [`DaemonRuntime`].
//!
//! Split out of `runtime.rs` so the workspace-relative filesystem surface —
//! policy gating on one side, `ownmesh-fs` custody on the other — is reviewable
//! without scrolling the multi-thousand-line daemon impl. Behavior is
//! unchanged; only the file boundary moved.
//!
//! This is a child module of `runtime`, so it reaches `DaemonRuntime`'s private
//! state directly. Handlers are `pub(super)` because the dispatch table lives in
//! the parent.
//!
//! `handle_*` classifies the request into policy facts and hands it to
//! `gate_and_run`; `execute_*` runs only after that gate has allowed it (or a
//! human approved it), and is never called directly from dispatch.

use super::{
    base64_standard, fs_err, parse_params, sensitive_path_tags, sha256_hex, DaemonRuntime,
    FsDeleteParams, FsListParams, FsReadParams, FsStatParams, FsWriteParams, PendingRequest,
};
use ownmesh_fs::{
    apply_patch, apply_unified_diff, delete_path, list_dir_page, looks_like_unified_diff,
    stat_path, write_file,
};
use ownmesh_ipc::{app_error, ClientIdentity, IpcError, IpcResult};
use ownmesh_policy::OperationFacts;
use serde_json::{json, Value};

impl DaemonRuntime {
    pub(super) fn execute_fs_list(&self, p: &FsListParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let max_entries = p.max_entries.unwrap_or(200).clamp(1, 500);
        let page = list_dir_page(&ws, &p.path, p.recursive, max_entries, p.cursor.as_deref())
            .map_err(fs_err)?;
        Ok(json!({
            "entries": page.entries,
            "next_cursor": page.next_cursor,
            "truncated": page.truncated,
            "total_matched": page.total_matched,
            "workspace_id": p.workspace_id,
        }))
    }

    pub(super) fn execute_fs_stat(&self, p: &FsStatParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let st = stat_path(&ws, &p.path, p.hash).map_err(fs_err)?;
        let mut value = serde_json::to_value(st).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })?;
        value
            .as_object_mut()
            .expect("file stat serializes as an object")
            .insert("workspace_id".into(), json!(p.workspace_id));
        Ok(value)
    }

    pub(super) fn execute_fs_read(&self, p: &FsReadParams) -> IpcResult<Value> {
        // Hard cap per hop so Base64(~4/3) + metadata fits:
        // - Agent envelope 750 KiB JSON
        // - Durable MCP data_json 256 KiB
        // Larger files are retrieved by paging offset/max_bytes (next_offset).
        const MAX_READ_BYTES: u64 = 160 * 1024;
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let offset = p.offset.unwrap_or(0);
        let want = p.max_bytes.unwrap_or(64 * 1024).min(MAX_READ_BYTES);
        let (data, total, truncated) =
            ownmesh_fs::read_file_range(&ws, &p.path, offset, want).map_err(fs_err)?;
        let returned = data.len() as u64;
        let next_offset = offset.saturating_add(returned);
        // Prefer UTF-8 text; otherwise return standard Base64 (RFC 4648 with padding)
        // so clients can decode without inventing a custom alphabet. Never lossy-decode
        // arbitrary bytes as text.
        let (encoding, content) = match String::from_utf8(data.clone()) {
            Ok(text) => ("utf-8", Value::String(text)),
            Err(_) => ("base64", Value::String(base64_standard(&data))),
        };
        let mut body = json!({
            "path": p.path,
            "content": content,
            "encoding": encoding,
            "offset": offset,
            "bytes": returned,
            "returned_bytes": returned,
            "total_bytes": total,
            "truncated": truncated,
            "sha256": sha256_hex(&data),
            "workspace_id": p.workspace_id,
        });
        if truncated {
            body.as_object_mut()
                .expect("object")
                .insert("next_offset".into(), json!(next_offset));
            body.as_object_mut()
                .expect("object")
                .insert("next_cursor".into(), json!(format!("off_{next_offset}")));
        }
        Ok(body)
    }

    pub(super) fn execute_fs_write(&self, p: &FsWriteParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let format = p
            .patch_format
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("");
        // Explicit replace always wins. Unified is selected by format or by a
        // hash-checked patch whose body is a unified diff (E7).
        let use_unified = match format {
            "replace" | "whole" | "full" => false,
            "unified" | "unified_diff" | "diff" => true,
            _ if p.expected_sha256.is_some() && looks_like_unified_diff(&p.content) => true,
            _ => false,
        };

        if use_unified {
            let new_hash =
                apply_unified_diff(&ws, &p.path, &p.content, p.expected_sha256.as_deref())
                    .map_err(fs_err)?;
            return Ok(json!({
                "path": p.path,
                "bytes_written": p.content.len(),
                "sha256": new_hash,
                "patched": true,
                "patch_format": "unified",
                "workspace_id": p.workspace_id,
            }));
        }

        if let Some(expected) = p.expected_sha256.as_deref() {
            let new_hash =
                apply_patch(&ws, &p.path, p.content.as_bytes(), Some(expected)).map_err(fs_err)?;
            return Ok(json!({
                "path": p.path,
                "bytes_written": p.content.len(),
                "sha256": new_hash,
                "patched": true,
                "patch_format": "replace",
                "workspace_id": p.workspace_id,
            }));
        }
        write_file(&ws, &p.path, p.content.as_bytes()).map_err(fs_err)?;
        Ok(json!({
            "path": p.path,
            "bytes_written": p.content.len(),
            "workspace_id": p.workspace_id,
        }))
    }

    pub(super) fn execute_fs_delete(&self, p: &FsDeleteParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        delete_path(&ws, &p.path, p.recursive).map_err(fs_err)?;
        Ok(json!({
            "path": p.path,
            "deleted": true,
            "workspace_id": p.workspace_id,
        }))
    }

    pub(super) async fn handle_fs_list(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: FsListParams = parse_params(params)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: !std::path::Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            tags: sensitive_path_tags(&p.path, false),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsList(p), client)
            .await
    }

    pub(super) async fn handle_fs_stat(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: FsStatParams = parse_params(params)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: !std::path::Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            tags: sensitive_path_tags(&p.path, false),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsStat(p), client)
            .await
    }

    pub(super) async fn handle_fs_read(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: FsReadParams = parse_params(params)?;
        normalize_fs_read_cursor(&mut p)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: !std::path::Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            tags: sensitive_path_tags(&p.path, false),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsRead(p), client)
            .await
    }

    pub(super) async fn handle_fs_write(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: FsWriteParams = parse_params(params)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: !std::path::Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            tags: sensitive_path_tags(&p.path, true),
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsWrite(p), client)
            .await
    }

    pub(super) async fn handle_fs_delete(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: FsDeleteParams = parse_params(params)?;
        p.workspace_id = self.workspace_id_for_path(p.workspace_id.as_deref(), &p.path)?;
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: !std::path::Path::new(&p.path).is_absolute(),
            workspace_id: p.workspace_id.clone(),
            tags: {
                let mut tags = vec!["delete".to_owned()];
                tags.extend(sensitive_path_tags(&p.path, true));
                tags
            },
            ..Default::default()
        };
        let key = p.idempotency_key.clone();
        self.gate_and_run(facts, key, PendingRequest::FsDelete(p), client)
            .await
    }
}

/// Normalize the only supported filesystem read continuation token.
///
/// A file-read cursor is deliberately just a canonical byte offset: it carries
/// no path, workspace, or authority, all of which remain exact action facts and
/// are rechecked independently. Reject alternate encodings and contradictory
/// offset/cursor pairs so a caller cannot accidentally reread or skip bytes.
fn normalize_fs_read_cursor(p: &mut FsReadParams) -> IpcResult<()> {
    let Some(cursor) = p.cursor.take() else {
        return Ok(());
    };
    let offset = cursor
        .strip_prefix("off_")
        .filter(|raw| !raw.is_empty() && raw.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|raw| raw.parse::<u64>().ok())
        .filter(|offset| cursor == format!("off_{offset}"))
        .ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "invalid fs.read cursor".into(),
        })?;
    if p.offset.is_some_and(|explicit| explicit != offset) {
        return Err(IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "fs.read cursor and offset disagree".into(),
        });
    }
    p.offset = Some(offset);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ownmesh_config::OwnMeshPaths;
    use ownmesh_ipc::methods;
    use ownmesh_policy::{preset_document, AccessPreset};
    use tempfile::tempdir;

    fn read_result(response: &Value) -> &Value {
        response
            .get("result")
            .expect("allowed read includes a result")
    }

    #[tokio::test]
    async fn fs_read_cursor_resumes_utf8_and_binary_without_duplicate_bytes() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        let root = paths.state_dir.join("workspace");
        std::fs::write(root.join("utf8.txt"), "abécd").unwrap();
        std::fs::write(root.join("binary.bin"), [0_u8, 255, 1, 254, 2, 253]).unwrap();
        let client = ClientIdentity::new("fs-read-cursor-test", "test");

        let first = runtime
            .dispatch(
                methods::OPS_FS_READ,
                Some(json!({ "path": "utf8.txt", "max_bytes": 4 })),
                &client,
            )
            .await
            .unwrap();
        let first = read_result(&first);
        assert_eq!(first["content"], "abé");
        assert_eq!(first["next_cursor"], "off_4");
        let second = runtime
            .dispatch(
                methods::OPS_FS_READ,
                Some(json!({ "path": "utf8.txt", "max_bytes": 4, "cursor": first["next_cursor"] })),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(
            format!(
                "{}{}",
                first["content"].as_str().unwrap(),
                read_result(&second)["content"].as_str().unwrap()
            ),
            "abécd"
        );

        let first = runtime
            .dispatch(
                methods::OPS_FS_READ,
                Some(json!({ "path": "binary.bin", "max_bytes": 3 })),
                &client,
            )
            .await
            .unwrap();
        let first = read_result(&first);
        assert_eq!(first["encoding"], "base64");
        assert_eq!(first["next_cursor"], "off_3");
        assert_eq!(first["content"], "AP8B");
        let second = runtime
            .dispatch(
                methods::OPS_FS_READ,
                Some(
                    json!({ "path": "binary.bin", "max_bytes": 3, "cursor": first["next_cursor"] }),
                ),
                &client,
            )
            .await
            .unwrap();
        assert_eq!(read_result(&second)["encoding"], "base64");
        assert_eq!(read_result(&second)["offset"], 3);
        assert_eq!(read_result(&second)["content"], "/gL9");
    }

    #[tokio::test]
    async fn fs_read_rejects_noncanonical_or_conflicting_continuations() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        std::fs::write(paths.state_dir.join("workspace").join("a.txt"), b"abcdef").unwrap();
        let client = ClientIdentity::new("fs-read-cursor-invalid-test", "test");

        let same_offset = runtime
            .dispatch(
                methods::OPS_FS_READ,
                Some(json!({ "path": "a.txt", "cursor": "off_3", "offset": 3 })),
                &client,
            )
            .await
            .expect("matching cursor and offset are one canonical read");
        assert_eq!(read_result(&same_offset)["offset"], 3);

        for params in [
            json!({ "path": "a.txt", "cursor": "cur_4" }),
            json!({ "path": "a.txt", "cursor": "off_04" }),
            json!({ "path": "a.txt", "cursor": "off_4", "offset": 3 }),
        ] {
            let error = runtime
                .dispatch(methods::OPS_FS_READ, Some(params), &client)
                .await
                .unwrap_err();
            assert!(matches!(
                error,
                IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    ..
                }
            ));
        }
    }

    #[tokio::test]
    async fn fs_write_stale_hash_is_conflict_and_preserves_file() {
        let temp = tempdir().unwrap();
        let paths = OwnMeshPaths::for_base(temp.path());
        let mut runtime = DaemonRuntime::open(&paths).unwrap();
        runtime.set_policy_for_test(preset_document(AccessPreset::FullAccess));
        let path = paths.state_dir.join("workspace").join("guarded.txt");
        std::fs::write(&path, b"before").unwrap();
        let client = ClientIdentity::new("fs-write-hash-conflict-test", "test");

        let error = runtime
            .dispatch(
                methods::OPS_FS_WRITE,
                Some(json!({
                    "path": "guarded.txt",
                    "content": "after",
                    "expected_sha256": "0".repeat(64),
                    "idempotency_key": "fs-write-stale-hash"
                })),
                &client,
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            IpcError::Remote {
                code: app_error::CONFLICT,
                ..
            }
        ));
        assert!(error
            .to_string()
            .ends_with("file changed since it was read"));
        assert_eq!(std::fs::read(&path).unwrap(), b"before");
    }
}
