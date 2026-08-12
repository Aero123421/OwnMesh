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
            "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
        }))
    }

    pub(super) fn execute_fs_stat(&self, p: &FsStatParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        let st = stat_path(&ws, &p.path, p.hash).map_err(fs_err)?;
        serde_json::to_value(st).map_err(|e| IpcError::Remote {
            code: app_error::INTERNAL,
            message: e.to_string(),
        })
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
        });
        if truncated {
            body.as_object_mut()
                .expect("object")
                .insert("next_offset".into(), json!(next_offset));
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
                "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
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
                "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
            }));
        }
        write_file(&ws, &p.path, p.content.as_bytes()).map_err(fs_err)?;
        Ok(json!({
            "path": p.path,
            "bytes_written": p.content.len(),
            "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
        }))
    }

    pub(super) fn execute_fs_delete(&self, p: &FsDeleteParams) -> IpcResult<Value> {
        let ws = self.workspace_for(p.workspace_id.as_deref())?;
        delete_path(&ws, &p.path, p.recursive).map_err(fs_err)?;
        Ok(json!({
            "path": p.path,
            "deleted": true,
            "workspace_id": p.workspace_id.as_deref().unwrap_or("ws_default"),
        }))
    }

    pub(super) async fn handle_fs_list(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let mut p: FsListParams = parse_params(params)?;
        p.workspace_id = Some(Self::canonical_workspace_id(p.workspace_id.as_deref())?);
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
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
        p.workspace_id = Some(Self::canonical_workspace_id(p.workspace_id.as_deref())?);
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
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
        p.workspace_id = Some(Self::canonical_workspace_id(p.workspace_id.as_deref())?);
        let facts = OperationFacts {
            capability: "filesystem.read".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
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
        p.workspace_id = Some(Self::canonical_workspace_id(p.workspace_id.as_deref())?);
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
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
        p.workspace_id = Some(Self::canonical_workspace_id(p.workspace_id.as_deref())?);
        let facts = OperationFacts {
            capability: "filesystem.write".into(),
            kind: "file".into(),
            path: Some(p.path.clone()),
            workspace_relative: true,
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
