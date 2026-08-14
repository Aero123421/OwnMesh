//! Device-local workspace registry handlers for [`DaemonRuntime`].
//!
//! Split out of `runtime.rs` so the workspace registry — a self-contained CRUD
//! surface over `workspaces.json` — is reviewable without scrolling the
//! multi-thousand-line daemon impl. Behavior is unchanged; only the file
//! boundary moved.
//!
//! This is a child module of `runtime`, so it reaches `DaemonRuntime`'s private
//! state directly. Handlers are `pub(super)` because the dispatch table lives in
//! the parent.

use super::{parse_params, sha256_hex, DaemonRuntime, WorkspaceEntry};
use ownmesh_ipc::{app_error, ClientIdentity, IpcError, IpcResult};
use serde::Deserialize;
use serde_json::{json, Value};
use std::path::PathBuf;

impl DaemonRuntime {
    pub(super) fn handle_workspace_list(&self, _client: &ClientIdentity) -> IpcResult<Value> {
        let mut workspaces: Vec<Value> = self
            .workspaces
            .iter()
            .map(|w| {
                json!({
                    "id": w.id,
                    "root": w.root.to_string_lossy(),
                    "label": w.label,
                })
            })
            .collect();
        workspaces.sort_by(|a, b| {
            a["id"]
                .as_str()
                .unwrap_or("")
                .cmp(b["id"].as_str().unwrap_or(""))
        });
        Ok(json!({
            "workspaces": workspaces,
            "count": workspaces.len(),
            "enforce_workspace": self.enforce_workspace,
        }))
    }

    pub(super) fn handle_workspace_show(&self, params: Option<Value>) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let id = p.id.trim();
        let entry = self
            .workspaces
            .iter()
            .find(|w| w.id == id || (id == "default" && w.id == "ws_default"))
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            })?;
        Ok(json!({
            "id": entry.id,
            "root": entry.root.to_string_lossy(),
            "label": entry.label,
            "exists": entry.root.exists(),
        }))
    }

    pub(super) fn handle_workspace_add(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            path: String,
            #[serde(default)]
            id: Option<String>,
            #[serde(default)]
            label: Option<String>,
        }
        let p: P = parse_params(params)?;
        let root = PathBuf::from(p.path.trim());
        if !root.is_absolute() {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "workspace path must be absolute".into(),
            });
        }
        let id = if let Some(raw) = p.id.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            raw.to_owned()
        } else {
            // Deterministic short id from canonical path bytes (ws_ + 12 hex).
            let key = root.to_string_lossy().to_ascii_lowercase();
            let digest = sha256_hex(key.as_bytes());
            format!("ws_{}", &digest[..12])
        };
        let entry = WorkspaceEntry {
            id,
            root,
            label: p.label,
            generation: String::new(),
        };
        let stored = self.upsert_workspace(entry)?;
        self.append_audit(
            "workspace.add",
            Some("workspace.add"),
            Some(stored.id.as_str()),
            Some("ok"),
            format!(
                "root={} principal={}",
                stored.root.display(),
                client.client_name
            ),
        );
        Ok(json!({
            "id": stored.id,
            "root": stored.root.to_string_lossy(),
            "label": stored.label,
            "created": true,
        }))
    }

    pub(super) fn handle_workspace_update(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
            #[serde(default)]
            label: Option<String>,
            #[serde(default)]
            path: Option<String>,
        }
        let p: P = parse_params(params)?;
        let id = p.id.trim().to_owned();
        if (id == "ws_default" || id == "default")
            && p.path
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .is_some()
        {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "ws_default root cannot be relocated".into(),
            });
        }
        let idx = self
            .workspaces
            .iter()
            .position(|w| w.id == id || (id == "default" && w.id == "ws_default"))
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            })?;
        if let Some(path) = p.path.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
            let root = PathBuf::from(path);
            if !root.is_absolute() {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "workspace path must be absolute".into(),
                });
            }
            std::fs::create_dir_all(&root).map_err(|e| IpcError::Remote {
                code: app_error::INTERNAL,
                message: e.to_string(),
            })?;
            if self.workspaces[idx].root != root {
                self.workspaces[idx].root = root;
                self.workspaces[idx].generation = super::new_workspace_generation();
            }
        }
        if let Some(label) = p.label {
            let label = label.trim().to_owned();
            self.workspaces[idx].label = if label.is_empty() { None } else { Some(label) };
        }
        self.persist_workspaces()?;
        let stored = self.workspaces[idx].clone();
        self.append_audit(
            "workspace.update",
            Some("workspace.update"),
            Some(stored.id.as_str()),
            Some("ok"),
            format!(
                "root={} principal={}",
                stored.root.display(),
                client.client_name
            ),
        );
        Ok(json!({
            "id": stored.id,
            "root": stored.root.to_string_lossy(),
            "label": stored.label,
            "updated": true,
        }))
    }

    pub(super) fn handle_workspace_remove(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        struct P {
            id: String,
        }
        let p: P = parse_params(params)?;
        let id = p.id.trim();
        if id == "ws_default" || id == "default" {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "ws_default cannot be removed".into(),
            });
        }
        let before = self.workspaces.len();
        self.workspaces.retain(|w| w.id != id);
        if self.workspaces.len() == before {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("unknown workspace_id: {id}"),
            });
        }
        self.persist_workspaces()?;
        self.append_audit(
            "workspace.remove",
            Some("workspace.remove"),
            Some(id),
            Some("ok"),
            format!("removed principal={}", client.client_name),
        );
        Ok(json!({
            "id": id,
            "removed": true,
        }))
    }
}
