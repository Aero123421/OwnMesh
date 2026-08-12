//! Device-to-device transfer handlers for [`DaemonRuntime`].
//!
//! Split out of `runtime.rs`: plan/preflight/start/chunk/finalize/status/list/
//! cancel/artifact_get form one bounded, resumable protocol whose invariants
//! (immutable plans, no overwrite fallback, exact-once finalize) are easier to
//! audit as a unit.
//!
//! Behavior is unchanged; only the file boundary moved. This is a child module
//! of `runtime`, so it reaches `DaemonRuntime`'s private state directly, and
//! handlers are `pub(super)` because the dispatch table lives in the parent.

use super::{
    app_error, base64_decode_strict, base64_standard, fs_err, json, parse_params, sha256_hex,
    ClientIdentity, DaemonRuntime, Deserialize, IpcError, IpcResult, JournalState, PartFileSink,
    Path, PlanLimits, Read, Seek, SeekFrom, SourceCleanupBinding, TransferAuthority,
    TransferBinding, TransferChunk, TransferError, TransferGrant, TransferPlan, Value,
    MAX_CHUNK_BYTES,
};

impl DaemonRuntime {
    pub(super) async fn handle_transfer_plan(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            source_path: String,
            destination_path: String,
            destination_workspace_id: String,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let source_workspace_id = p.workspace_id.unwrap_or_else(|| "ws_default".into());
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: authority.principal_id.clone(),
            destination_principal_id: authority.principal_id.clone(),
            source_device_id: authority.device_id.clone(),
            destination_device_id: authority.device_id.clone(),
            source_workspace_id: source_workspace_id.clone(),
            destination_workspace_id: p.destination_workspace_id.clone(),
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        binding.validate().map_err(Self::transfer_error)?;
        // Source planning owns only source custody.  The destination Agent
        // performs its own workspace/no-replace preflight and later obtains the
        // destination lease.  Resolving a remote destination root here would
        // incorrectly require two devices to share a daemon filesystem.
        // TransferBinding::validate above still rejects absolute/traversal paths
        // before either value becomes immutable plan metadata.
        let source = self.workspace_for(Some(&source_workspace_id))?;
        let source_handle = source
            .open_verified_read(Path::new(&binding.source_relative_path))
            .map_err(fs_err)?;
        let grant = TransferGrant {
            grant_id: format!("grant_{}", authority.operation_id),
            operation_id: authority.operation_id.clone(),
            payload_sha256: authority.payload_sha256.clone(),
            expires_at_unix: authority.expires_at_unix,
        };
        let plan = TransferPlan::for_workspace_source(
            source_handle,
            binding,
            grant,
            PlanLimits::default(),
            Self::now() as u64,
        )
        .map_err(Self::transfer_error)?;
        self.transfer_store
            .save_plan(&plan)
            .map_err(Self::transfer_error)?;
        Ok(json!({
            "plan_id": plan.id(),
            "size_bytes": plan.size_bytes(),
            "sha256": plan.sha256(),
            "source_workspace_id": plan.binding().source_workspace_id,
            "destination_workspace_id": plan.binding().destination_workspace_id,
            "expires_at_unix": authority.expires_at_unix,
        }))
    }

    /// Internal source-side preflight used only by the authenticated Agent
    /// transport.  It hashes from a pinned source custody path and creates the
    /// immutable local source plan, but deliberately does not inspect a
    /// destination filesystem: that custody boundary belongs to the other
    /// device's `transfer.preflight_destination` operation.
    pub(super) async fn handle_transfer_preflight_source(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            transfer_id: String,
            source_path: String,
            destination_path: String,
            source_principal_id: String,
            destination_principal_id: String,
            source_device_id: String,
            destination_device_id: String,
            source_workspace_id: String,
            destination_workspace_id: String,
            epoch: u32,
            fence: u64,
            session_nonce: String,
            expires_at: u64,
            coordinator_request_id: String,
            workspace_version: u64,
            #[serde(default)]
            plan_sha256: Option<String>,
            #[serde(default)]
            content_sha256: Option<String>,
            #[serde(default)]
            size_bytes: Option<u64>,
            #[serde(default)]
            grant_id: Option<String>,
            #[serde(default)]
            grant_operation_id: Option<String>,
            #[serde(default)]
            grant_payload_sha256: Option<String>,
            #[serde(default)]
            grant_expires_at_unix: Option<u64>,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let source_workspace_id = p.workspace_id.unwrap_or_else(|| "ws_default".into());
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: p.source_principal_id,
            destination_principal_id: p.destination_principal_id,
            source_device_id: p.source_device_id,
            destination_device_id: p.destination_device_id,
            source_workspace_id: source_workspace_id.clone(),
            destination_workspace_id: p.destination_workspace_id,
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        if p.transfer_id.is_empty()
            || p.transfer_id.len() > 256
            || p.transfer_id.bytes().any(|byte| byte.is_ascii_control())
            || p.epoch == 0
            || p.fence == 0
            || p.session_nonce.is_empty()
            || p.session_nonce.len() > 256
            || p.session_nonce.bytes().any(|byte| byte.is_ascii_control())
            || p.expires_at <= (Self::now() as u64).saturating_mul(1000)
            || p.coordinator_request_id.is_empty()
            || p.coordinator_request_id.len() > 256
            || p.coordinator_request_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || p.workspace_version == 0
            || p.source_workspace_id != source_workspace_id
            || binding.source_principal_id != authority.principal_id
            || binding.source_device_id != authority.device_id
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "source preflight is not bound to the authenticated Agent identity".into(),
            });
        }
        binding.validate().map_err(Self::transfer_error)?;
        let source = self.workspace_for(Some(&source_workspace_id))?;
        let source_handle = source
            .open_verified_read(Path::new(&binding.source_relative_path))
            .map_err(fs_err)?;
        let final_plan = match (
            p.plan_sha256,
            p.content_sha256,
            p.size_bytes,
            p.grant_id,
            p.grant_operation_id,
            p.grant_payload_sha256,
            p.grant_expires_at_unix,
        ) {
            (None, None, None, None, None, None, None) => None,
            (
                Some(plan_sha256),
                Some(content_sha256),
                Some(size_bytes),
                Some(grant_id),
                Some(operation_id),
                Some(payload_sha256),
                Some(expires_at_unix),
            ) => {
                if expires_at_unix != authority.expires_at_unix {
                    return Err(IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "final transfer grant expiry differs from authenticated operation"
                            .into(),
                    });
                }
                let grant = TransferGrant {
                    grant_id,
                    operation_id,
                    payload_sha256,
                    expires_at_unix,
                };
                let verified =
                    TransferPlan::from_verified(binding.clone(), grant, size_bytes, content_sha256)
                        .map_err(Self::transfer_error)?;
                if verified.plan_sha256() != plan_sha256 {
                    return Err(IpcError::Remote {
                        code: app_error::UNAUTHORIZED,
                        message: "final transfer plan digest is not canonical".into(),
                    });
                }
                Some(verified)
            }
            _ => {
                return Err(IpcError::Remote {
                    code: app_error::INVALID_PARAMS,
                    message: "final transfer preflight fields must be supplied together".into(),
                })
            }
        };
        let grant = TransferGrant {
            grant_id: format!("grant_{}", authority.operation_id),
            operation_id: authority.operation_id.clone(),
            payload_sha256: authority.payload_sha256.clone(),
            expires_at_unix: authority.expires_at_unix,
        };
        let observed = TransferPlan::for_workspace_source(
            source_handle,
            binding,
            grant,
            PlanLimits::default(),
            Self::now() as u64,
        )
        .map_err(Self::transfer_error)?;
        let plan = if let Some(final_plan) = final_plan {
            if observed.size_bytes() != final_plan.size_bytes()
                || observed.sha256() != final_plan.sha256()
            {
                return Err(IpcError::Remote {
                    code: app_error::CONFLICT,
                    message: "source changed after preflight evidence".into(),
                });
            }
            final_plan
        } else {
            observed
        };
        self.transfer_store
            .save_plan(&plan)
            .map_err(Self::transfer_error)?;
        Ok(json!({
            "transfer_id": p.transfer_id,
            "role": "source",
            "tenant_id": authority.tenant_id,
            "principal_id": authority.principal_id,
            "device_id": authority.device_id,
            "workspace_id": plan.binding().source_workspace_id,
            "plan_id": plan.id(),
            "size_bytes": plan.size_bytes(),
            "sha256": plan.sha256(),
            "plan_sha256": plan.plan_sha256(),
            "source_workspace_id": plan.binding().source_workspace_id,
            "destination_workspace_id": plan.binding().destination_workspace_id,
            "epoch": p.epoch,
            "fence": p.fence,
            "session_nonce": p.session_nonce,
            "expires_at": p.expires_at,
            "coordinator_request_id": p.coordinator_request_id,
            "workspace_version": p.workspace_version,
            "expires_at_unix": authority.expires_at_unix,
        }))
    }

    /// Internal destination-side preflight.  It is intentionally read-only:
    /// reserve/part-file creation happens later in `destination_prepare`, after
    /// both authenticated Agent replies have been correlated by the coordinator.
    pub(super) async fn handle_transfer_preflight_destination(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            transfer_id: String,
            source_path: String,
            destination_path: String,
            source_principal_id: String,
            destination_principal_id: String,
            source_device_id: String,
            destination_device_id: String,
            source_workspace_id: String,
            destination_workspace_id: String,
            workspace_id: String,
            plan_sha256: String,
            epoch: u32,
            fence: u64,
            session_nonce: String,
            expires_at: u64,
            coordinator_request_id: String,
            workspace_version: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: p.source_principal_id,
            destination_principal_id: p.destination_principal_id,
            source_device_id: p.source_device_id,
            destination_device_id: p.destination_device_id,
            source_workspace_id: p.source_workspace_id,
            destination_workspace_id: p.workspace_id.clone(),
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        if p.transfer_id.is_empty()
            || p.transfer_id.len() > 256
            || p.transfer_id.bytes().any(|byte| byte.is_ascii_control())
            || p.epoch == 0
            || p.fence == 0
            || p.session_nonce.is_empty()
            || p.session_nonce.len() > 256
            || p.session_nonce.bytes().any(|byte| byte.is_ascii_control())
            || p.expires_at <= (Self::now() as u64).saturating_mul(1000)
            || p.coordinator_request_id.is_empty()
            || p.coordinator_request_id.len() > 256
            || p.coordinator_request_id
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || p.workspace_version == 0
            || p.destination_workspace_id != p.workspace_id
            || !p
                .plan_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            || p.plan_sha256.len() != 64
            || binding.destination_principal_id != authority.principal_id
            || binding.destination_device_id != authority.device_id
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination preflight is not bound to the authenticated Agent identity"
                    .into(),
            });
        }
        binding.validate().map_err(Self::transfer_error)?;
        let workspace = self.workspace_for(Some(&binding.destination_workspace_id))?;
        let destination = workspace
            .resolve(Path::new(&binding.destination_relative_path))
            .map_err(fs_err)?;
        if destination.exists() {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "destination already exists; overwrite is forbidden".into(),
            });
        }
        let parent = destination.parent().ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "destination parent is missing".into(),
        })?;
        let parent_meta = std::fs::symlink_metadata(parent).map_err(|error| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("inspect destination parent: {error}"),
        })?;
        if !parent_meta.is_dir() || parent_meta.file_type().is_symlink() {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination parent is not a pinned workspace directory".into(),
            });
        }
        Ok(json!({
            "transfer_id": p.transfer_id,
            "role": "destination",
            "tenant_id": authority.tenant_id,
            "principal_id": authority.principal_id,
            "device_id": authority.device_id,
            "workspace_id": binding.destination_workspace_id,
            "plan_sha256": p.plan_sha256,
            "destination_workspace_id": binding.destination_workspace_id,
            "destination_path": binding.destination_relative_path,
            "epoch": p.epoch,
            "fence": p.fence,
            "session_nonce": p.session_nonce,
            "expires_at": p.expires_at,
            "coordinator_request_id": p.coordinator_request_id,
            "workspace_version": p.workspace_version,
            "available": true,
            "expires_at_unix": authority.expires_at_unix,
        }))
    }

    /// Strict Agent-only admission for a ticket-bound transfer session.  The
    /// bearer remains opaque and is never persisted or returned from runtime.
    pub(super) async fn handle_transfer_start(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            transfer_id: String,
            role: String,
            ticket: String,
            plan_sha256: String,
            content_sha256: String,
            size_bytes: u64,
            source_path: String,
            destination_path: String,
            source_device_id: String,
            destination_device_id: String,
            source_workspace_id: String,
            destination_workspace_id: String,
            source_workspace_version: u64,
            destination_workspace_version: u64,
            workspace_id: String,
            workspace_version: u64,
            epoch: u32,
            fence: u64,
            grant_id: String,
            grant_operation_id: String,
            grant_payload_sha256: String,
            grant_expires_at_unix: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let hex =
            |value: &str| value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
        let local_device = if p.role == "source" {
            &p.source_device_id
        } else {
            &p.destination_device_id
        };
        let local_workspace = if p.role == "source" {
            &p.source_workspace_id
        } else {
            &p.destination_workspace_id
        };
        if !matches!(p.role.as_str(), "source" | "destination")
            || p.transfer_id.is_empty()
            || p.transfer_id.len() > 256
            || p.source_path.is_empty()
            || p.destination_path.is_empty()
            || p.source_path.len() > 4096
            || p.destination_path.len() > 4096
            || p.source_path.contains('\\')
            || p.destination_path.contains('\\')
            || p.source_path
                .split('/')
                .any(|part| part == "." || part == ".." || part.is_empty())
            || p.destination_path
                .split('/')
                .any(|part| part == "." || part == ".." || part.is_empty())
            || p.transfer_id != p.grant_id
            || p.grant_operation_id != p.transfer_id
            || p.grant_expires_at_unix != authority.expires_at_unix
            || authority.device_id != *local_device
            || p.workspace_id != *local_workspace
            || p.epoch == 0
            || p.fence == 0
            || p.workspace_version == 0
            || p.source_workspace_version == 0
            || p.destination_workspace_version == 0
            || !hex(&p.plan_sha256)
            || !hex(&p.content_sha256)
            || !hex(&p.grant_payload_sha256)
            || p.ticket.is_empty()
            || p.ticket.len() > 16 * 1024
            || p.ticket.bytes().any(|byte| byte.is_ascii_whitespace())
        {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "invalid ticket-bound transfer start".into(),
            });
        }
        let binding = TransferBinding {
            tenant_id: authority.tenant_id.clone(),
            source_principal_id: authority.principal_id.clone(),
            destination_principal_id: authority.principal_id.clone(),
            source_device_id: p.source_device_id,
            destination_device_id: p.destination_device_id,
            source_workspace_id: p.source_workspace_id,
            destination_workspace_id: p.destination_workspace_id,
            source_relative_path: p.source_path,
            destination_relative_path: p.destination_path,
        };
        let plan = TransferPlan::from_verified(
            binding,
            TransferGrant {
                grant_id: p.grant_id,
                operation_id: p.grant_operation_id,
                payload_sha256: p.grant_payload_sha256,
                expires_at_unix: p.grant_expires_at_unix,
            },
            p.size_bytes,
            p.content_sha256,
        )
        .map_err(Self::transfer_error)?;
        if plan.plan_sha256() != p.plan_sha256 {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "transfer start plan hash mismatch".into(),
            });
        }
        self.transfer_store
            .save_plan(&plan)
            .map_err(Self::transfer_error)?;
        // `ticket` is passed straight to connect_transfer_socket by the Agent
        // transport.  This receipt intentionally omits the bearer and paths.
        Ok(
            json!({ "transfer_id": p.transfer_id, "plan_id": plan.id(), "role": p.role, "plan_sha256": p.plan_sha256, "epoch": p.epoch, "fence": p.fence, "admitted": true }),
        )
    }

    fn transfer_plan_for(
        &self,
        plan_id: &str,
        authority: &TransferAuthority,
        role: Option<&str>,
    ) -> IpcResult<TransferPlan> {
        let plan = self
            .transfer_store
            .load_plan(plan_id, Self::now() as u64)
            .map_err(Self::transfer_error)?
            .ok_or_else(|| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "transfer plan was not found".into(),
            })?;
        Self::verify_local_transfer_identity(&plan, authority, role)?;
        Ok(plan)
    }

    pub(super) async fn handle_transfer_source_open(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            #[serde(default)]
            sequence: u64,
            #[serde(default)]
            offset: u64,
            #[serde(default)]
            workspace_id: Option<String>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("source"))?;
        if p.workspace_id.as_deref().unwrap_or("ws_default") != plan.binding().source_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "source open workspace does not match immutable plan".into(),
            });
        }
        let workspace = self.workspace_for(Some(&plan.binding().source_workspace_id))?;
        let sender = self
            .transfer_store
            .open_source_sender_at_lazy(plan.clone(), p.sequence, p.offset, || {
                workspace
                    .open_verified_read(Path::new(&plan.binding().source_relative_path))
                    .map_err(|_| TransferError::CustodyUnavailable)
            })
            .map_err(Self::transfer_error)?;
        self.transfer_senders.insert(plan.id().to_owned(), sender);
        self.transfer_last_chunks.remove(plan.id());
        Ok(
            json!({ "plan_id": plan.id(), "next_sequence": p.sequence, "next_offset": p.offset, "chunk_max_bytes": MAX_CHUNK_BYTES }),
        )
    }

    pub(super) async fn handle_transfer_source_chunk(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            sequence: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("source"))?;
        if let Some((sequence, frame)) = self.transfer_last_chunks.get(plan.id()) {
            if *sequence == p.sequence {
                return Ok(
                    json!({ "plan_id": plan.id(), "sequence": sequence, "frame_base64": frame, "replayed": true }),
                );
            }
        }
        let next = self
            .transfer_senders
            .get_mut(plan.id())
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "source is not open; reopen at the durable receiver cursor".into(),
            })?
            .next_chunk()
            .map_err(Self::transfer_error)?;
        let Some(chunk) = next else {
            self.transfer_senders.remove(plan.id());
            self.transfer_last_chunks.remove(plan.id());
            // Keep the immutable source snapshot + plan until the Agent has
            // received the Room's authenticated finish_ack. A disconnect
            // after the last destination ACK must be able to reopen exactly
            // this retained handle at offset == size without trusting a path.
            return Ok(json!({ "plan_id": plan.id(), "sequence": p.sequence, "eof": true }));
        };
        if chunk.sequence != p.sequence {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "source chunk sequence is not the requested contiguous cursor".into(),
            });
        }
        let frame = base64_standard(&chunk.encode().map_err(Self::transfer_error)?);
        self.transfer_last_chunks
            .insert(plan.id().to_owned(), (chunk.sequence, frame.clone()));
        Ok(
            json!({ "plan_id": plan.id(), "sequence": chunk.sequence, "offset": chunk.offset, "bytes": chunk.bytes.len(), "sha256": chunk.sha256, "frame_base64": frame, "replayed": false }),
        )
    }

    pub(super) async fn handle_transfer_destination_prepare(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
            next_sequence: u64,
            next_offset: u64,
            workspace_id: String,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination workspace does not match immutable plan".into(),
            });
        }
        let workspace = self.workspace_for(Some(&p.workspace_id))?;
        let destination = workspace
            .resolve(Path::new(&plan.binding().destination_relative_path))
            .map_err(fs_err)?;
        if let Some(journal) = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?
        {
            if journal.published() {
                self.transfer_receivers.remove(plan.id());
                let mut artifact = workspace
                    .open_verified_transfer_artifact_read(Path::new(
                        &plan.binding().destination_relative_path,
                    ))
                    .map_err(fs_err)?
                    .into_file();
                self.transfer_store
                    .verify_published_destination_handle(&plan, &mut artifact)
                    .map_err(Self::transfer_error)?;
                return Ok(
                    json!({ "plan_id": plan.id(), "state": journal.state(), "next_sequence": journal.contiguous_ack().map(|v| v + 1).unwrap_or(0), "next_offset": journal.bytes_received(), "epoch": p.epoch, "fence": p.fence, "completed": true, "published": true }),
                );
            }
        }
        if destination.exists() {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "destination already exists; overwrite is forbidden".into(),
            });
        }
        self.ensure_destination_cache_capacity(plan.id())
            .map_err(Self::transfer_error)?;
        let now = Self::now() as u64;
        let lease = self
            .transfer_store
            .acquire_for_fence(&plan, now, authority.expires_at_unix, p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        let journal = self
            .transfer_store
            .claim_at_room_cursor(
                &lease,
                &plan,
                &authority.principal_id,
                p.epoch,
                p.fence,
                now,
                authority.expires_at_unix,
                p.next_sequence,
                p.next_offset,
            )
            .map_err(Self::transfer_error)?;
        // The fresh durable fence is authoritative now. Drop the prior
        // generation's retained handle before PartFileSink stages/removes its
        // generation path (required for no-share-delete Windows handles).
        self.transfer_receivers.remove(plan.id());
        if journal.state() == JournalState::Completed {
            let mut sink = PartFileSink::create(
                &self.transfer_store,
                &plan,
                p.epoch,
                journal.bytes_received(),
            )
            .map_err(Self::transfer_error)?;
            sink.verify_complete().map_err(Self::transfer_error)?;
            return Ok(
                json!({ "plan_id": plan.id(), "state": journal.state(), "next_sequence": p.next_sequence, "next_offset": p.next_offset, "epoch": journal.epoch(), "fence": journal.fence(), "completed": true }),
            );
        }
        let cached = self
            .rebuild_destination_transfer(plan.clone(), journal.clone(), p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        self.transfer_receivers.insert(plan.id().to_owned(), cached);
        Ok(
            json!({ "plan_id": plan.id(), "state": journal.state(), "next_sequence": journal.contiguous_ack().map(|v| v + 1).unwrap_or(0), "next_offset": journal.bytes_received(), "epoch": journal.epoch(), "fence": journal.fence() }),
        )
    }

    pub(super) async fn handle_transfer_destination_chunk(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
            frame_base64: String,
            workspace_id: String,
        }
        let p: Params = parse_params(params)?;
        if p.frame_base64.len() > (MAX_CHUNK_BYTES + 52).div_ceil(3) * 4 {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "transfer frame exceeds bounded base64 budget".into(),
            });
        }
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "destination chunk workspace does not match immutable plan".into(),
            });
        }
        let frame = base64_decode_strict(&p.frame_base64).ok_or_else(|| IpcError::Remote {
            code: app_error::INVALID_PARAMS,
            message: "transfer frame is not canonical base64".into(),
        })?;
        let chunk = TransferChunk::decode(&frame).map_err(Self::transfer_error)?;
        let now = Self::now() as u64;
        let lease = self
            .transfer_store
            .acquire(&plan, now, authority.expires_at_unix)
            .map_err(Self::transfer_error)?;
        let journal = self
            .transfer_store
            .load_for_fence(&plan, p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        self.ensure_destination_cache_capacity(plan.id())
            .map_err(Self::transfer_error)?;
        // Remove while mutating so every error path evicts the rolling state.
        // Only an exact durable cursor match may reuse the retained handle.
        let cached = self.transfer_receivers.remove(plan.id());
        let mut active = match cached {
            Some(cached) => {
                if !cached.matches(p.epoch, p.fence, &journal) {
                    return Err(Self::transfer_error(TransferError::CorruptJournal));
                }
                cached
                    .sink
                    .validate_cached_position(journal.bytes_received())
                    .map_err(Self::transfer_error)?;
                cached
            }
            None => self
                .rebuild_destination_transfer(plan.clone(), journal.clone(), p.epoch, p.fence)
                .map_err(Self::transfer_error)?,
        };
        active
            .receiver
            .receive(&mut active.sink, chunk)
            .map_err(Self::transfer_error)?;
        let updated = active.receiver.journal_snapshot();
        #[cfg(test)]
        self.maybe_inject_persist_fault(&self.transfer_journal_persist_fault, "transfer journal")?;
        self.transfer_store
            .save(&lease, &updated)
            .map_err(Self::transfer_error)?;
        if updated.state() == JournalState::Receiving {
            self.transfer_receivers.insert(plan.id().to_owned(), active);
        }
        Ok(
            json!({ "plan_id": plan.id(), "state": updated.state(), "contiguous_ack": updated.contiguous_ack(), "bytes_received": updated.bytes_received(), "completed": updated.state() == JournalState::Completed }),
        )
    }

    pub(super) async fn handle_transfer_finalize(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
            workspace_id: String,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "finalize workspace does not match immutable plan".into(),
            });
        }
        let journal = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "transfer is incomplete".into(),
            })?;
        let workspace = self.workspace_for(Some(&p.workspace_id))?;
        if journal.published() {
            self.transfer_receivers.remove(plan.id());
            let mut artifact = workspace
                .open_verified_transfer_artifact_read(Path::new(
                    &plan.binding().destination_relative_path,
                ))
                .map_err(fs_err)?
                .into_file();
            self.transfer_store
                .verify_published_destination_handle(&plan, &mut artifact)
                .map_err(Self::transfer_error)?;
            drop(artifact);
            self.transfer_store
                .cleanup_published_generation_parts(&plan)
                .map_err(Self::transfer_error)?;
            return Ok(
                json!({ "plan_id": plan.id(), "published": true, "replayed": true, "sha256": plan.sha256(), "size_bytes": plan.size_bytes() }),
            );
        }
        if journal.epoch() != p.epoch
            || journal.fence() != p.fence
            || journal.state() != JournalState::Completed
        {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "transfer is incomplete".into(),
            });
        }
        // Only an exact terminal fence may release the retained append handle
        // before publish. Stale or premature finalize requests cannot evict a
        // healthy long-running receiver.
        self.transfer_receivers.remove(plan.id());
        let lease = self
            .transfer_store
            .acquire(&plan, Self::now() as u64, authority.expires_at_unix)
            .map_err(Self::transfer_error)?;
        match self
            .transfer_store
            .publish_completed_no_replace(&plan, &workspace)
        {
            Ok(()) | Err(ownmesh_transfer::TransferError::DestinationExists) => {
                let mut artifact = workspace
                    .open_verified_transfer_artifact_read(Path::new(
                        &plan.binding().destination_relative_path,
                    ))
                    .map_err(fs_err)?
                    .into_file();
                self.transfer_store
                    .verify_published_destination_handle(&plan, &mut artifact)
                    .map_err(Self::transfer_error)?;
            }
            Err(error) => return Err(Self::transfer_error(error)),
        }
        // The destination file is now verified as the exact immutable plan
        // artifact. Persist this receipt before returning so a crash after the
        // no-replace publish is replay-safe rather than a false conflict.
        let mut receipt = self
            .transfer_store
            .load_for_fence(&plan, p.epoch, p.fence)
            .map_err(Self::transfer_error)?;
        receipt
            .mark_published(&plan)
            .map_err(Self::transfer_error)?;
        self.transfer_store
            .save(&lease, &receipt)
            .map_err(Self::transfer_error)?;
        self.transfer_store
            .cleanup_published_generation_parts(&plan)
            .map_err(Self::transfer_error)?;
        Ok(
            json!({ "plan_id": plan.id(), "published": true, "replayed": false, "sha256": plan.sha256(), "size_bytes": plan.size_bytes() }),
        )
    }

    pub(super) async fn handle_transfer_status(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, None)?;
        let journal = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?;
        Ok(
            json!({ "plan_id": plan.id(), "size_bytes": plan.size_bytes(), "sha256": plan.sha256(), "state": journal.as_ref().map(ownmesh_transfer::TransferJournal::state), "contiguous_ack": journal.as_ref().and_then(ownmesh_transfer::TransferJournal::contiguous_ack), "bytes_received": journal.as_ref().map(ownmesh_transfer::TransferJournal::bytes_received).unwrap_or(0) }),
        )
    }

    pub(super) async fn handle_transfer_list(
        &mut self,
        _params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        let authority = self.transfer_authority(client)?;
        let plans = self
            .transfer_store
            .list_plans(Self::now() as u64)
            .map_err(Self::transfer_error)?;
        let mut entries = Vec::new();
        for plan in plans {
            if Self::verify_local_transfer_identity(&plan, &authority, None).is_ok() {
                let journal = self
                    .transfer_store
                    .load(&plan)
                    .map_err(Self::transfer_error)?;
                entries.push(json!({ "plan_id": plan.id(), "source_workspace_id": plan.binding().source_workspace_id, "destination_workspace_id": plan.binding().destination_workspace_id, "size_bytes": plan.size_bytes(), "sha256": plan.sha256(), "state": journal.as_ref().map(ownmesh_transfer::TransferJournal::state), "bytes_received": journal.as_ref().map(ownmesh_transfer::TransferJournal::bytes_received).unwrap_or(0) }));
            }
        }
        Ok(json!({ "transfers": entries }))
    }

    pub(super) async fn handle_transfer_cancel(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            epoch: u64,
            fence: u64,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let cleanup_binding = SourceCleanupBinding {
            plan_id: p.plan_id.clone(),
            tenant_id: authority.tenant_id.clone(),
            principal_id: authority.principal_id.clone(),
            device_id: authority.device_id.clone(),
            epoch: p.epoch,
            fence: p.fence,
        };
        if let Some(outcome) = self
            .transfer_store
            .complete_source_cleanup(&cleanup_binding, Self::now() as u64)
            .map_err(Self::transfer_error)?
        {
            self.transfer_senders.remove(&p.plan_id);
            self.transfer_last_chunks.remove(&p.plan_id);
            self.transfer_receivers.remove(&p.plan_id);
            return Ok(
                json!({ "plan_id": p.plan_id, "cancelled": true, "source_only": true, "replayed": outcome.replayed }),
            );
        }
        let plan = self.transfer_plan_for(&p.plan_id, &authority, None)?;
        let journal = match self.transfer_store.load_for_fence(&plan, p.epoch, p.fence) {
            Ok(journal) => journal,
            // A source Agent has no receiver journal or part file to cancel.
            // It still owns an in-memory sender cache which must be dropped on
            // an authenticated transfer cancellation; do not manufacture a
            // destination journal on the source device.
            Err(ownmesh_transfer::TransferError::Terminal)
                if plan.binding().source_device_id == authority.device_id
                    && plan.binding().destination_device_id != authority.device_id =>
            {
                self.transfer_senders.remove(plan.id());
                self.transfer_last_chunks.remove(plan.id());
                self.transfer_store
                    .begin_source_cleanup(&plan, &cleanup_binding, Self::now() as u64)
                    .map_err(Self::transfer_error)?;
                let outcome = self
                    .transfer_store
                    .complete_source_cleanup(&cleanup_binding, Self::now() as u64)
                    .map_err(Self::transfer_error)?
                    .ok_or_else(|| IpcError::Remote {
                        code: app_error::INTERNAL,
                        message: "source cleanup intent disappeared".into(),
                    })?;
                return Ok(
                    json!({ "plan_id": plan.id(), "cancelled": true, "source_only": true, "replayed": outcome.replayed }),
                );
            }
            Err(error) => return Err(Self::transfer_error(error)),
        };
        if journal.state() == JournalState::Cancelled {
            return Ok(
                json!({ "plan_id": plan.id(), "cancelled": true, "state": journal.state(), "replayed": true }),
            );
        }
        if matches!(
            journal.state(),
            JournalState::Completed | JournalState::Published | JournalState::Failed
        ) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "completed or failed transfer cannot be cancelled".into(),
            });
        }
        // Exact non-terminal fence/state has now been accepted. Stale cancel
        // requests above cannot evict the active destination stream.
        let cached_destination = self.transfer_receivers.remove(plan.id());
        let now = Self::now() as u64;
        let lease = self
            .transfer_store
            .acquire(&plan, now, authority.expires_at_unix)
            .map_err(Self::transfer_error)?;
        let mut active = match cached_destination {
            Some(cached) => {
                if !cached.matches(p.epoch, p.fence, &journal) {
                    return Err(Self::transfer_error(TransferError::CorruptJournal));
                }
                cached
                    .sink
                    .validate_cached_position(journal.bytes_received())
                    .map_err(Self::transfer_error)?;
                cached
            }
            None => self
                .rebuild_destination_transfer(plan.clone(), journal.clone(), p.epoch, p.fence)
                .map_err(Self::transfer_error)?,
        };
        active
            .receiver
            .cancel(&mut active.sink)
            .map_err(Self::transfer_error)?;
        let updated = active.receiver.journal_snapshot();
        self.transfer_store
            .save(&lease, &updated)
            .map_err(Self::transfer_error)?;
        self.transfer_senders.remove(plan.id());
        self.transfer_last_chunks.remove(plan.id());
        let _ = self.transfer_store.remove_source_snapshot(&plan);
        Ok(json!({ "plan_id": plan.id(), "cancelled": true, "state": updated.state() }))
    }

    pub(super) async fn handle_transfer_artifact_get(
        &mut self,
        params: Option<Value>,
        client: &ClientIdentity,
    ) -> IpcResult<Value> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Params {
            plan_id: String,
            workspace_id: String,
            #[serde(default)]
            offset: u64,
            #[serde(default)]
            max_bytes: Option<u64>,
        }
        let p: Params = parse_params(params)?;
        let authority = self.transfer_authority(client)?;
        let plan = self.transfer_plan_for(&p.plan_id, &authority, Some("destination"))?;
        if p.workspace_id != plan.binding().destination_workspace_id {
            return Err(IpcError::Remote {
                code: app_error::UNAUTHORIZED,
                message: "artifact workspace does not match immutable plan".into(),
            });
        }
        let journal = self
            .transfer_store
            .load(&plan)
            .map_err(Self::transfer_error)?
            .ok_or_else(|| IpcError::Remote {
                code: app_error::CONFLICT,
                message: "artifact is not prepared".into(),
            })?;
        if !matches!(
            journal.state(),
            JournalState::Completed | JournalState::Published
        ) {
            return Err(IpcError::Remote {
                code: app_error::CONFLICT,
                message: "artifact is incomplete".into(),
            });
        }
        let ws = self.workspace_for(Some(&p.workspace_id))?;
        let artifact = ws
            .open_verified_transfer_artifact_read(Path::new(
                &plan.binding().destination_relative_path,
            ))
            .map_err(fs_err)?;
        // The completed artifact is deliberately a no-replace hardlink to the
        // private verified part.  `ownmesh-fs` correctly rejects that
        // cross-boundary hardlink for ordinary path-selected reads; this is the
        // narrow exception for an already authenticated immutable plan.  The
        // caller cannot choose this path, and the read remains regular-file,
        // no-symlink, offset/page bounded.
        let want = p
            .max_bytes
            .unwrap_or(64 * 1024)
            .clamp(1, MAX_CHUNK_BYTES as u64);
        let total = artifact.size_bytes();
        if p.offset > total {
            return Err(IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: "transfer artifact offset exceeds its immutable total size".into(),
            });
        }
        let mut file = artifact.into_file();
        self.transfer_store
            .verify_published_destination_handle(&plan, &mut file)
            .map_err(Self::transfer_error)?;
        file.seek(SeekFrom::Start(p.offset))
            .map_err(|error| IpcError::Remote {
                code: app_error::INVALID_PARAMS,
                message: format!("seek transfer artifact: {error}"),
            })?;
        let mut data = vec![0_u8; usize::try_from(want).unwrap_or(MAX_CHUNK_BYTES)];
        let returned = file.read(&mut data).map_err(|error| IpcError::Remote {
            code: app_error::INTERNAL,
            message: format!("read transfer artifact: {error}"),
        })?;
        data.truncate(returned);
        let truncated = p
            .offset
            .saturating_add(u64::try_from(returned).unwrap_or(u64::MAX))
            < total;
        let returned = data.len() as u64;
        Ok(
            json!({ "plan_id": plan.id(), "offset": p.offset, "bytes": returned, "total_bytes": total, "next_offset": if truncated { Value::from(p.offset.saturating_add(returned)) } else { Value::Null }, "truncated": truncated, "encoding": "base64", "content_base64": base64_standard(&data), "page_sha256": sha256_hex(&data), "sha256": plan.sha256() }),
        )
    }
}
