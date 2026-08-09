# OwnMesh v1.2.0-beta.12

Integrity visit focused on Terra E5 blockers plus the next E6/E7 production slices.

## Highlights

### E3 — policy Ask identity + recovery approval execution
- Remote Agent dispatches bind the MCP `operation_id` into `DaemonRuntime` so policy
  `Ask` receipts echo the control-plane identity (DeviceRoom no longer rejects
  `operation_id_mismatch` on `OWNMESH_E_APPROVAL_REQUIRED`).
- Control-plane `/approve` recovery decisions are applied on-device: deferred
  request executes or denies exactly once; results fold onto the original MCP
  operation via `target_operation_id`.
- Recovery `approval.decision` frames now carry server-computed `payload_hash` +
  `authorization.bound_action` (decision, target op/hash/expiry, approver
  principal/tenant, claim version). The Agent no longer bypasses exact-action
  verification for this path. Browser transaction and decision envelope expiry
  never outlive the original MCP `expires_at`; expired deferred approvals fail
  closed on-device without side effects.
- ChatGPT confirmation is still not claimed as a cryptographic OwnMesh attestation.
  Browser/CLI recovery remains the optional path when device policy is configured to ask.
- CLI one-shot `read_until` PTY helper uses a bounded sync channel + aggregate byte
  cap (no per-read accumulator clones under output pressure).

### E5 — live PTY integrity
- Process-tree terminate for cloud sessions (`taskkill /T` on Windows; Unix session + process-group kill) so background shell descendants do not survive `session.terminate`.
- `session.resize` fails closed before sequence reservation when no live PTY host exists (daemon recovery).
- Live output ring reports remaining bytes; replay surfaces continuation (`truncated` / `next_seq` / `live_pending_bytes`) instead of false EOF.

### Mandatory bounds
- Executable pin/revalidation streams hashes under a 64 MiB ceiling (no unbounded `read`).
- Idempotency journal, git diff spool, and agent transport state all stat/ceiling before allocation.

### E7 — bounded unified-diff patch
- `ownmesh_fs_patch` accepts `patch_format=unified` (or a hash-checked unified body) for single-file apply.
- Multi-file/binary diffs fail closed. Whole-file replace remains available via `patch_format=replace`.

### E6 — nine structured profile adapters
- Device IPC `profile.list` / `profile.show` run real PATH detection for the nine official profile IDs, and public MCP routes both through the Agent to the device.
- Each official profile runs in the persistent sidecar with strict bounded stdio framing: headerless Codex app-server, ACP v1 (including negotiated load), Pi RPC, and stream-json argv dialects.
- The public workerd acceptance path proves all nine unique outputs, delayed turn completion without blocking `session.open`, native argv/negotiated resume where source-backed, explicit degraded rejection otherwise, safe no-credential-probe status, and exact terminate cleanup.
- CLI `profile *` surfaces remain explicit unsupported; this acceptance covers the remote MCP profile contract.

## Gate posture
- `scripts/tests/test_v12_e2_e9_workerd_loopback.py` stays **RED (exit 2)** until E7–E9 acceptance rows are fully evidenced on the real binary × workerd path.
- E8 elevated broker mint and E9 resumable transfer remain open.
- Completeness claim remains false; E10 live-account proof is out of scope for this run.

## Surface registry

[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**27 explicit unsupported CLI surfaces** and **34 total** unsupported surfaces.
Profile CLI wiring, transfer, and elevated broker install remain unsupported.
Completeness claim remains false.
