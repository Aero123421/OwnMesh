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
- ChatGPT confirmation is still not claimed as a cryptographic OwnMesh attestation.
  Browser/CLI recovery remains the optional path when device policy is configured to ask.

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

### E6 — profile detection + PTY launch
- Device IPC `profile.list` / `profile.show` / `profile.scan` run real PATH detection for the nine official profile IDs.
- MCP `ownmesh_list_profiles` with `device_id` routes to the device; without `device_id` returns catalog metadata only.
- `session.open` with `profile_id` builds an official launch plan and owns a live PTY fallback. Credentials never leave the device.
- CLI `profile *` surfaces remain explicit unsupported until CLI wiring is proved.

## Gate posture
- `scripts/tests/test_v12_e2_e9_workerd_loopback.py` stays **RED (exit 2)** until E4–E9 acceptance rows are fully evidenced on the real binary × workerd path.
- E8 elevated broker mint and E9 resumable transfer remain open.
- Completeness claim remains false; E10 live-account proof is out of scope for this run.

## Surface registry

[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**27 explicit unsupported CLI surfaces** and **34 total** unsupported surfaces.
Profile CLI wiring, transfer, and elevated broker install remain unsupported.
Completeness claim remains false.
