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
- The real public MCP → workerd/DeviceRoom → Agent WSS → ownmeshd fixture now
  creates a nested temporary Git repository and has `review.start` run pinned
  argv-only `git apply` for two working-tree files. It proves distinct
  passing/failing argv tests, status/diff cursor bounds, typed multi-page result
  spool digests, exact-once/payload-conflict handling, no implicit ref or index
  mutation, workspace ACL and invalid-repository rejection, stale-HEAD
  invalidation, and cancellation through process-tree termination. E7 is PROVEN
  on this local real path.

### E6 — nine structured profile adapters
- Device IPC `profile.list` / `profile.show` run real PATH detection for the nine official profile IDs, and public MCP routes both through the Agent to the device.
- Each official profile runs in the persistent sidecar with strict bounded stdio framing: headerless Codex app-server, ACP v1 (including negotiated load), Pi RPC, and stream-json argv dialects.
- The public workerd acceptance path proves all nine unique outputs, delayed turn completion without blocking `session.open`, native argv/negotiated resume where source-backed, explicit degraded rejection otherwise, safe no-credential-probe status, and exact terminate cleanup.
- CLI `profile *` surfaces remain explicit unsupported; this acceptance covers the remote MCP profile contract.

### E9 — authenticated resumable transfer
- The public MCP → local Wrangler/workerd → TransferRoom Durable Object → two
  independently enrolled Agent WSS → two real `ownmeshd` path proves
  send/get/list/status/cancel, three-plus binary 64 KiB chunks including NUL and
  non-UTF-8 bytes, zero-byte artifacts, bounded artifact pages and exact hashes.
- A 32 MiB transfer kills and restarts the destination Agent/daemon after a
  durable non-zero ACK, then resumes from that Room cursor under a fresh
  epoch/fence. A separate partial 32 MiB cancellation removes all generation
  parts and leaves only its bounded terminal journal.
- The fixture also proves no-overwrite and owner/tenant/device/workspace/path
  denials. After stopping both Agents and workerd, it snapshots the real
  D1/Durable Object SQLite files, requires `PRAGMA integrity_check = ok`, and
  scans raw cells/bytes: bearer tickets, JTI, private ephemeral material and
  relay ciphertext/plaintext are absent. Only user-requested artifact pages are
  allowlisted with their 64 KiB cap, hash and expiry.
- Raw ticket/key/frame substitution is deliberately not injectable through the
  public MCP surface. Lower-layer wrong-ticket, proof, replay, gap, duplicate,
  fence, tamper and overflow cases remain covered by strict TransferRoom,
  transport, runtime and transfer-core tests; the public fixture does not
  mislabel them as public-client injections.

## Gate posture
- `scripts/tests/test_v12_e2_e9_workerd_loopback.py` invokes both the E2/E3 and
  E9 real-path fixtures. It stays **RED (exit 2)** because E8 remains open; E9
  is PROVEN and can no longer be silently skipped by the aggregate gate.
- E8's native broker lifecycle is implemented on Linux, macOS, and Windows, and
  the Linux root/systemd receipt passes. The aggregate gate stays red until the
  real public MCP → installed ownmeshd → native broker route and the remaining
  macOS/Windows native release receipts are recorded.
- Live Cloudflare deployment plus ChatGPT DCR/OAuth/passkey return has been
  manually exercised. It is compatibility evidence, not a reproducible release
  gate and does not replace the local workerd acceptance fixtures.
- The completeness claim remains false for the explicitly excluded CLI surfaces.

## Surface registry

[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**22 explicit unsupported CLI surfaces** and **27 total** unsupported surfaces.
Profile CLI wiring remains unsupported. Transfer CLI plan/send/list/status/cancel
and native privileged broker install/status/uninstall are supported; their exact
platform evidence is recorded separately in the manifest and E8/E9 notes.
Completeness claim remains false.
