# ADR 0010: Bounded device-local op-journal retention for terminal receipts

- Status: Accepted
- Date: 2026-08-16
- Deciders: OwnMesh runtime maintainers

## Context

The device-local idempotency journal (`op-journal.json`) stores one entry per
completed remote/local side-effect operation, keyed by
`principal + idempotency_key`, to guarantee exact-once replay: a retried
operation returns the stored receipt instead of re-executing. Until v1.2.13 the
completed entries were persisted verbatim, including full stdout/file bodies.
A long-lived daemon therefore grew toward the hard durable caps
(`MAX_OP_JOURNAL_ENTRIES = 4096`, `MAX_OP_JOURNAL_FILE_BYTES = 4 MiB`); at the
cap every new side-effect operation was refused at the receipt-persist step,
creating an intentionally uncertain outcome. There was no practical lifecycle
for terminal receipts, and the failure mode was invisible to `system.diagnose`
and `ownmesh doctor`.

The control plane bounds its own replay retention on a different, staged
schedule: MCP operation results with an idempotency key are compacted to
tombstones after 7 days (`MCP_OPS_RESULT_TTL_MS`) and those tombstones are
hard-deleted 30 days after tombstoning (`MCP_OPS_TOMBSTONE_TTL_MS`, which
also resets `updated_at`), i.e. roughly 37 days after completion. Keyless
terminal rows are hard-deleted at the 7-day result TTL because they bind no
replay key. The device window and the control-plane window are therefore
**not identical**; the honest statement is that the control plane retains a
keyed idempotency receipt strictly longer than the device's 30-day receipt
window, so a device receipt never outlives the key the control plane could
replay against.

## Decision

1. **Completed entries are compacted before durable persistence and after
   the receipt is durably committed.** The immediate response still carries
   the full result; once the exact-once receipt is durably persisted, both
   the durable file and the in-memory map store only that receipt
   (`durable_receipt: true`, `truncated: true`, `status`, `operation_id`,
   completion timestamp, plus the small additive receipt fields
   `remote_payload_hash` and — for `review.start` — `review_id` and
   `workspace_id`, so an idempotent replay can still continue through
   `review.show`/`review.page`). In-session replay therefore returns the
   compact receipt (never a re-execution, never a huge body). Large
   stdout/file bodies are never retained in durable state or indefinitely
   in memory when a compact receipt is sufficient.
1b. **Every completed entry carries the exact-once `operation_id` marker.**
    `review.start` stores the serialized `ReviewManifest`, which names the
    control-plane id as `remote_operation_id`; the handler now also stamps
    the `operation_id` written by `begin_idempotent` onto the stored body,
    so a finished review is classified completed (and replays as a receipt)
    instead of being treated as an uncertain in-progress/unknown state.
    `session.open` participates in the same journal: when the caller
    supplies an idempotency key (the Agent/MCP transport always injects the
    signed operation key) the durable marker is reserved before the session
    record is created and the completed body is stored with the explicit
    `__ownmesh_operation_state == "completed"` value, so a retried open
    after response loss or daemon restart continues the original session
    instead of spawning a duplicate PTY/sidecar; the compact receipt keeps
    the generated session id (under its original field name `id`, plus an
    additive `session_id` alias so the first and the replayed public
    responses are schema-stable) and the controller lease for that
    continuation. Local IPC callers that send no key are unchanged (no
    journal entry).
1a. **Completion is an explicit, positive marker.** Only `durable_receipt:
    true`, the explicit `__ownmesh_operation_state == "completed"` value, or
    a legacy (pre-1.2.13) completed body with positive completion proof
    (`operation_id` plus `decision`/`approval_required`/`review_id`) is
    classified completed. A JSON object with no explicit marker — a
    truncated or hand-written `{}` — is **uncertain**, never compacted,
    never evicted, and never replayed as completed. Legacy journals still
    migrate: provably-completed bodies are stamped and compacted at load;
    everything else stays fail-closed.
1b. **Load-time compaction is durably fail-closed for *side effects*.** The
    compacted journal is persisted at load. If that persist fails, a stale
    `op-journal.json.bak` cannot be removed, or the primary/backup is
    corrupt/over-budget, the daemon **starts in degraded read-only mode**
    rather than refusing startup entirely. Side-effect operations
    (`write`/`exec`/session mutation/transfer/policy mutation) fail closed
    with `OWNMESH_E_JOURNAL_DEGRADED` and a local repair hint. Read-only
    surfaces (`status`, `doctor`, `fs_read`/`fs_list`/`fs_stat`,
    `system_diagnose`) stay up and report `journals.op_journal.status =
    degraded` / overall `journal_degraded`. The in-memory journal is empty
    and is **not** treated as a healthy empty journal. Repair is local-only
    (`ownmesh doctor --repair-journal --i-understand-replay-risk`): it
    archives the unreadable file, restores a valid backup when one exists,
    or writes an empty journal after explicit confirmation. Automatic
    remote repair is out of scope. The byte-budget check still validates
    the pretty-serialized size the durable writer actually emits.
2. **Terminal receipts have an explicit bounded lifecycle.** Every completed
   entry carries `__ownmesh_completed_unix`. When the journal is at capacity
   (entries or durable bytes), only completed entries older than **30 days**
   may be evicted. This is the device-local replay window: within it a
   retried operation is replayed as a receipt, and after it a retried
   operation is treated as new. It is **not** claimed to equal the
   control-plane tombstone window (which is 7 days result retention + 30
   days tombstone retention, hard-deleted 30 days after tombstoning — the
   control-plane key always outlives the device window, so the device never
   replays a receipt the control plane has already forgotten). Legacy entries
   without the stamp are stamped at load (conservatively, with the load
   time) so they age normally.
3. **In-progress/uncertain markers are never compacted or evicted.** The
   non-retriable in-progress marker is the exact-once commit point; pruning
   it could permit duplicate side effects. At capacity with nothing evictable,
   new keys are still refused fail-closed.
4. **Health surfaces expose the lifecycle.** `system.diagnose` gains an
   additive `journals.op_journal` field (entries / durable bytes vs caps,
   in-progress count, uncertain count, warn ≥ 60% and critical at cap
   statuses) and `ownmesh doctor` gains a read-only `journals.op_journal`
   check. New additive overall values (`journal_degraded`,
   `op_journal_pressure`, `op_journal_uncertain`, `transition_journal_issues`)
   may appear; the 5-check id contract is
   unchanged. An unreadable journal reports `journals.op_journal.status =
   degraded` and overall `journal_degraded` instead of refusing daemon
   startup. Entries the runtime refuses to replay/compact/evict (unknown
   forward-version state, malformed state values, or non-object entries) are
   counted as uncertain and never reported healthy.
5. **A completed remote receipt may be removed early only after a durable
   control-plane commit acknowledgement.** From v1.2.31, DeviceRoom sends an
   authenticated `operation.reconcile` acknowledgement only after the matching
   terminal `mcp_operations` row and the room sequence are durable. On
   reconnect the Agent offers completed operation ids in pages of at most 64;
   DeviceRoom confirms them with point lookups bound to the same device. The
   Agent then atomically removes only exact-id, positively completed receipts.
   Missing, non-terminal, foreign-device, in-progress, and unknown-state
   entries are never removed. The feature is advertised in
   `accepted.session_parameters`, so a new Agent never sends the additive
   request to an older control plane.

## Consequences

- Exact-once/replay within the 30-day device-local window is preserved:
  in-session replay returns the compact receipt (the full body exists only
  in the immediate response), restart replay returns the same compact
  durable receipt (never a re-execution). This is documented in
  `docs/RELEASE_NOTES_v1.2.13.md`.
- **Documented semantic change:** a completed operation replayed *after a
  daemon restart and after 30 days* may re-execute, because its receipt was
  evicted at capacity (or refused on the replay path). The control plane
  retains its idempotency key strictly longer (7-day result TTL plus a
  30-day tombstone TTL, hard-deleted 30 days after tombstoning), so the
  device never replays a receipt the control plane has already forgotten;
  a retried operation after the device window is a fresh operation on both
  sides. No security boundary is weakened: the eviction is age-gated,
  capacity-triggered, and never touches in-progress markers.
- Replayed payloads may include the additive `__ownmesh_completed_unix`
  field (alongside the existing `replayed` marker).
- Long-lived daemons stay far below the hard byte cap because the durable
  file holds receipts, not bodies. A connected v1.2.31+ deployment normally
  reclaims committed remote receipts promptly; the 30-day rule remains the
  fallback when acknowledgement is unavailable.

## Alternatives considered

- **Persist full bodies forever and only raise the caps.** Rejected: the
  observed production failure grew to 3.02 MiB with 425 ordinary entries;
  raising caps just postpones the same refusal and duplicates sensitive
  result bodies in durable state.
- **Evict completed entries regardless of age when at capacity.** Rejected:
  a still-replayable operation could be re-executed within the control
  plane's idempotency window — a real duplicate-side-effect risk.
- **Source the login shell PATH in the daemon (related P1-D work).**
  Rejected for the sibling ADR-less fix: shell sourcing is nondeterministic
  and untestable; deterministic user-local discovery was chosen instead.
