# Changelog

## Unreleased

- Durable MCP operation quota is configurable via Worker env
  `MCP_OPS_MAX_PER_TENANT` (default 20_000). Tool responses warn with
  `mcp_ops_quota_pressure` at ≥ 60% occupancy, `ownmesh_system_diagnose`
  reports `control_plane.mcp_ops_quota`, and keyless terminal rows are
  hard-deleted at the 7-day result TTL instead of occupying a 30-day
  idempotency tombstone. Fail-closed `OWNMESH_E_MCP_OP_QUOTA` and keyed
  receipt retention are unchanged.
- `ownmesh_get_operation` accepts optional `wait_ms` (clamped to 25s) to
  long-poll until a terminal snapshot. Concurrent waiters per tenant are
  capped; excess calls return the current snapshot with
  `mcp_get_operation_wait_saturated` and do not persist that warning.
- `ownmesh_transfer_plan` accepts optional `overwrite_expected_sha256`. When
  set, destination replacement is allowed only if the existing file matches
  that hash at preflight and publish. Blind `force`/`overwrite` remains
  rejected. `ownmesh transfer plan --overwrite-expected-sha256` exposes the
  same bound.
- `ownmesh_command_run` / `ownmesh_run_command` accept `detach: true` so a
  long-running command is dispatched without the synchronous timeout clamp
  and is not terminalized by the five-minute poll expiry. Completion is
  retrieved with `ownmesh_get_operation`. Concurrent detached jobs per device
  are capped fail-closed. The synchronous `timeout_ms` clamp is configurable
  via Worker env `MCP_MAX_TIMEOUT_MS` (default 300000, hard ceiling 3600000).
  Timed-out synchronous commands include hint
  `use detach:true or a session for long-running commands`.

## v1.2.13 — Runtime reliability and cross-platform repair

- Expired sidecar transition journal records are reconciled non-blockingly
  instead of poisoning every future session; a record is cleared only when
  session/supervisor state and an OS-level or supervisor liveness probe prove
  every referenced predecessor/successor sidecar is dead, and retained
  fail-closed with a health surface otherwise. A failed supervisor sweep no
  longer untracks a live host.
- Completed op-journal entries are compacted to exact-once durable receipts
  before persistence; terminal receipts have a bounded 30-day lifecycle and a
  lingering pre-compaction `.bak` is removed *before* the compacted write
  (so a crash between the write and the cleanup cannot leave a legacy
  large-body copy behind; the backup is recovered from if the primary is
  missing, and an unremovable stale backup at load refuses startup
  fail-closed with an actionable message; runtime persistence also fails
  closed and rolls back its in-memory mutation). Completed markers without the
  exact-once `operation_id` are classified uncertain (never replayed,
  compacted, or evicted). Compact receipts keep the original field names
  (`id` stays `id`, plus an additive `session_id` alias for `session.open`),
  so the first and the replayed public responses are schema-stable.
- Op-journal near-capacity eviction is proactive: the byte-pressure projection
  includes the incoming in-progress marker, so a journal within one marker's
  worth of the 4 MiB cap evicts expired completed receipts *before* inserting
  the marker instead of refusing the new side-effect key with a byte-budget
  failure while eligible receipts sat unused. Control Plane idempotency
  tombstones past the 30-day hard-delete window are expired *before* the
  existing-row lookup, so a closed-window key is minted as a fresh operation
  instead of returning `existing` forever.
- Windows executable resolution follows PATHEXT semantics everywhere:
  npm-style extensionless shims never beat an invocable `.exe/.cmd/.bat`
  sibling, batch shims run through the pinned absolute `cmd.exe`, and default
  interactive sessions resolve the shell through the same shared resolver.
  Generic command execution retains proxy invocation paths while separately
  pinning their canonical backing executable.
  Default PTY shells fail closed: an unresolvable `$SHELL`/bare `cmd.exe` is
  never handed to a spawner (the absolute system `cmd.exe` or `/bin/sh` is
  used instead), and the live PTY spawner re-resolves and rejects
  unresolvable programs with the exact reason. Unix uses `portable-pty` 0.9 so
  macOS children start with cleared inherited signal masks; Windows remains on
  0.8.1 because 0.9 enables `PSEUDOCONSOLE_INHERIT_CURSOR`, whose `ESC[6n`
  handshake blocks an unattended ConPTY before command output. Darwin
  termination snapshots descendants by controlling TTY, PTY
  session, and ancestry. It first freezes the dedicated TTY, preventing a
  waiting parent shell from running its next command when a leaf exits, then
  directly kills the snapshot and the frozen TTY remainder around the leader
  signal (Apple `pkill` has no `-s sid` selector). Bounded
  confirmation checks both the child handle and exact PID state in the process
  table; an absent PID confirms exit, a zombie is
  authoritatively reaped, and Darwin's `P_WEXIT` (`E`) state is accepted as
  committed to kernel exit without a potentially blocking synchronous wait;
  every ordinary live/observation-error state remains fail-closed.
- Linux user-CLI discovery covers `~/.local/bin`, Cargo, Nix, npm-global and
  NVM node bins without sourcing shell startup files; service PATH mismatch is
  surfaced in diagnostics.
- The shipped systemd user unit is reconciled with OwnMesh custody and
  registered workspaces without disabling hardening — this is **process-level
  and proc-visibility** hardening only; the unit deliberately provides no
  `ProtectSystem=`-style filesystem confinement or systemd workspace
  allow-list (every filesystem namespacing directive would force
  `PrivateUsers=yes` in a per-user service and hide real uids, breaking
  byte-for-byte custody validation; ADR 0011). The daemon also reads
  `/proc/self/uid_map` at startup and logs an actionable warning when the
  effective unit has placed it inside a user namespace that hides real host
  uids (custody still fails closed; the warning explains cause and
  remediation). Doctor discloses degraded
  service protection and honors `SYSTEMD_UNIT_PATH` replace semantics (a
  unit outside the effective search path is never reported as loaded).
- `system.diagnose`/`ownmesh doctor` no longer report `healthy` alongside
  poisoned transition journals, dangerous op-journal pressure, or official
  profile-discovery failures; durable in-progress operation markers are shown
  as warnings. Remote session mutations are exactly-once, completed review
  receipts preserve failed/cancelled phase, and completed session/review
  retries are looked up before mutable local preflight. Error mapping preserves the actionable cause
  (Win32 error 193, missing profile executables, journal repair hints).
  Free-form diagnosis-note redaction also covers marker-plus-filler forms
  (`token is <long-opaque-value>`, `api key was <value>`), not just
  assignment/space-delimited shapes.
- Linux enrollment uses the OS hostname instead of `unknown-host` when
  environment variables are absent.

## v1.2.12 — Workspace activation and transfer expiry

- Newly registered workspaces stay `pending_activation` until the Agent
  generation is observed, so `workspace_list` cannot imply execution readiness.
  A completed remove is not revived by a later stale list of the same generation.
- `workspace_not_available` now carries a bounded cause and next action.
  Fresh-passkey `approval_required` responses always include a same-origin
  `approval_url`. Linux enrollment uses the OS hostname instead of
  `unknown-host`.
- Transfer plan/send/status expose typed next-action semantics, expire
  non-terminal transfers, and revalidate the immutable source at send. The TUI
  Devices screen can refresh Control Plane inventory on an explicit keypress.

## v1.2.11 — Crash-safe self-update

- `ownmesh update` now performs the complete signed upgrade lifecycle: session
  drain, service stop, five-binary replacement, restart, version/health check,
  and verified rollback. Windows hands off to a private detached worker so the
  installed CLI never locks its own replacement.
- A durable apply journal and PID-plus-process-birth transaction binding recover
  interrupted updates without trusting PID reuse or an unverified backup.
- Portable installers quiesce exact installed OwnMesh processes, restart a
  previously running service, and restore the previous binaries when post-install
  health fails. Linux headless SSH sessions safely derive an existing systemd
  user-bus environment without enabling lingering or creating a bus.

## v1.2.10 — Full Access routing compatibility

- Explicit `workspace_id: null` remains the public Full Access selection but is
  normalized to the schema-compatible omitted field on the internal Agent wire,
  preventing valid unbound operations from disconnecting the Agent.
- Device cancel controls remain workspace-independent while retaining their
  exact target, principal, tenant, device, and idempotency bindings, so online
  cancellation reaches workspace-bound operations.

## v1.2.9 — Runtime and workspace authority

- Workspace records are device-scoped and synchronized from authenticated
  Agent readiness; opaque mapping generations fence same-ID root replacement,
  and restricted null-workspace operations are rejected before routing.
- Durable cancel fencing, clearer dispatch phases, credential-rotation-safe
  idempotency, and bounded internal-context timing make operation state converge
  across disconnects and retries.
- Expired Agent dispatches reconcile through exact-once receipts instead of
  poisoning the WebSocket; uncertain legacy dispatches fail closed.
- Windows service restart waits for a real stop/ready transition, profile probes
  are time-bounded, effective policy is remotely readable, and deprecated
  session release is hidden from model-facing discovery.

## v1.2.8 — Git workspace binding

- Relative Git operations now fail closed when repository-local configuration
  redirects the worktree outside the selected OwnMesh workspace.
- Valid linked worktrees and explicit absolute Full Access operations retain
  their existing behavior.

## v1.2.7 — Windows installer reliability

- The verified PowerShell installer now retries only transient Windows
  sharing/image-lock failures while replacing installed binaries.
- A persistent lock still aborts the upgrade, restores the prior installation,
  and reports the exact recovery action; signature, checksum, custody, and
  post-install verification remain unchanged.

## v1.2.6 — Runtime correctness and agent ergonomics

- Device enrollment state and live routing presence are reported separately;
  expired operations and reconnect backoff now converge after idle/restart paths.
- Interrupted session creation and stale supervisor state reconcile only with
  exact process-birth or authenticated supervisor evidence.
- Linked Git worktrees, Rustup proxy execution, file-read cursors, optimistic
  hash conflicts, Windows command output, and large executable pinning are
  handled consistently.
- Remote filesystem, Git, command, and diagnosis operations bind an explicit
  workspace and its authoritative version through request and result receipts.
- Synchronous MCP calls wait briefly for fast terminal results, while normal
  responses are compact and durable authority metadata remains server-side.
- Codex replay events are normalized into bounded semantic events, and the new
  typed diagnosis tool explains common offline/supervisor/stale-session states
  without exposing logs, paths, argv, environment values, or credentials.
- The official CLI securely loads its managed IPC credential and Doctor reports
  credential/service states without incorrectly declaring keychain data absent.
- `/health` is a storage-free liveness probe; `/health/ready` remains the
  fail-closed dependency and schema readiness check.

## v1.2.5 — Authentication recovery and rate-limit resilience

- Remote operation polling now stays below the control-plane credential rate
  limit and honors bounded `Retry-After` responses instead of failing long jobs.
- The TUI exposes an explicit device-flow re-authentication action even when a
  stale local login marker exists; it never reads or prints credential secrets.
- Owner login, OAuth consent, and device verification provide primary UI copy
  in English, Japanese, Simplified Chinese, and Russian, with headless/passkey
  recovery guidance.
- Device-code requests can be explicitly denied through the same short-lived,
  single-use, principal-bound transaction used for approval.

## v1.2.4 — Guided TUI onboarding

- The bundled dark TUI now guides first-run server setup, language and policy
  selection, device-code sign-in, device enrollment, and Agent startup.
- Dashboard status distinguishes configured, authenticated, enrolled, service
  installed, and Agent-running states; ChatGPT connector setup is a separate,
  clearly labelled step.
- Setup and repair preserve unrelated instances, update preferences, and
  custom policy rules unless the user explicitly selects a different preset.
- Windows user autostart uses a root-level least-privilege task that standard
  users can create. Existing legacy tasks are detected and removed during
  migration, and task enumeration fails closed on query errors.

## v1.2.3 — Policy precedence and real-path evidence

- An explicit `deny` policy rule now outranks a matching temporary grant. A deny
  added after a grant was issued takes effect immediately instead of waiting for
  the grant to expire (specification §7.7).
- The `workspace_only` and `recommended` presets ask before reading
  credential-like files (`.env*`, private keys, `credentials`, keystores) inside
  a workspace. The classification is derived by the daemon from the resolved
  path; clients cannot set or suppress it. Full-access presets are unchanged and
  keep no hidden ask.
- Policy rules accept an optional `when_tag` condition matched against
  server-computed operation facts.
- `docs/mcp-clients.md` now lists all six OAuth scopes with their real tool
  membership. The previous table omitted `ownmesh.write` and `ownmesh.session`
  and attributed session tools to `ownmesh.exec`.
- New decision records: ADR 0007 (restricted presets deny command execution),
  ADR 0008 (control-plane authorization is scopes plus action binding).
- Added `docs/ROADMAP.md`; `pnpm -r lint` now runs a repository lint distinct
  from `typecheck`.
- Policy rule prefixes retain their documented textual behavior while resolving
  interior traversal before matching; temporary grants remain component-bound.
- `policy explain` now accepts a path and workspace and uses the same
  daemon-derived sensitive tags as execution.
- Log commands unwrap daemon results consistently and surface approval-required
  responses instead of printing transport envelopes.
- The nightly loopback workflow runs real ownmeshd binaries against local
  Wrangler for E1, E2/E3, and resumable E9 transfer without weakening
  production health or rate limits.

## v1.2.2 — Grant isolation and local log access

- Filesystem temporary grants are bound to one canonical workspace and native
  path components, preventing cross-workspace or separator-based scope reuse.
- `ownmesh logs providers/query` exposes bounded, cursor-paged device logs over
  local authenticated IPC. Log bodies are intentionally not routed through the
  remote MCP control plane.
- Human-readable log output escapes terminal control characters.
- The daemon runtime is split into focused session, transfer, and workspace
  modules without changing its protocol contract.
- Setup and Doctor guidance better distinguish the recommended path from the
  broader full-access mode.

## v1.2.1 — Stable UX and contract fixes

- Read-only first-run commands no longer create configuration that blocks setup.
- JSON failures emit exactly one stable envelope across CLI surfaces.
- Control-plane rate limits separate authenticated credentials from shared-IP
  bootstrap traffic while retaining a coarse IP abuse ceiling.
- `doctor` network access is opt-in, `--offline` overrides aliases, and explicit
  probe failures return a non-zero status.
- Existing v1.2 Unicode/space instance aliases remain readable while newly
  created aliases use the strict portable syntax.

## v1.2.0 — Stable supported surface

- **Complete shipped CLI:** the machine-checked supported-surface registry has
  no intentionally unimplemented entries. Device rename/labels, remote
  exec/session creation, profile flows, approval watch/decisions, typed policy
  and recovery administration, transfer, and bounded MCP stdio are wired.
- **Security administration:** approval, policy, unlock, and token mutations
  require a fresh passkey decision bound to the exact operation and execute
  exactly once; remote routes never fall back locally.
- **Self-hosted UX:** signed one-line installers, desktop/headless quickstart,
  guided Cloudflare deployment, rotating OAuth refresh tokens, and ChatGPT MCP
  linking form one supported onboarding path.
- **Evidence disclosure:** the networkless broker lifecycle is implemented on
  Linux/macOS/Windows and has a Linux native receipt. macOS/Windows native and
  full public E8 receipts, plus automated external ChatGPT E10 evidence, remain
  tracked separately and are not claimed as live-proven.

## v1.2.0-beta.12 — E5 process-tree/replay integrity + E6 detect + E7 unified diff

- **Self-hosting UX:** portable `wrangler.jsonc`, guided D1/migration/deploy/owner
  bootstrap, one-command machine `setup --quickstart`, and a headless device-code
  variant. Re-running guided deploy does not rotate existing secrets.
- **ChatGPT OAuth:** built-in single-owner passkey login, public-client DCR for
  exact ChatGPT callbacks, rotating refresh tokens, browser consent, and one-URL
  MCP setup. RFC 8628 polling errors parse correctly without an access token.
- **Cloud cost guardrails:** pre-D1 auth/MCP rate-limit bindings keyed only by
  hashed credentials (IP fallback for unauthenticated bootstrap), plus documented
  Workers/D1/DO limits. Authorization remains OAuth + device policy.
- **Transfer:** public authenticated CLI plan/send/status/list/cancel and the E9
  two-Agent encrypted resume/cancel artifact path are implemented and evidenced.
- **Privileged boundary:** networkless native broker lifecycle is implemented on
  Linux, macOS, and Windows; Linux has a root receipt. macOS/Windows native
  release receipts and the full public-route E8 acceptance remain open evidence.

- **E5 process tree:** live PTY terminate kills the OS process tree (Windows
  `taskkill /T`, Unix session/`pkill -s` + process-group) so background
  descendants of interactive shells cannot survive `session.terminate`.
- **E5 resize:** `session.resize` fails closed before sequence reserve when no
  live PTY host exists (daemon recovery / non-PTY kind) — no phantom success.
- **E5 replay:** live-ring drain reports remaining bytes; multi-page drain loops
  under budget; `session.replay` surfaces `live_pending_bytes` and forces
  `truncated`/`next_seq` when unread live output remains.
- **Bounds:** executable pin/revalidation, idempotency journal open, git diff
  spool load, and agent transport state all ceiling **before** allocation.
- **E7:** bounded single-file unified-diff apply (`patch_format=unified` or
  hash-checked unified body) on `fs.patch` / `ops.fs.write`.
- **E6:** device `profile.list`/`show`/`scan` IPC + MCP `ownmesh_list_profiles`
  with `device_id` runs real PATH detection; `session.open` with `profile_id`
  builds an official launch plan and owns a live PTY fallback. CLI profile
  surfaces remain explicit unsupported.
- Aggregate E2–E9 acceptance remains fail-closed only on the independent E8
  public-route evidence; E4–E7 and E9 have real-path receipts.

## v1.2.0-beta.11 — handle-held dir list, PTY at-most-once, workspace CRUD

- **E4 custody:** restricted `list_dir` holds the validated directory handle and
  enumerates through handle-rooted APIs (Windows `GetFileInformationByHandleEx`,
  Linux `/proc/self/fd`, other Unix `fdopendir`). Rename-to-outside-symlink/junction
  races fail closed and never return outside entries.
- **E5 exact-once:** `session.write` / `session.resize` treat `RetryPending` as
  **at-most-once** — never re-deliver PTY input/resize; surface an explicit
  uncertain/conflict outcome for reconciliation.
- **E4 workspace CRUD:** device-local `ops.workspace.{list,show,add,update,remove}`
  IPC, CLI `ownmesh workspace …`, and public MCP tools
  `ownmesh_workspace_*` route through Agent → ownmeshd. `ws_default` cannot be
  removed or relocated.
- Gate remains intentionally red until E6–E9 production rows are complete.


## v1.2.0-beta.10 — session policy authority + PTY exact-once + dir spool bind

- E3: MCP per-tool argument allowlist strips hidden session `command`/`cwd` and client authority keys before hash/route
- E3/E5: `session.open` denied under `workspace_only`/`recommended` (same confinement posture as `command.run`); public MCP regression under recommended creates no external marker
- E5: controller `input_seq`/`resize_seq` reserve payload digest **before** PTY mutation; durable exact-once receipt; stale/gap/conflict never reach the process
- E4: directory v2 spool cursors bound to root/recursive request identity; aggregate name/path byte budget checked before append
- Gate remains RED (exit 2): E4/E5/E7 partial; E6/E8/E9 open; CLI workspace/profile/transfer/broker install still unsupported

## v1.2.0-beta.9 — E3 principal bind + E4 session workspace + E5 ordered input

- E3: ownmeshd derives runtime principal from verified `bound_action` (`client:remote:<tenant>:<principal>`); local idempotency journal namespaced per principal
- E3/E5: minimal `tenant_members` table + `canOperateDevice` so same-tenant members can operate devices; `session.give` normalizes bare principal ids into the remote runtime namespace; public two-principal handoff proof
- E4: `ownmesh_session_list` requires `workspace_id`; list/show filter/reject cross-workspace session metadata
- E5: MCP `input_seq` / `resize_seq` required on write/resize; ownmeshd persists last-applied and rejects gaps/stale through the real workerd path
- Gate remains RED (exit 2): E4/E5/E7 partial; E6/E8/E9 open; CLI workspace/profile/transfer/broker install still unsupported

## v1.2.0-beta.8 — E5 live PTY + E3 crash outbox + large dir spool + session lifecycle

- E3: Agent transport durable pending dispatch outbox; crash/reconnect resumes or emits terminal `OWNMESH_E_DISPATCH_LOST` (no stranded seen-without-completion); capacity rejects without live eviction
- E2/E4: directory listings >25k spill to private durable spool with integrity hash + `v2:` cursors so Full Access can retrieve every entry in chunks
- E5: live PTY host in ownmeshd; public MCP session list/show/claim/release/give/terminate; `workspace_id` required on close/claim/release/give/terminate
- E5: pipe fallback uses concurrent capped readers + timeout kill (no unbounded `Command::output`)
- E7: git diff spool TTL/count/byte quota cleanup on private state dir
- Restricted write parents component-wise with held directory handle across temp+rename (Linux `renameat`)
- Release notes document 32 explicit unsupported CLI surfaces / 39 total via `release/SUPPORTED_SURFACES.json`
- Gate remains RED (exit 2): E4/E5/E7 partial; E6/E8/E9 open; CLI workspace/profile/transfer/broker install still unsupported

## v1.2.0-beta.7 — E4 workspace selection + custody hardlinks + E2 surface proof

- Directory `list_dir_page` is cursor-resumable: after-cursor collection + sort + page; >4_000-entry regression asserts every name once (no silent drop after former 4k scan window)
- Restricted custody rejects multi-link hardlinks and cross-volume mounts after handle final-path revalidation (Unix nlink/dev + Windows links/volume serial)
- Device-local `workspaces.json` registry (`ws_default` + additional `ws_...` roots); MCP `workspace_id` selects the root at ownmeshd side-effect boundary
- E2 workerd proof extended: `ownmesh_fs_patch`, `ownmesh_command_shell`, workspace cross-denial, `ownmesh_session_open`
- Agent remote maps session.* and git.status/diff; MCP adds session write/resize/replay/close + git status/diff tools
- Git status/diff stream stdout/stderr with hard byte caps (no unbounded `Command::output`)
- Gate remains RED (exit 2): E4/E5/E7 partial; E6/E8/E9 open; CLI workspace/profile/transfer/broker install still unsupported

## v1.2.0-beta.6 — E2/E3 durable bounds + fail-closed E2–E9 gate

- Pending dispatch outbox is never wiped by client-data truncation; separate 900 KiB outbox ceiling; oversized claims fail closed before side effects
- Durable result bounding preserves `next_offset` / `sha256` / `exit_code` / list cursors and short previews
- Per-hop read (160 KiB) and command output (200 KiB) budgets aligned with durable store + Agent envelope; 512 KiB+ files page via offset
- Directory list UTF-8 page-byte budget (~200 KiB) keeps stable `(name,path)` cursors
- Cancel uses durable target-bound claim+outbox (`cancel:<op>`); `cancel_requested` only after confirmed route
- E2 workerd proof: multi-chunk 512 KiB binary read + list/stat/delete
- `test_v12_e2_e9_workerd_loopback.py` exits non-zero while E4–E9 rows remain open (no green incomplete gate)
- E4–E9 and E10 remain open

## v1.2.0-beta.5+ — E2/E3 dispatch integrity + bounded Agent completions

- Post-send DeviceRoom route timeout/throw is `dispatch_uncertain` (not terminal `failed`): MCP ops stay pending, dispatch outbox stays redeliverable, delayed Agent results can still CAS-finalize; DeviceRoom correlation dedup prevents double send
- Agent remote completion path: bounded mpsc completion queue (8) + in-flight semaphore (32); slow WSS consumers backpressure instead of unbounded RSS; `OWNMESH_E_AGENT_BACKPRESSURE` when saturated
- Durable MCP dispatch outbox: claim stores exact route body; retries redeliver when Worker dies after claim and before DeviceRoom inject; clients never see the outbox
- Idempotency tombstones are never evicted under quota pressure before the 30-day window; overflow fails closed
- Agent transport completed-reply aggregate byte budget + compact durable receipts; transport state file size cap
- ownmeshd op-journal entry/file/value budgets with fail-closed capacity (no unbounded `read_to_string`)
- Directory list cursors bind full `(name, path)` sort tuple so recursive duplicate basenames are not skipped
- Docs honesty: ChatGPT connection guide no longer implies cloud PTY sessions are production-ready (E5 open)
- Gate entrypoint: `scripts/tests/test_v12_e2_e9_workerd_loopback.py` (runs real E2/E3 binary×workerd proof)
- E4–E9 remain open (workspace CRUD/TOCTOU, cloud PTY, profiles, patch/Git, broker, transfer)

## v1.2.0-beta.4 — E3 action binding + bounded I/O (integrity hardening)

- Server-computed `payload_hash` binds action facts + operation_id + expires_at + claim_version + OAuth client
- Atomic `claimMcpOperationByIdempotency` + partial unique D1 index (one owner per idempotency key)
- Concurrent same-key differing actions fail closed; identical actions replay without re-route
- DeviceRoom stamps control-plane `expires_at` onto the operation.request envelope; agents reject expiry
- Server-side clamp of timeout/output/list/read budgets at MCP and ownmeshd/exec
- Cancel kills process trees (Unix process group / Windows taskkill /T); exclusive randomized write temps
- E2 workerd loopback: byte-identical idempotent replay + separate mismatch assertion
- Honest docs: E4–E9 and E10 remain open

## v1.2.0-beta.3 — E2 remote routing candidate

- Wire public Streamable HTTP `/mcp` through DeviceRoom to the real ownmeshd Agent and shared policy-gated `DaemonRuntime`.
- Emit `ownmesh.operation/1.0` requests with matching `correlation_id`/`operation_id`, `expires_at`, capability, idempotency key, and nested arguments; strip client-supplied authorization fields.
- Advertise `remote_routing_enabled: true` with filesystem/command/cancel capabilities; DeviceRoom only injects to routing-ready Agents.
- Execute direct fs list/stat/read-range/write/delete and structured/raw command paths with bounded read windows (`offset`/`max_bytes`, encoding, SHA-256, visible truncation).
- Persist Agent terminal replies before send; runtime idempotency journals prevent completed side-effect reruns across process restart.
- ChatGPT-primary action model: authenticated MCP invocation is the requested action; no invented ChatGPT confirmation attestation; optional local approval only when device policy asks.
- Real binary × local Wrangler/workerd proof: `scripts/tests/test_e2_workerd_loopback.py`.
- Routing notes: [`docs/V1.2_E2_REMOTE_ROUTING.md`](./docs/V1.2_E2_REMOTE_ROUTING.md).
- Does not promote CLI `exec --device`, cloud PTY, profiles, broker mint, transfer, or live-account E10 surfaces.

## v1.2.0-beta.2 — E1 Agent transport candidate

- Connect enrolled `ownmeshd` instances to the active control plane at `/agent/connect` over `wss://` (or loopback-only `ws://`) using the existing issuer/device-bound credential.
- Complete hello/challenge/Ed25519 proof/accepted/ready authentication without logging or persisting plaintext credentials outside the existing secret store.
- Persist outbound/inbound sequence state before side effects, reconnect with bounded backoff, advertise resume state, and deduplicate message IDs and operation correlations across reconnects.
- Keep pre-E2 remote routing fail-closed until the runtime handle is wired.
- A real local WebSocket test covers two authenticated connections, resume, and fresh-sequence cached-result replay. A real debug `ownmeshd` binary additionally authenticates twice against local Wrangler/workerd with temporary D1 state and an isolated native keychain namespace, proving process-restart resume.
- Enable the native `keyring` 3.x backends explicitly so production credentials persist in Windows Credential Manager, macOS Keychain, or Unix Secret Service instead of the crate's process-local mock. Live-account E2E remains open, so no supported surface is promoted.
- Transport notes: [`docs/V1.2_E1_AGENT_TRANSPORT.md`](./docs/V1.2_E1_AGENT_TRANSPORT.md).

## v1.2.0-beta.1 — E0 operation contract freeze

- Add the independent `ownmesh.operation/1.0` request/progress/event/result payload contract while retaining the `ownmesh.device/1.0` outer envelope.
- Require operation/correlation binding, request expiry and idempotency, exact payload fields, safe cross-runtime sequence integers, and fail-closed terminal result shapes.
- Add Rust/TypeScript typed parsers, a JSON Schema, and four shared golden fixtures with cross-language round-trip coverage.
- Reserve `workspace_id` for E4 without promoting workspace or remote-execution surfaces; the existing 39 hard-error unsupported surfaces remain unchanged.
- Contract notes: [`docs/V1.2_E0_OPERATION_CONTRACT.md`](./docs/V1.2_E0_OPERATION_CONTRACT.md).

## v1.1.3 — deterministic release gate

- Carry forward the v1.1.2 portable-installer repair without changing its security or compatibility scope.
- Make the Unix Docker-provider mock executable deterministic on hosted Linux filesystems by closing and syncing a staged script before atomically renaming it into place; this prevents the release gate from failing with transient `ETXTBSY` while preserving the same test assertions.
- Make the daemon restart regression wait for stopped connection tasks to release their fixed credential-registry lock, with a bounded timeout instead of an arbitrary sleep.
- Retain the immutable `v1.1.2` tag as a historical failed release candidate. Its fail-closed tag workflow published no GitHub Release or assets.
- Release notes: [`docs/RELEASE_NOTES_v1.1.3.md`](./docs/RELEASE_NOTES_v1.1.3.md).

## v1.1.2 — Unix installer repair

- Repair `ownmesh-installer.sh` so the declared `#!/bin/sh` path parses and runs under POSIX shells such as Ubuntu `dash`; add an unconditional `sh -n` regression that does not skip when Minisign is absent.
- Preserve fail-closed environment validation without Bash-only `$'...'` quoting, including CR/LF and shell-metacharacter rejection.
- Enroll the real pinned Minisign 0.11 Linux x64 archive digest and select the exact x86_64 binary from the multi-architecture bootstrap archive.
- Refuse pre-existing symlink, reparse-point, directory, or other non-file binary targets in both portable installers; validate final targets and remove newly written files during rollback so a failed update cannot leave a partial new binary set.
- Restore Windows backups with atomic same-volume replacement plus digest verification, clean private transaction files after success or safe failure, and retain backups only when rollback itself fails.
- Make signed Unix installer coverage a required Ubuntu release gate by provisioning a SHA-256-pinned Minisign 0.11 binary; missing signer/key generation is now a hard test failure instead of a skip.
- v1.1.1 remains immutable for auditability, with a release warning on its unusable Unix installer. Signed archives and the Windows installer were independently reverified before this patch train.
- Release notes: [`docs/RELEASE_NOTES_v1.1.2.md`](./docs/RELEASE_NOTES_v1.1.2.md).

## v1.1.1 — CI and security repair

- **ownmesh-config:** transaction lock `OpenOptions` now sets explicit `truncate(false)` with `create(true)` (crash-safe lock semantics; fixes `clippy::suspicious_open_options` under `-D warnings`).
- **ownmesh-ipc (Windows):** registry state custody pins and attests the directory handle before mutation, accepts only `TokenUser` or the same process token's stable `TokenOwner`, repairs that elevated-token owner case through the same handle, rejects every unrelated owner, and revalidates after acquiring the pinned registry lock namespace anchor; identity remains file-index based across genuine path aliases. CI explicitly enforces foreign-owner, reparse, and replacement regressions without relaxing owner-only DACL / non-regular checks.
- **control-plane OAuth:** consent expiry is captured at Worker GET receipt, before asynchronous form parsing/authentication; a delayed-auth-provider regression proves the five-minute lifetime cannot be extended by route work.
- **ownmesh-logs / ownmesh-broker (Linux/macOS Clippy):** cfg-gate Windows-only imports and helpers; drop useless `uid_t`/`gid_t`→`u32` conversions; fix underscore-prefixed binding use; remove redundant `String::to_string` map_err; keep macOS LaunchDaemon allowed-uid emission distinct from Windows/Linux CLI flag fold (with unit coverage).
- **control-plane devDependency:** upgrade `wrangler` 3.x → 4.x (and matching `@cloudflare/workers-types` 5.x) so `pnpm audit --audit-level=high` is clean of miniflare-transitives `undici` / `ws` / `sharp` highs; no audit ignores or threshold changes.
- Release notes: [`docs/RELEASE_NOTES_v1.1.1.md`](./docs/RELEASE_NOTES_v1.1.1.md).
- No Dependabot merges; `v1.1.0` tag left immutable.

## v1.1.0 — 2026-08-07

### Secure distribution

- Multi-arch portable archives: Windows x64, macOS arm64/x64, Linux musl arm64/x64.
- Required minisign signing of `SHA256SUMS` with immediate verify; no degraded unsigned formal release.
- Installers for macOS/Linux (`ownmesh-installer.sh`) and Windows (`ownmesh-installer.ps1`) **require** minisign verification of `SHA256SUMS.minisig` against the pinned trust root before trusting checksums (no SHA-only fallback; no `curl|sh` / `irm|iex`).
- Installers enforce the updater archive contract **before** extraction (entry/size caps, exact allow-list, no full `tar -xzf` / `Expand-Archive`); member-by-member staging + atomic install/rollback; fail closed when safe listing/extract is unavailable.
- Homebrew formula template + `scripts/render_distribution.py` checksum injection.
- Release assets include installers, `ownmesh.rb`, `ownmesh-release-meta.json`, SBOMs, provenance.

### Self-update

- Production `ownmesh update check|download|apply|channel` against official GitHub Releases.
- Embedded minisign trust root; verify order signature → checksums → archive.
- Fail-closed host allow-list, size/time/entry/uncompressed limits, downgrade refusal, protocol compatibility.
- Archive extraction permits only required binaries + declared docs; rejects bombs, duplicates, symlinks, traversal.
- Atomic multi-binary apply with backup/rollback; Homebrew self-update refused.

### Onboarding / local trust boundary

- `setup` config+policy journaled transaction under exclusive lock with durable recovery (no new-config + old-strong-policy window).
- Mandatory fail-closed recovery on every production config/policy load path (daemon start, CLI); recovery failure preserves journal and refuses operation; concurrent setup serialized.
- Strict control-plane `url::Url` validation (https / loopback-http only; reject userinfo/query/fragment); redacted errors.
- `doctor` never loads OS credentials; presence from non-secret metadata only.
- Human-operator IPC (`approval.approve|deny`, `policy.preset`, `daemon.unlock`, `token.revoke`) fail-closed until a distinct OS/UI presence proof exists (same-UID unauthenticated IPC is not human presence).

### Versioning

- Workspace / packages / control-plane service version aligned to **1.1.0**.

## v1.0.2

See [`docs/RELEASE_NOTES_v1.0.2.md`](./docs/RELEASE_NOTES_v1.0.2.md).
