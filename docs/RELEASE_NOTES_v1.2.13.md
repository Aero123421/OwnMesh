# OwnMesh v1.2.13

OwnMesh v1.2.13 is a patch release focused on runtime reliability and
cross-platform repair. It preserves the v1.2 product surface, the OAuth/passkey
model, the MCP protocol, policy fail-closed guarantees, and the Control Plane
storage schema. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- **One expired sidecar transition journal record no longer poisons every
  future session.** `recover_sidecar_transitions()` previously aborted on *any*
  record whose host TTL had passed, bricking every `session.open`/claim/give/
  renew/detach on the device. Expired records are now reconciled
  non-blockingly: they are cleared only when authoritative session state proves
  them harmless (the session is `Closed` or gone, and the host TTL is provably
  past), and retained fail-closed with a health surface otherwise. A stale row
  can no longer block unrelated sessions, and ambiguity is never converted into
  success. Journal validation now requires every record's expiry to cover the
  host TTL of every binding it references, so a crash-interleaved or
  inconsistent record can never be cleared as "expired" while its host may
  still be alive; a `Closed` session whose `sidecar_host` still references a
  live host from the record is retained fail-closed. Journal validation also
  enforces the cross-field invariant that `target.terminal` agrees with the
  transition `kind` (only `close`/`terminate` are terminal): a structurally
  valid record whose kind and terminal flag disagree would be replayed one way
  and receipted another, so both shapes are rejected fail-closed by the daemon
  loader and by the shared validator `ownmesh doctor` uses. Retained-transition
  health is refreshed from the journal after each reconcile pass, so a record
  that is later provably resolved stops being reported as unresolved. While a
  record is unresolved, the *affected* session is fenced against
  controller-mutating operations (see below) so the ambiguous intent cannot be
  overwritten by a different controller change. Journal writes are
  rollback-safe: `begin`/`mark_applied`/`mark_terminal_applied` validate the
  would-be state before mutating memory and roll the in-memory entry back on
  any persist failure, so a pre-commit failure can never leave a non-durable
  intent behind for supervisor bootstrap recovery to execute. An expired
  record is now cleared only when the referenced sidecar is *provably dead*:
  the daemon asks the OS for the attested child process (`child_pid` +
  `child_process_birth`) and, for provisional bindings, probes the session
  supervisor (`session_supervisor.host_live`). Both the predecessor binding and
  an applied successor binding are checked; proving only the predecessor dead
  can never clear a record while the successor remains live. Expiry plus
  session state alone is never treated as proof of termination, and the
  supervisor's expiry sweep no longer untracks a host whose termination failed
  — it retains and retries it, so an orphaned sidecar cannot silently survive
  after its journal record was cleared. A record whose proof is indeterminate
  stays retained fail-closed and is surfaced in health.

  Two crash-window gaps found in review are closed in this release:

  - **The supervisor never reports an in-flight kill as death.** The expiry
    sweep now keeps an expired host visible to liveness probes for the whole
    termination attempt (an explicit in-flight state): a concurrent
    `session_supervisor.host_live` probe can no longer observe "not tracked"
    while the sidecar is still alive, and a host whose child does not confirm
    exit within the bounded poll window is *not* untracked — the sweep keeps
    it and retries. `terminate_child_tree` fails honestly instead of claiming
    success over a still-running child.
  - **Recovery restores the full controller mutation, not only the binding.**
    A crash between the supervisor mutation / `Applied` journal write and the
    `SessionManager` commit leaves the durable controller unchanged while the
    sidecar already belongs to the successor; recovery now applies the
    recorded seat verbatim (principal, exact lease id, controller epoch and
    expiry, attached state) before clearing the record, so the former
    controller can never keep `session.write` access through the successor's
    sidecar. Recovery also never regresses a durable controller generation
    that is already newer than the journal record (defense in depth). The
    journal records the exact `lease_id` on every target so remote write
    authorization (lease id + epoch) keeps working after restart.
- **The operation idempotency journal no longer grows toward its hard cap.**
  Completed entries are compacted to exact-once durable receipts before
  persistence, and the in-memory map is compacted to the same receipt once it
  is durably committed — large stdout/file bodies exist only in the immediate
  response and are never retained indefinitely in durable state or memory. The
  op journal now persists with a dedicated no-backup atomic writer: the shared
  writer's `op-journal.json.bak` (a pre-replace copy that could hold the
  pre-compaction large-body journal after a crash) is no longer created at
  all, and any stale backup left by an older version is removed *before*
  the compacted write — a crash between the write and the cleanup cannot
  leave the legacy large-body copy behind — with the removal retried on
  every persist for transient locks and **fail-closed at load and at runtime
  persistence**: a stale backup that cannot be removed (locked/ACL-protected)
  refuses startup, or rejects the current journal commit while restoring its
  in-memory pre-commit marker, with an actionable message instead of running
  while the pre-compaction body copy remains on disk; `ownmesh doctor` reports
  any lingering backup instead of healthy. Terminal
  receipts have an explicit bounded lifecycle: at capacity only completed
  entries older than 30 days are evicted, and the replay path enforces the
  same window — a completed receipt older than 30 days is no longer replayed
  (the Control Plane has already compacted the result to a correlation
  tombstone and a retry is dispatched as a new operation), so a long-lived
  daemon cannot silently replace a fresh operation with a stale receipt.
  Near-capacity eviction is proactive: the byte-pressure projection includes
  the incoming in-progress marker, so a journal that is still under the
  durable budget — but within one marker's worth of the 4 MiB cap — evicts
  expired completed receipts *before* inserting the marker instead of
  refusing the new side-effect key with a byte-budget persist failure while
  eligible receipts sat unused (v1.2.13 review).
  (The device and Control Plane retention windows are deliberately **not
  identical**: the device expires completed receipts 30 days after
  completion, while the Control Plane retains the full result for 7 days
  (`MCP_OPS_RESULT_TTL_MS`) and then keeps the idempotency key as a
  tombstone for another 30 days (`MCP_OPS_TOMBSTONE_TTL_MS`, hard-delete 30
  days after tombstoning) — the Control Plane key therefore always outlives
  the device receipt window, so the device never replays a receipt the
  Control Plane has already forgotten, and a retry after the device window
  is a fresh operation on both sides. See ADR 0010.) In-progress/uncertain markers are never
  compacted or evicted, regardless of age; at capacity with nothing evictable,
  new side-effect operations are still refused fail-closed. Unknown/forward-
  version journal states are treated as uncertain, never as completed
  receipts — including a present-but-malformed state value such as `null`, a
  number, or a boolean, and a top-level entry that is not a JSON object at
  all, which the old classifier could mistake for a completed receipt.
  Completion is now an *explicit* positive marker: only `durable_receipt:
  true`, the explicit `__ownmesh_operation_state == "completed"` value, or a
  legacy (pre-1.2.13) completed body with positive completion proof
  (`operation_id` plus `decision`/`approval_required`/`review_id`) counts as
  completed — a truncated or hand-written `{}` is uncertain, never compacted,
  never evicted, and never replayed as completed. Every completed entry must
  also carry the exact-once `operation_id` (ADR 0010 §1b): a
  `durable_receipt: true` marker or an explicit `"completed"` value *without*
  one is malformed (hand-written or truncated) and stays uncertain —
  compacting or eventually evicting it could let a retried operation execute
  as a new side effect. Compact receipts preserve
  the small identifiers a client needs to continue an operation whose
  response was lost after compaction/restart: `review_id`/`workspace_id` for
  `review.start`, and the generated session `id`, controller lease, and
  `controller_epoch` for `session.open` (the nested `session` snapshot is
  kept for `session.attach`/`session.claim`), so an idempotent replay after
  compaction or restart can still continue the session or review. The
  receipt keeps the *original field names* — a top-level `id` stays `id`
  (never renamed to `session_id`, which would also mislabel non-session ids
  such as `workspace.add`'s `ws_...`), and `session.open` additionally
  writes an additive `session_id` alias — so the first and the replayed
  public responses are schema-stable. Legacy
  journals from v1.2.12 still shrink at load: entries that are provably
  completed migrate to compact receipts; everything else stays fail-closed.
  The load-time compaction is durably fail-closed: if the compacted journal
  cannot be persisted, the daemon refuses to start with an actionable message
  instead of running with a compacted in-memory view while the large bodies
  remain on disk, and the byte-budget check validates the pretty-serialized
  size the durable writer actually emits (a compact-serialized check could
  pass while the pretty file exceeds the cap).
  See
  [`docs/adr/0010-bounded-op-journal-retention.md`](../docs/adr/0010-bounded-op-journal-retention.md).
- **`review.start` receipts are now exactly-once replayable.** A completed
  review's op-journal entry is the serialized `ReviewManifest`, which stores
  the control-plane id as `remote_operation_id` — not the `operation_id`
  exact-once marker the compaction classifier requires. The handler now
  stamps `operation_id` onto the stored body, so a finished review is
  classified as a completed receipt: it compacts to a bounded receipt
  (pinned argv/test pins are dropped; `review_id`, `workspace_id`, and
  `remote_payload_hash` are preserved) and a retried `review.start` after
  restart or response loss returns the receipt — with the `review_id` needed
  to continue through `review.show`/`review.page` — instead of an
  in-progress/uncertain conflict. Before this fix the finished review stayed
  classified uncertain and its full manifest (including pins) was retained
  durably. Compact receipts also retain the terminal `phase` and derive the
  matching `status`, so failed and cancelled reviews never replay as
  completed. Receipt lookup and payload-hash verification happen before
  workspace/profile/executable preflight: a valid completed retry still
  replays if those local dependencies have since disappeared, while a new
  operation continues to fail preflight before reserving its key.
- **`session.open` is exact-once on the device.** The MCP contract already
  required a caller idempotency key for `session.open`; the handler now
  honors it through the device idempotency journal. When a key is present
  (the Agent/MCP transport always injects the signed operation key), the
  durable marker is reserved before the session record is created and a
  completed open stores a compact receipt that keeps the generated session
  id and controller lease. A retried open — after response loss, daemon
  restart, or reconnect — replays the original session instead of spawning a
  duplicate PTY or persistent sidecar; the replay window is the same 30-day
  completed-receipt lifecycle as every other side-effect operation, and
  in-progress/uncertain outcomes are never pruned. The first and the replayed
  responses are schema-stable: both carry the generated `id` and the
  additive `session_id` alias, so the control plane and MCP clients can
  continue the session identically after a replay. Local IPC callers that
  send no key are unchanged (no journal entry). Receipt lookup happens before
  workspace/profile preflight, so an already completed retry is not blocked by
  later local configuration drift; a new open still validates before it
  reserves the durable marker.
- **Remote controller mutations are exactly-once on the device.** Remote
  `session.claim`, `session.renew`, `session.detach`, `session.give`,
  `session.close`, and single-session `session.terminate` now reserve the
  signed operation key before their external side effect and persist a compact
  replay receipt after the session/supervisor commit. A response-loss retry
  replays the first result (including the top-level controller lease where
  applicable) instead of rotating a lease/nonce or repeating a terminal
  transition. An in-progress or uncertain key remains fail-closed.
- **Windows executable resolution follows PATHEXT semantics.** `command.run`,
  profile detection, review execution, and session launch now resolve
  `pi`/`opencode` (extensionless npm shims) to the invocable `.exe/.com/.cmd/
  .bat` sibling before the extensionless POSIX shim, eliminating Win32 error
  193 — including for explicit relative paths such as `./pi` or `pi\\`, which
  previously bypassed PATHEXT ordering. A genuine extensionless native binary
  is still found when no invocable sibling exists. Generic PTY sessions run
  `.cmd`/`.bat` shims through the documented `cmd.exe /e:ON /v:OFF /d /s /c
  call <script> <args>` form with each argv token preserved; arguments that
  cmd.exe would reinterpret (quotes, `%`/`!`, control characters, or unquoted
  metacharacters) fail closed with an actionable error instead of producing a
  different command line. Generic `command.run` retains the resolved
  invocation path while separately pinning its canonical backing executable,
  preserving proxy semantics such as rustup's `cargo` dispatch without
  weakening executable-identity revalidation. Unix behavior is unchanged.
- **Windows batch shims no longer bypass the raw-shell policy boundary.** A
  `.cmd`/`.bat` file is shell content — `cmd.exe` interprets its file body
  with full shell semantics even when the argv is passed literally — so
  classification now treats it as `raw_shell` on every platform (the same as
  a `.sh` script on Unix). A policy denying `raw_shell` therefore denies
  `.cmd`/`.bat` execution; `command.run` reclassifies and the pin/approval
  revalidation rejects a structured pin that resolves to a batch script
  (fail-closed, never converted to success). The `cmd.exe` wrapper used by
  sessions and raw-authorized runs is pinned to the absolute
  `%SystemRoot%\System32\cmd.exe` so Windows process resolution can never
  search the current directory for a shadowing interpreter.
- **Default PTY shells resolve fail-closed.** `default_shell_command()` never
  hands a bare or unresolvable program to a spawner: the shared launchable
  resolver runs first, and on failure the platform's absolute default shell
  (`/bin/sh` on Unix, `%SystemRoot%\System32\cmd.exe` on Windows) is used
  instead of the caller-supplied name — a bare `cmd.exe` would let
  `CreateProcess` search the working directory for a shadowing `cmd.exe`/
  `cmd.com` (Microsoft CreateProcess documentation), and a bare Unix
  `$SHELL` would be re-searched by a spawner PATH that may disagree with
  the resolver profile detection and command execution use. As defense in
  depth the live PTY spawner (`LiveHost`) also resolves through the same
  resolver and fails closed with the exact reason, matching `spawn_pty` and
  structured session launch (v1.2.13 review).
- **macOS PTY children terminate reliably without blocking teardown.** The Unix PTY
  backend is updated to `portable-pty` 0.9, which clears inherited signal masks
  in the child before `exec`. Windows remains on 0.8.1 because 0.9 enables
  `PSEUDOCONSOLE_INHERIT_CURSOR`; its `ESC[6n` cursor-position handshake blocks
  unattended ConPTY commands before their output. The existing Windows
  no-emulator echo test pins that behavior. The Unix update prevents macOS shells from
  surviving a termination attempt. During concurrent PTY teardown, Darwin can
  continue returning an indeterminate non-blocking child state after the PID
  has disappeared. OwnMesh now snapshots the Darwin process table by PTY
  controlling TTY, PTY session, and ancestry. Before killing any descendant it
  freezes the dedicated PTY, so terminating a leaf process cannot wake a
  waiting parent shell and let that shell run its next command during teardown.
  It directly kills every captured descendant before signalling the PTY leader,
  then kills the frozen TTY remainder and repeats the snapshot after the leader
  signal to close the spawn race. The controlling-TTY selector
  catches background jobs that have changed parent or process group, while the
  numeric session snapshot avoids relying on Apple's `pkill`, which does not
  implement the `-s sid` selector. OwnMesh also confirms both the child handle
  and exact PID presence in Darwin's process table. An absent PID
  confirms exit; a `Z` state confirms the process has
  already exited and permits an immediate authoritative reap. Darwin's `E`
  flag (`P_WEXIT`) confirms that the process is already committed to kernel
  exit, so OwnMesh accepts it without a synchronous `wait()` that could block
  during kernel teardown; every ordinary live state remains unconfirmed. The
  confirmation window remains bounded (five seconds on macOS; one second
  elsewhere), and observation errors fail closed: an unconfirmed child remains
  tracked and is retried instead of being reported dead; no terminate or Drop
  path waits indefinitely on a live or kernel-exiting process.
- **The Linux service finds user-installed developer CLIs.** The systemd user
  service inherits a system-only `PATH`, so `~/.local/bin`, Cargo, Nix,
  npm-global, and NVM node-version bins are now searched deterministically
  (shell-free, shared by detection and launch so there is no
  detect-ready-then-spawn-bare-name gap). Profile discovery and process
  resolution use the exact same resolver; a profile that is not installed
  returns a typed, actionable error instead of spawning an unverified bare
  name. The same resolver now backs every spawn path on every platform:
  structured `command.run` rejects an unresolvable program fail-closed
  before authorization (a shell binary is still denied as raw_shell by
  policy, never admitted as structured), the Unix spawn path resolves argv
  through the shared resolver instead of handing a bare name to the
  spawner, and session launch (PTY and structured) resolves its program the
  same way — so detection, command execution, review pinning and session
  launch can never disagree about which executable is invocable.
- **The shipped systemd --user unit keeps process-level confinement and
  byte-for-byte custody validation; ProtectSystem-style mount-namespace
  confinement is impossible in a --user service without breaking custody.**
  This is a **scoped** reconciliation, not a complete OS-level sandbox: the
  shipped unit provides process-level and proc-visibility confinement only,
  and deliberately provides **no** filesystem confinement
  (`ProtectSystem=`/`ProtectHome=`/`ReadWritePaths=`/`PrivateTmp=` — there
  is no systemd workspace allow-list; filesystem governance is the daemon's
  own custody validation plus the registered-workspace model; see Known
  limitations and ADR 0011).
  The v1.2.12 unit's `ProtectSystem=`/`ProtectHome=`/`ReadWritePaths=`/
  `PrivateTmp=` in a per-user service implicitly enable `PrivateUsers=true`
  (systemd.exec(5), systemd NEWS v254; verified against
  `exec_needs_cap_sys_admin()` in systemd's src/core/execute.c), which maps
  host-root-owned ancestors
  (`/`, `/home`) to overflow uid 65534 and broke OwnMesh custody validation
  (`credential state ancestor is owned by untrusted uid 65534: /home`). The
  v1.2.13 review found that accepting the overflow uid is unsound: inside a
  user namespace it is the only visible representation of *every* host uid
  outside the mapping — host root and every other host user alike — so a
  foreign-owned `01777`/`0755` ancestor (reachable via path overrides)
  would pass and its owner could replace the daemon's state directory (A5
  cross-user boundary). The v1.2.13 unit therefore does **not** force a
  user namespace: it ships the process-level guards `NoNewPrivileges=true`,
  `UMask=0077`, `RestrictSUIDSGID=true`, `RestrictRealtime=true`,
  `LockPersonality=true`, `SystemCallArchitectures=native`,
  `RestrictNamespaces=yes`, plus `ProtectProc=invisible` (verified to boot
  on systemd v259; systemd.exec(5) documents it as system-only, so on
  versions where a per-user service cannot apply it it degrades to a no-op,
  never a boot failure). Custody validation accepts only the daemon's own
  uid and host root as ancestor owners; the overflow uid is never accepted
  (see
  [`docs/adr/0011-systemd-user-sandbox-custody-reconciliation.md`](../docs/adr/0011-systemd-user-sandbox-custody-reconciliation.md)).
  Verified on systemd v259: the daemon boots (config, device identity,
  credential registry, IPC socket), PTY sessions spawn, and Node/V8
  runtimes work. The shipped unit is deliberately **process-level and
  proc-visibility** confinement, not `ProtectSystem=`-style mount-namespace
  confinement: every filesystem namespacing directive (`ProtectSystem=`,
  `ProtectHome=`, `ReadWritePaths=`, `ReadOnlyPaths=`, `InaccessiblePaths=`,
  `PrivateTmp=`, `PrivateDevices=`, `BindPaths=`, `TemporaryFileSystem=`, …)
  forces `PrivateUsers=yes` in a per-user service (systemd NEWS v254;
  `exec_needs_cap_sys_admin()` in systemd's src/core/execute.c), and inside
  that namespace the overflow uid 65534 is the only visible representation
  of every host uid outside the mapping — host root and attacker alike — so
  custody validation cannot verify real ownership. Filesystem governance
  for the daemon and its spawned sessions is therefore the daemon's own
  custody validation (every state/config ancestor must be owned by the
  daemon's uid or host root) plus the registered-workspace model, not an
  OS-level mount namespace; sessions run arbitrary user commands by design,
  so confining the daemon's filesystem would confine sessions and break the
  product. `CapabilityBoundingSet=`,
  `ProtectClock=`, `ProtectKernelLogs=`, and `ProtectKernelModules=` are
  deliberately NOT emitted: on systemd v259 they fail --user service startup
  with exit status 218/CAPABILITIES even under `PrivateUsers=yes` (verified
  empirically; systemd.exec(5) documents that an unset
  `CapabilityBoundingSet=` leaves the bounding set unmodified — the login
  session's set is inherited unchanged). `ProtectHome=` is omitted because a
  read-only home conflicts with the registered-workspace model, and
  `MemoryDenyWriteExecute=yes` is omitted because it breaks JIT runtimes
  (Node/V8) that spawned sessions rely on. The daemon also reconciles its
  effective sandbox at startup: `ownmeshd` reads `/proc/self/uid_map` on
  Linux and, when the effective unit has placed it inside a user namespace
  that hides real host uids (any map other than the full identity — exactly
  what `PrivateUsers=yes`/the filesystem directives produce), logs an
  actionable warning that custody cannot verify real ownership, will fail
  closed with `ancestor is owned by untrusted uid 65534`, and how to
  remediate (`ownmesh service install` after removing the directives); the
  check is diagnostic only, custody still enforces the boundary, and the
  shipped unit renders the registered-workspace reconciliation contract
  explicitly (never `ProtectHome=`/`ProtectSystem=`/`ReadWritePaths=`/
  `ReadOnlyPaths=`/`InaccessiblePaths=`, so dynamically registered
  workspaces under the user's home are never confined by the shipped unit;
  render-tested). `ownmesh doctor` discloses the
  *effective* hardening of the installed unit: it reads manager-effective
  properties via `systemctl --user show` when available and otherwise falls
  back to a section-validated parse of the unit file plus drop-ins across
  the full user-manager search path — including type-level `service.d` and
  dash-prefix drop-in directories, same-named replacement semantics (systemd
  issue #13198), and `/dev/null`/empty masks (a masked unit is disclosed,
  not reported as a baseline). The effective-baseline predicate evaluates
  every shipped guard (`NoNewPrivileges`, `UMask=0077`,
  `RestrictSUIDSGID`, `RestrictRealtime`, `LockPersonality`,
  `SystemCallArchitectures=native`, `RestrictNamespaces=yes`,
  `ProtectProc=invisible`) and requires that no user-namespace-forcing
  directive is present, so a drop-in that disables a guard or re-adds
  `PrivateUsers=yes`/`ProtectSystem=`/`ProtectHome=`/`ReadWritePaths=`/
  `PrivateTmp=`/`ProtectKernelTunables=`/`ProtectControlGroups=`/
  `ProtectHostname=` is surfaced as a warning with the custody consequence
  (the daemon fails to start with `ancestor is owned by untrusted uid
  65534`) instead of being reported as an unmodified baseline. The static
  fallback (used when `systemctl show` is unavailable) applies the same
  predicate: a present-but-weak `UMask=` (e.g. `0002`) is disclosed as
  weakened, never counted as the shipped `0077` baseline, and the modeled
  user-manager search path matches `systemd-analyze --user unit-paths`
  (systemd resolves the unset `$XDG_CONFIG_DIRS` default to `/etc`, not
  `/etc/xdg`, so a phantom `/etc/xdg/systemd/user` entry is not searched).
  Local
  overrides that disable a baseline guard or re-introduce a start-breaking
  directive (`CapabilityBoundingSet=`/`ProtectClock=`/`ProtectKernelLogs=`/
  `ProtectKernelModules=`) are surfaced as warnings (re-run `ownmesh
  service install`); the clean shipped unit is not reported as weakened.
- **Diagnostics no longer report `healthy` while real failures exist.**
  `system.diagnose` runs the expired-transition reconcile pass first so the
  observation reflects post-recovery state, and gains additive top-level
  `journals.transition`, `journals.op_journal`, and `profile_discovery`
  fields; a poisoned transition journal (including an expired pending record),
  dangerous (critical) op-journal pressure, uncertain op-journal entries
  (unknown/forward-version or malformed state the runtime refuses to replay,
  compact, or evict), or profile-discovery failure moves `overall` away from
  `healthy` with a `run_local_doctor` recommendation. Warn-level op-journal
  pressure (≥ 60% of a cap) is exposed in `journals.op_journal.status` but
  does not by itself flip `overall`; critical pressure and uncertain entries
  do. A durable `in_progress` marker is surfaced as a warning rather than a
  healthy pass (a genuinely active operation may produce that warning only
  briefly). The five check ids are unchanged (no schema version bump). `ownmesh
  doctor` adds read-only `journals.transition`, `journals.op_journal`,
  `profiles.discovery` (runs official profile discovery and compares the bare
  service PATH with the deterministic user-local search) and
  `service.hardening` checks. Doctor validates the transition journal with
  the *same typed validator as the daemon's loader* (shared crate): version,
  entry cap, map-key/record-id agreement, unknown-field rejection, invalid
  enums, identifier shape, epoch/expiry bounds, host-expiry coverage, binding
  invariants, and phase consistency — a journal the daemon would refuse to
  open is disclosed, not reported healthy. It counts uncertain op-journal
  entries (including unmarked `{}` objects) instead of reporting them as
  okay, and a missing `HOME` surfaces as a profile-discovery health issue
  instead of silently producing a healthy observation. The Control Plane
  normalizer treats a present-but-`null` diagnosis status as `malformed`
  (never `ok`), and a *present but incomplete* subtree (`{journals:{}}`,
  `{journals:{transition:{}}}`, `{profile_discovery:{}}`) is also `malformed`
  — only the whole subtree being absent is a legacy omission that stays `ok`
  — so device-side corruption is surfaced rather than normalized to healthy;
  free-form profile-discovery notes are redacted (credential assignments
  dropped, embedded secrets, space-delimited bearer credentials such as
  `Bearer sk-…`/`authorization eyJ…`, marker-plus-filler forms such as
  `token is <long-opaque-value>`/`api key was <value>`, and user-home paths
  — POSIX `/home/alice` and Windows `C:\Users\Alice` forms — replaced with
  `[REDACTED]`) before exposure or persistence, while benign prose that
  merely mentions a credential word survives.
- **Ambiguous sidecar transitions fence the affected session.** While a
  session has an unresolved transition-journal record, controller-mutating
  operations on that session (`session.attach` controller role,
  `session.claim`, `session.give`, `session.detach`, `session.renew`,
  `session.release`, an observer downgrade by the current controller,
  `session.close`, `session.terminate` (single and `all`), `session.write`,
  and `session.resize`) are refused fail-closed with an actionable
  `ownmesh doctor` hint — recovery still permits unrelated sessions, but the
  affected session's controller state, terminal state, and sidecar input
  cannot race the ambiguous intent. Clearing the record (via recovery or
  operator resolution) restores access.
- **Linux enrollment hostname fallback is poison-free.** The fallback chain
  (`COMPUTERNAME` → `HOSTNAME` → OS nodename → hostname files) is now a pure,
  unit-tested function: a bad value from one source (e.g. `unknown-host`,
  `localhost`) can no longer prevent the next source from being used.
- **Error reporting preserves the actionable cause.** Win32 error 193 spawn
  failures get a typed message naming the extensionless-shim cause and
  remediation (error code stays `INTERNAL`); profile launch failures name the
  missing binary and point at `ownmesh doctor`; retained expired transition
  records point at `ownmesh doctor` and the journal directory; unresolved or
  cmd-unsafe session argv fails closed with the exact reason before any
  spawner is reached.

## Compatibility and migration

- No D1 migration is required.
- **Documented replay-window note:** device-local completed operation receipts
  are retained for 30 days after completion. Within the window, replay
  returns a compact exact-once receipt — never a re-execution — and the full
  result body exists only in the immediate response. A completed receipt
  older than 30 days is expired (at capacity, and on the replay path itself),
  so a retried operation *after* the window is treated as a new operation.
  The Control Plane's idempotency-key lifecycle is **longer and staged**: it
  retains the full result for 7 days after completion
  (`MCP_OPS_RESULT_TTL_MS`), then compacts the row to a correlation
  tombstone and keeps that tombstone for another 30 days
  (`MCP_OPS_TOMBSTONE_TTL_MS`, hard-deleting it 30 days after tombstoning —
  roughly 37 days after completion). The hard-delete now runs *before* the
  existing-row lookup on the claim path, so a tombstone whose window has
  closed is never returned as `existing` indefinitely: a same-key retry
  after the window is minted as a fresh operation immediately instead of
  waiting for an unrelated operation to trigger quota cleanup (v1.2.13
  review). The two windows are therefore not the
  same, and this release does not claim they are; the safety property is that
  the Control Plane key always outlives the device receipt window, so the
  device never replays a receipt the Control Plane has already hard-deleted,
  and a retry after the device window is a fresh operation on both sides. No
  duplicate-side-effect path exists in either window combination. In-progress
  /uncertain outcomes are never pruned, regardless of age.
- **Op-journal backup recovery:** if `op-journal.json` is missing but a stale
  `op-journal.json.bak` survives (a crash in an older writer between its
  backup copy and the replace, or external removal of the primary), the
  daemon now recovers the last-known journal from the backup, persists the
  compacted form as the new primary, and removes the backup — starting empty
  would silently drop exact-once receipts and let a retried operation
  re-execute. A corrupt/over-budget backup refuses startup with an actionable
  message instead of being ignored, and a backup that survives the promotion
  but cannot be removed also refuses startup (fail-closed) rather than
  leaving the pre-compaction journal on disk; the runtime cleanup is retried
  on every persist so a transient file lock cannot retain the pre-compaction
  journal indefinitely.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- Operators should redeploy the Control Plane so `/health` and MCP advertise
  version `1.2.13`. Existing Agents remain compatible; new Agents expose the
  additive journal/discovery diagnosis fields, which the Control Plane folds
  into `overall` only when present.

## Known limitations

- **Device-local workspace activation is handshake-timed (follow-up).** A
  newly added device-local workspace still returns `created=true` from
  `workspace_add` while the workspace remains `pending_activation` until the
  Agent advertises its local generation on the next handshake (by design
  since v1.2.12). Immediate `workspace_show`/git tool use on a brand-new
  workspace can report `workspace_not_available` until that advertisement.
  Investigated for v1.2.13: the device registry is only advertised in the
  `ready` handshake (`remote_workspace_registry`), so a workspace registered
  via device-local IPC after a connection is not reflected in the Control
  Plane record until the Agent reconnects; there is no incremental registry
  refresh message. A follow-up release may add an Agent-initiated registry
  refresh (protocol addition, tracked in the roadmap) — out of scope for a
  patch release.
- **The shipped unit provides no OS-level filesystem confinement** — this
  is a documented limitation, not a complete sandbox reconciliation. The
  unit does not force a user namespace (v1.2.13 review, ADR 0011):
  `PrivateUsers=yes` and the filesystem namespacing directives
  (`ProtectSystem=`/`ProtectHome=`/`ReadWritePaths=`/`PrivateTmp=`/
  `ProtectKernelTunables=`/`ProtectControlGroups=`/`ProtectHostname=`/…)
  implicitly enable `PrivateUsers=` in a per-user service, which maps every
  host uid outside the namespace — host root and every other host user alike
  — to the overflow uid 65534. Accepting the overflow uid would let a
  foreign-owned `01777`/`0755` ancestor pass and its owner could replace the
  daemon's state directory (A5 cross-user boundary), so custody validation
  stays byte-for-byte strict and the unit ships only process-level guards
  plus `ProtectProc=invisible`. A local drop-in that re-adds a
  user-namespace-forcing directive fails closed at startup with `ancestor is
  owned by untrusted uid 65534` and is disclosed as start-breaking by
  doctor, never silently accepted as hardening. `ProtectHostname=yes` may be
  ignored by systemd in containers that prohibit UTS namespaces (harmless;
  systemd logs it and continues).
- **`CapabilityBoundingSet=` / `ProtectClock=` / `ProtectKernelLogs=` /
  `ProtectKernelModules=` are not shipped**: on systemd v259 they fail
  --user service startup with exit status 218/CAPABILITIES even under
  `PrivateUsers=yes` (verified empirically; the behavior is
  platform/version-dependent). The capability bounding set is the login
  session's unmodified set (systemd.exec(5): an unset option leaves it
  unmodified), and a drop-in that adds any of these directives is disclosed
  as start-breaking by doctor, never silently accepted. The documented
  integration check is `systemd-analyze security --user
  ownmesh-ownmeshd.service`. `RestrictNamespaces=yes` applies to the whole
  service including spawned sessions: the daemon and its session host never
  create namespaces, and common session programs (node, python, bash) are
  unaffected (verified empirically); a session that needs namespace creation
  (rootless podman, docker, unshare, bwrap) can be enabled with a local
  drop-in that sets `RestrictNamespaces=no`.

## Upgrade

1. Run `ownmesh update` or install the signed v1.2.13 archive.
2. If you installed the service before this release, run
   `ownmesh service install` (or `ownmesh service restart`) so the reconciled
   systemd unit is applied.
3. Deploy the v1.2.13 Control Plane.
4. Confirm `/health/ready` and run `ownmesh doctor --check-network`.
