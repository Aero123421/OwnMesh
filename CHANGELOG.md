# Changelog

## Unreleased

## v1.2.32 — Bounded OAuth refresh retry convergence

- Added an encrypted, 60-second rotation receipt so concurrent exact refresh
  retries and response-loss retransmissions converge to the same successor
  token set instead of revoking the successful result.
- Kept fail-closed refresh reuse detection for expired receipts, binding
  mismatches, and ancestors whose token family has already advanced.
- Added an atomic D1 migration and MemoryStore/SqlStore race, response-loss,
  binding, expiry, and successor-generation regression coverage.

## v1.2.31 — Acknowledged journal reclamation and bounded audit storage

- Added an authenticated, feature-negotiated control-plane acknowledgement for
  terminal results. Agents reclaim only exact completed receipts confirmed in
  D1; in-progress, uncertain, missing, and foreign-device entries remain
  fail-closed.
- Added bounded reconnect reconciliation in pages of 64 so existing full
  journals recover automatically after upgrade without manual deletion.
- Added a 30-day default TTL, 50,000-row per-tenant cap, bounded summaries,
  transactional counters, and indexed 128-row maintenance batches for D1
  audit metadata.
- Added migration, protocol, persistence, rollback, quota, and query-plan
  regression coverage.

## v1.2.30 — ChatGPT stable CIMD refresh tokens

- Recognized ChatGPT's stable CIMD client ID and callback as an exact OAuth
  pair when deciding whether to issue a rotating refresh token.
- Fixed repeated ChatGPT sign-in after the 15-minute access token expires when
  the authorization request omits `offline_access`.
- Kept legacy dynamic registration compatibility and added negative coverage
  for lookalike client IDs and non-exact callback URLs.

## v1.2.29 — Cloudflare CIMD fetch compatibility

- Replaced the unsupported Workers `fetch` redirect mode used for ChatGPT
  client metadata with a Cloudflare-compatible manual redirect response.
- Kept CIMD fail-closed: redirects are never followed, every non-2xx response
  is rejected, and metadata remains bounded and exactly client-id/redirect bound.
- Added regression coverage for the Workers request mode and hostile redirect
  responses, plus a live Cloudflare edge-runtime verification.

## v1.2.28 — ChatGPT CIMD compatibility

- Negotiated token endpoint authentication from the current plural CIMD
  capability list while retaining legacy singular-field compatibility.
- Kept OwnMesh public-client-only: CIMD is accepted only when `none` is in the
  client/server method intersection; confidential token authentication remains
  rejected.
- Added regression coverage using ChatGPT's current production metadata shape.

## v1.2.27 — Bounded Cloudflare control-plane cost

- Replaced `mcp_operations` full scans with an atomic per-tenant admission
  counter and leased, index-backed 128-row retention batches.
- Bounded MCP waits to two store reads, added leased/jittered uncertain-delivery
  recovery, and aligned long-command correlation TTL with admitted timeout.
- Added sanitized retryable D1-outage responses and full-jitter Agent reconnect.
- Updated the Cloudflare compatibility date, Wrangler, and Workers types.

## v1.2.26 — Generic external CLI sessions

### Generic external CLI sessions (breaking)

- Removed the coding-agent Profile crate, CLI/TUI/doctor flows, IPC methods,
  MCP tools and Profile-specific session fields, vendor protocol adapters,
  fixtures, and the `W-E6-RECEIPTS` release waiver.
- External CLIs now use the same exact `program`/`args` command, process, PTY,
  and session model as every executable. OwnMesh authorizes the child
  process/session boundary, not vendor-internal tool actions; workspace/cwd is
  explicitly not an OS sandbox.
- Legacy Profile methods are method-not-found, old Profile session inputs are
  invalid-params with migration guidance, and persisted Profile sessions are
  discarded rather than guessed into generic sessions.
- MCP catalog v2 records the intentional public break. Catalog v1 remains
  historical release evidence only. See ADR 0018.

## v1.2.25 — Runtime custody, dual-era MCP, and release evidence

v1.2.25 releases the hardening merged in #182. Elevated broker waits now use
captured request authority outside the daemon runtime mutex, prior-process
in-progress operations converge to a durable orphaned state without replay,
and Linux shebang execution binds the script and interpreter through sealed
custody. The Control Plane serves both MCP `2025-03-26` and `2026-07-28` from
one authorization/tool registry, adds CIMD and RFC 9207 issuer responses, and
freezes catalog-v1 call compatibility. Release publication now depends on an
exact packaged-binary workerd E2E and emits signed, attested machine-readable
evidence. No authorization, privacy, telemetry, or relay default is loosened.

### Runtime execution and restart state

- Elevated command broker connect, wait, cancel, output, and custody
  re-attestation no longer hold the global runtime mutex. Admission and
  finalization retain the exact operation, principal, credential generation,
  expiry, payload hash, executable pins, and journal marker.
- A prior-process `in_progress` marker is classified as
  `recoverable_orphaned`, surfaced as `OWNMESH_E_OPERATION_ORPHANED`, and is
  never silently retried. Generic command process reattachment is not claimed.
- Linux interpreter scripts pin both the script and interpreter and execute
  sealed snapshots through proc-fd handoff. A bounded Node loader preserves
  the approved module URL and relative imports; unsupported `env` option
  syntax fails closed.

### MCP and OAuth compatibility

- Legacy MCP `2025-03-26` and stateless modern MCP `2026-07-28` share one tool
  registry, scope map, action binding, and device-policy route. Modern requests
  receive strict metadata/header validation, typed negotiation errors,
  `server/discover`, result types, and cache hints.
- Catalog v1 has a frozen compatibility baseline. Existing names, including
  hidden deprecated aliases, remain callable through the 1.x window; CI rejects
  required-field, property, effect-hint, or callable-surface breakage.
- OAuth advertises and validates bounded Client ID Metadata Documents, includes
  RFC 9207 `iss`, and retains DCR as the compatibility fallback. Private-key
  JWT is neither advertised nor accepted.

### Release assurance and diagnostics

- Publication waits for the downloaded, checksum-verified Linux x64 archive to
  pass workerd device, filesystem, command, session, restart/recovery, profile,
  and two-Agent resumable-transfer tests.
- Releases emit `ownmesh-release-evidence.json` from exact artifact hashes,
  catalog receipts, and gate facts. The receipt is covered by the mandatory
  minisign checksum chain and GitHub provenance.
- Machine endpoint probes classify DNS, TLS, connect timeout, Cloudflare edge
  denial, Worker auth/4xx/5xx, malformed JSON, and catalog mismatch separately,
  with bounded retries and CF-Ray reporting.

## v1.2.24 — Runtime availability and profile adapter correctness

v1.2.24 is the first formal release after v1.2.23. It combines the post-release availability work in #169 and #167 with the official nine-profile adapter correctness work in #171. No authorization, privacy, telemetry, or relay default is loosened.

### Device availability

- Non-elevated `command.run` no longer holds the daemon runtime mutex while
  waiting for the child. Policy admission, pinning, and the exact-once journal
  reserve still run under the lock; the child wait runs after release; the
  in-progress marker is the compare-and-swap target at finalization. An
  unrelated filesystem or diagnosis request can complete while a long command
  is running, and a shell-wrapped OwnMesh CLI no longer deadlocks the device
  (#160, [ADR 0015](docs/adr/0015-runtime-lock-released-across-command-wait.md)).
  The pre-spawn `OWNMESH_E_SELF_REENTRANT_EXEC` guard remains. `system.diagnose`
  adds a bounded `runtime_queue` check (`idle` / `executing` /
  `self_reentrant_exec`) without argv, paths, or output. A live unlocked exec
  that reserved a journal marker is not reported as a stuck receipt; a leftover
  marker plus a keyless in-flight exec stays visible. The unlocked admit path
  still applies lockdown, journal-degraded, and revoked-principal gates before
  spawn. A global command semaphore is acquired before the runtime mutex,
  journal reservation, and executable custody; queued remote commands can be
  cancelled without later spawning or consuming their idempotency key, while
  detached jobs retain their separate four-job cap. Control-plane and local
  approvals use the same unlocked typed finalization path, including approval
  bridges, and rollback restores only the operation's own journal/approval
  entries so unrelated concurrent commits are never overwritten.
- `session.open` will not commit `state=running` unless the OS reports the
  attested child as still running. A short-lived process that is already a
  zombie at the attestation barrier is rolled back instead of poisoning later
  open/replay/close. Structured children that exit while a descendant keeps
  their stdout/stderr pipes open are classified at the supervisor status
  boundary; the durable birth witness remains the plain PID-reuse witness.
  Linux `/proc` state `Z` and absence/probe ambiguity are disclosed explicitly
  rather than overstated as an unambiguous reap result (#31).
- The Windows portable installer polls authenticated `ownmesh --json status`
  until `daemon.version` matches the installed CLI, using the same 20 s
  bounded deadline as `ownmesh update`. A healthy daemon that needs more than
  500 ms no longer triggers binary rollback. A leftover Task Scheduler
  `LastTaskResult` while the task is READY is not this instance; a terminal
  COM result fails the installer only after this instance was observed
  running, or when the task is disabled. The bounded wait uses a monotonic
  `Stopwatch`, tolerates native stderr/partial status while startup is in
  progress, and never treats localized task text or a failed COM probe as
  authoritative task absence. The supported 20-second default and
  `OWNMESH_DAEMON_READY_TIMEOUT_SECONDS` override remain unchanged (#154).
- Setup, `ownmesh doctor`, and the TUI Repair Agent path inspect the same
  config/state/runtime ancestor custody walk the Agent uses at start. A
  group-writable parent such as `~/.local/state` is a dedicated
  `layout.custody` failure with path, mode, owner, and a non-recursive
  `chmod g-w,o-w` next step — not a healthy doctor report plus a looping
  `service start`. Repair never chmods a directory it does not own and never
  recurses; TUI confirmation shows the exact paths first (#168).

## v1.2.23 — Availability, workspace authority, and dependency refresh

v1.2.23 is the first formal release after v1.2.21. The v1.2.22 source train
below was prepared on `main`, but no v1.2.22 tag or GitHub Release was
published; v1.2.23 therefore includes every v1.2.22 lifecycle, endpoint, and
session fix as well as the changes in this section.

Mitigates the concrete failure modes reproduced from the 2026-08-25 production
session (#158–#162) and the reopened Linux session regression (#31). These
changes do not claim every issue acceptance criterion is complete: live
ChatGPT/production canaries, the Cloudflare WAF configuration, transactional
multi-session reattach, and the runtime-wide execution-lock redesign remain
tracked in their original issues.

### Device availability

- A remote `command_run` of the OwnMesh CLI is refused before spawn with
  `OWNMESH_E_SELF_REENTRANT_EXEC` instead of deadlocking the daemon. The daemon
  holds one runtime mutex across a child's whole lifetime, so a child that
  synchronously re-enters daemon IPC waited on the lock its own parent held —
  and every later filesystem, Git, session, and diagnosis request for that
  device queued behind it until the first operation was cancelled by hand.
  Detection uses OS file identity, so the same installed file reached after a
  rename, through a hard link, or through a symlink is recognized; `--version`
  and `--help` stay executable because they exit during argument parsing,
  before any IPC is opened. A byte-for-byte copied executable and invocation
  through a shell or script remain outside this guard, so #160 stays open for
  the runtime-wide lock redesign.
- Linux session lifecycle treats an exited-but-unreaped child as exited. A
  zombie keeps its PID slot and kernel start time, so the birth-witness probe
  reported it as live: `close` answered "authenticated child is still alive,
  refusing PID-only termination", the dead session stayed pinned as `running`,
  and one such record made every later `session_open`, `replay`, and `close`
  fail while naming that unrelated session. PID-reuse protection is unchanged —
  the birth witness is still compared, it just no longer counts a zombie as
  running (#31).
- Reattach now isolates failures per session. A session the supervisor proves
  has no live child reconciles to terminal; an indeterminate one is retained
  fail-closed. Neither aborts the pass for unrelated sessions (#31).
- `session_show` reconciles provably dead records during an ordinary read, so a
  finished session stops being displayed as `running` (#31).

### Authorization continuity

- A routine OAuth refresh rotation no longer invalidates queued device
  operations. Revocation and refresh-token reuse now advance a separate
  `revocation_epoch`, and device operations bind to that epoch rather than to
  every credential issuance. Access tokens live 15 minutes, so an operation
  waiting through a reconnect, a Durable Object wake, or a temporary queue
  blockage previously crossed a refresh boundary and was failed as a
  non-retryable credential mismatch — indistinguishable from a real revocation
  (#162).
- Explicit revocation and refresh-family reuse still terminally invalidate every
  operation authorized by the affected family, and an invalidated operation is
  never rebound, redelivered, or retried in place.
- The public error names a bounded reason (`explicit_revocation`,
  `refresh_reuse`, `routine_refresh`, `unknown_generation_change`) without
  exposing tokens, refresh families, or credential material. A credential
  continuation returns `OWNMESH_E_AUTHORIZATION_REFRESHED` with
  `retryable: true` and `next_action: resubmit` instead of a bare
  `retryable: false` a caller cannot act on (#162).

### Workspace registry and approval authority

- A live Agent publishes `workspace.registry` changes only after the Control
  Plane has durably written the new generation to D1 and the DeviceRoom state;
  only then is `workspace.registry.ack` emitted. The Agent validates and accepts
  that strict live ACK, so a successful acknowledgement can no longer outrun
  authoritative activation or be confused with a reconnect-only handshake
  (#165).
- Approval decisions are bound to the target operation's original workspace ID
  and Control Plane version. DeviceRoom resolves the target operation again at
  final delivery, revalidates its workspace generation, and terminally refuses
  the target if an administrator removed and recreated that workspace while the
  approval was pending. The routing-only `workspace_id` is removed before the
  strict runtime schema is invoked, so transport metadata cannot masquerade as
  an approved runtime argument (#165).
- Unix workspace-registry lock descriptors are opened close-on-exec. Persistent
  session sidecars can no longer inherit the daemon's registry lock and keep a
  restarted daemon from acquiring it after the original process exits (#165).

### Diagnosis and catalog compatibility

- The `system.diagnose` payload contract is validated independently of the
  device protocol version. A newer Agent's additive checks and fields no longer
  invalidate a diagnosis: the scan window is a fixed bound rather than the size
  of the Control Plane's own known-id set, which is what silently truncated the
  required `sessions` check once the Agent began emitting `agent_route` ahead of
  it, collapsing a valid diagnosis into `invalid_response` (#161).
- The single `invalid_response` bucket is replaced by bounded reason codes
  (`unsupported_contract_version`, `missing_agent_metadata`,
  `missing_required_check`, `bad_check_shape`, `bad_status`,
  `malformed_payload`), and a different contract major returns
  `unsupported_diagnosis_version` with the version numbers and an
  `upgrade_control_plane` recommendation instead of blaming the device. A known
  check with an unknown state stays visible as `unsupported_value` and lifts
  `overall` away from `healthy`. Missing security-relevant checks remain
  fail-closed (#161).
- MCP exposes a deterministic catalog revision — a SHA-256 over exactly the
  bytes `tools/list` returns — on `GET /mcp`, `/health`, `initialize._meta`, and
  every `tools/list` response, so a deployment's catalog and a client's snapshot
  can be compared directly (#158).
- The catalog revision is bound into the MCP session id. A request carrying a
  session minted under a different revision is answered with HTTP 404, which
  MCP defines as "session expired, re-`initialize`", so a long-lived connector
  converges on the current catalog after a deployment instead of serving a stale
  one. `listChanged` stays `false`: this Streamable HTTP deployment has no
  server-initiated stream and must not claim a notification it cannot deliver
  (#158).
- `pnpm run deploy:guided` verifies that the origin now serving traffic
  advertises the version being released, and refuses to report success
  otherwise. A deploy that leaves an older Worker live is what left production
  three release generations behind while clients kept an old catalog (#158).

### Deployment

- `scripts/probe_machine_endpoints.py` checks MCP discovery and the OAuth
  metadata endpoints from two HTTP stacks under several User-Agents and reports
  which layer answered, so a Cloudflare browser-signature rejection (HTTP 403 /
  Error 1010) is never mistaken for a Worker fault. Such a rejection never
  reaches the Worker, carries no `WWW-Authenticate` challenge, and removes the
  whole tool catalog rather than failing one operation. `docs/deploy-cloudflare.md`
  documents the scoped WAF skip rule that fixes it while keeping rate limiting,
  payload bounds, and authentication in force (#159).

### macOS prepared executable compatibility

- macOS 26 kills copied Apple platform binaries such as `/bin/sh` and
  `/bin/echo`, even when the private copy is byte-identical and its embedded
  signature verifies. Prepared execution now keeps the existing private,
  digest-verified snapshot for ordinary user executables, but launches only an
  `SF_RESTRICTED`, root-owned system backing path after proving the executable
  and every canonical ancestor are non-writable by the daemon, retaining all
  opened custody handles, revalidating the pins, and preserving the approved
  invocation as `argv[0]`. No executable is re-signed or rewritten.
- The verify-to-spawn mutation tests use a copied OwnMesh test image instead of
  assuming a relocated Apple platform binary is executable. macOS coverage now
  also executes a real restricted platform binary and retargets its mutable
  proxy after preparation to prove the attacker-controlled invocation is never
  reopened.

### Dependency and CI maintenance

- Rust dependencies were updated with their regression suites kept green:
  `hmac` 0.13, `chacha20poly1305` 0.11, `jsonschema` 0.50,
  `thiserror` 2.0.20, `unicode-width` 0.2.2, `windows-sys` 0.61.2,
  `base64` 0.23.1, `zip` 8.6.0, and the test-only `minisign` 0.9.1
  (#72, #74–#81).
- The Worker toolchain moved to Wrangler 4.123.0 and
  `@cloudflare/workers-types` 5.20260817.1 (#130, #131). GitHub Actions moved to
  the reviewed releases of `setup-node`, `checkout`, `download-artifact`,
  `action-gh-release`, and `gitleaks-action` (#66–#70).
- Dependabot proposals for Node 26 types (#73) and `portable-pty` 0.9 on Windows
  (#82) were deliberately not merged: OwnMesh still supports Node 22.6+, and
  Windows remains pinned to `portable-pty` 0.8.1 because 0.9 reintroduces the
  documented ConPTY cursor-query hang.

### Release verification

- The Nightly real-binary suite now follows the authoritative ready-handshake
  contract, waits on public transfer states rather than runner timing, uses the
  production default IPC endpoint resolver, and preserves per-daemon logs.
  E1, E2/E3, and E9 cover live workspace activation, PTY/review receipts,
  restart/resume from a durable non-zero transfer cursor, partial cancellation,
  and durable-state secret/material exclusion (#165).

See `docs/RELEASE_NOTES_v1.2.23.md` for details.

## v1.2.22 — Service lifecycle, endpoint, and session honesty

Closes the nine open issues from the 2026-08-24 audit (#147–#155). Every one
is displayed state that was not the authoritative state; each is closed by
making the check authoritative rather than by relaxing the claim.

### Service lifecycle honesty

- `service start` and `service stop` now cross the observable daemon IPC
  boundary instead of treating an accepted service-manager request as a
  completed transition; a request that never reaches (or leaves) the endpoint
  returns `OWNMESH_E_SERVICE` with the manager's own installed/running facts
  rather than `ok:true` with `running:null` (#154).
- macOS `service stop` boots the LaunchAgent out of the user domain, so
  `KeepAlive=true` can no longer relaunch the daemon behind a reported stop;
  `start` re-enables and bootstraps the job idempotently, and `uninstall`
  refuses to delete the plist until launchd confirms the job is unloaded
  (#147).
- Linux `service uninstall` reports every `systemctl --user` failure and keeps
  the unit and install record in place until the manager confirms the unit is
  inactive, so a failed stop can no longer be hidden by deleting the unit file.
  An unreachable user bus is no longer mistaken for an absent unit (#149).
- `service install` compares the descriptor actually registered with the OS —
  systemd unit body, macOS plist, and the Windows task's structural identity
  (action and trigger cardinality plus every rendered setting, since Task
  Scheduler reformats imported XML) — against a versioned descriptor digest
  persisted in `user-service.json`. A hand-edited, older-version, or unreadable
  descriptor is repaired instead of reported as idempotent success. Descriptor
  identity is independent of whether the service is currently loaded, so a
  deliberate `service stop` survives a later install (#153).
- Probe results that prove nothing are classified as unknown rather than as
  absence: `systemctl is-active` is read by reported state rather than exit
  status (it exits non-zero for every state but `active`), and only an
  explicitly reported absence from `launchctl print` allows the descriptor to
  be removed (#147/#149).
- The Windows Scheduled Task binds the daemon to the config/state/runtime
  directories validated at install time, via typed `ownmeshd run
  --config-dir/--state-dir/--runtime-dir` arguments shared by the XML import
  and the `/TR` fallback — no `cmd /c set … &&` wrapper. Typed arguments
  outrank `OWNMESH_*` environment variables, so an autostarted daemon can no
  longer split one installation into two state trees (#148).

### Endpoints and sessions

- Unix endpoints are validated against the platform `sockaddr_un` capacity
  before bind: a long but valid runtime directory now resolves to a
  deterministic short owner-only pathname (0700, custody-attested) that every
  producer and consumer derives identically, and an explicitly configured
  socket path that cannot be bound is rejected with the required reduction
  instead of failing later inside `bind` (#155).
- Windows named pipes are scoped by a SHA-256 digest of the normalized runtime
  path rather than a truncated alphanumeric filter, so distinct profiles can no
  longer collide onto one pipe; a failed connect names the upgrade/restart
  remedy for a daemon still on the legacy pipe name (#151).
- Structured-pipe sessions publish EOF and a real exit code: each reader marks
  its stream terminal on every exit path, the child is reaped once, and
  completion requires child exit plus both stream EOFs so a late stream cannot
  be truncated. Supervisor status and daemon diagnosis now observe a completed
  structured child instead of reporting it live until TTL. A forced termination
  waits a bounded grace for the readers to publish EOF themselves and only
  seals the streams when a descendant still holds the pipes — refusing further
  appends so no output can follow the reported completion, and disclosing the
  cutoff rather than implying a clean EOF. A termination that failed publishes
  nothing (#152).

### Installer

- The Unix installer recognizes a running `ownmeshd` whose executable was
  replaced, which Linux reports as `/proc/<pid>/exe` → `<path> (deleted)`. The
  suffix is stripped only after the remaining pathname matches the normalized
  install-dir daemon, so upgrades restart and version-check the stale daemon
  instead of silently leaving it running; matching is never by process name
  (#150).

See `docs/RELEASE_NOTES_v1.2.22.md` for details.

## v1.2.21 — Transport availability, journal honesty, and Linux disclosure

- Agent and transfer WebSocket connects are bounded (15 s) with RFC 8305-style
  family interleaving and IPv4 fallback; a blackholed AAAA can no longer park a
  reconnect forever (#140). `connect_timeout` is a typed reconnect category.
- Terminal operation failures reconcile their reserved op-journal marker into
  a compact failed receipt, so retries replay the stored failure instead of
  being refused forever as in_progress keys; crash residue keeps exact-once
  semantics per ADR 0010 (#142).
- Doctor and system.diagnose expose live Agent-route presence via the new
  credentialed `daemon.route_status` IPC method (`daemon.agent_route` check,
  additive `agent_route` diagnosis id and `agent_route_offline` overall);
  doctor no longer passes while ChatGPT sees the device offline (#141).
- Incremental workspace registry refresh: ready agents publish the full
  registry on device-local changes over one new authenticated message
  (`workspace.registry` / ack, ADR 0014), so workspace activation no longer
  waits for a reconnect (#146). Shared JSON schema added and validated in both
  languages.
- Linux disclosures without loosening defaults: spawn-resolution failures list
  the searched directories (service PATH plus user-local extras, home
  collapsed); EPERM spawn errors and the hardening pass row name
  RestrictNamespaces=yes and its operator drop-in (#144/#145); doctor warns
  when Linger=no so logout-killed agents are diagnosable, and TUI/docs state
  the session-lifetime caveat (#143).

See `docs/RELEASE_NOTES_v1.2.21.md` for details.

## v1.2.20 — TUI terminal-contract reliability

- Ctrl+C is a universal emergency exit from every screen, overlay, wizard
  step, and palette state; raw mode no longer swallows the interrupt gesture.
  `q` remains the normal quit. Documented in the command bar and help text
  across all four UI languages.
- Terminal input failures (EOF, detached or broken TTY) end the interactive
  loop as a controlled exit instead of an endless redraw-only idle loop, and
  terminal restoration reports (and retries) partial cleanup failures instead
  of a false success. Non-TTY invocations fail closed with usage guidance.
- Mouse capture is disabled by default: captured clicks were discarded and
  scroll events mutated unrelated list cursors while hijacking native
  terminal selection (worst on macOS trackpads). Capture returns only with
  functional mouse navigation.
- List navigation is clamped to existing rows on every path (keyboard,
  refresh shrink, screen transitions) and lists scroll to keep the selected
  row visible via Ratatui stateful widgets; empty lists pin the cursor.

See `docs/RELEASE_NOTES_v1.2.20.md` for details.

## v1.2.19 — ChatGPT MCP token refresh and control-plane version visibility

- `/mcp` returns HTTP 401 with `WWW-Authenticate` (and JSON-RPC `-32001`) when
  a Bearer token is missing on `tools/call` or is invalid on any JSON-RPC
  method, so ChatGPT can refresh instead of treating a 200 JSON-RPC error as
  transport success. Unauthenticated `initialize` / `tools/list` stay available
  for discovery.
- `GET /.well-known/oauth-protected-resource/mcp` serves RFC 9728 metadata for
  the `/mcp` resource identifier; `authorization_servers` remains the issuer
  origin.
- `ownmesh doctor --check-network` warns when the control-plane `/health`
  version does not match the CLI. See `release/SUPPORTED_SURFACES.json`.

## v1.2.18 — Windows installer upgrade stop on PowerShell 5.1

- The portable Windows installer no longer treats a missing `OwnMesh-ownmeshd`
  scheduled task as a terminating error under Windows PowerShell 5.1
  (`$ErrorActionPreference = Stop` + `schtasks` NativeCommandError).
  Upgrades that only need to stop matching install-dir processes continue.
- The same `powershell -File` path also hashes with .NET SHA-256 and restores
  the Desktop `$PSHOME\Modules` path so a pwsh-inherited Core `PSModulePath`
  cannot hide `Get-FileHash` / `Unblock-File`. See
  `installers/ownmesh-installer.ps1`. The machine-checked contract remains
  `release/SUPPORTED_SURFACES.json`.

## v1.2.17 — Hardening gates and fail-closed OAuth redemption

- Authorization-code grants verify then CAS-bind the redeemed code hash to
  one token family. D1 migration `0017` adds `oauth_tokens.auth_code_hash`.
- Request bodies are limited by actual bytes; Content-Length is advisory.
  Device `user_code` values are generated with Web Crypto rejection sampling.
- TAR header/extension records are charged to updater decompression budgets.
- Support-bundle export is a typed allowlisted v2 preview; mixed-case
  high-entropy tokens fail closed and export bytes match preview bytes.
- Doctor surfaces non-secret credential-store provenance (backend, residual
  fallback entries, degraded cleanup).
- Privileged-broker replay ledgers reconcile crash-left reservations and
  enforce capacity. Updater apply/rollback stays crash-consistent for the
  five required binaries. See #100 #101 #113 #121 #122 #123 #124 #125 #126
  #128. The machine-checked contract remains `release/SUPPORTED_SURFACES.json`.

## v1.2.16 — Prepared executable custody

- Approval-bound command execution now retains the exact invocation entry,
  canonical backing identity, classification, and `argv[0]`. Invocation or
  backing drift returns `OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT`; the runtime no
  longer substitutes a canonical backing path for a changed proxy.
- Generic and review command spawn consume a non-cloneable prepared executable.
  Linux uses a sealed anonymous image, macOS an owner-only verified snapshot,
  and Windows target/proxy/ancestor handles held without write/delete sharing
  until spawn completes. Raw shells prepare the selected interpreter too.
- Deterministic cross-platform regression fixtures cover proxy deletion,
  retarget/recreation, backing replacement, atomic and in-place content change,
  parent-directory replacement, exact `argv[0]`, and zero canary side effects.
- Executable entry identity is part of policy/approval facts, and the typed
  drift error is aligned across Rust, IPC/CLI, TypeScript, and JSON schemas.
  See ADR 0013.

## v1.2.15 — Service install remediator and runtime-dir alignment

- Linux CLI/updater runtime discovery uses owner-only `/run/user/<uid>/ownmesh`
  when `XDG_RUNTIME_DIR` is unset, matching the systemd user unit instead of
  falling back to `state_dir/run`. Update worker and nested `ownmesh status`
  children receive `OWNMESH_CONFIG_DIR` / `OWNMESH_STATE_DIR` /
  `OWNMESH_RUNTIME_DIR` so a headless shell cannot health-check the wrong
  socket. See #113.
- `ownmesh service install` now remediates leftover OwnMesh-generated systemd
  user drop-ins (`10-ownmesh-workspaces.conf` / `# Generated by OwnMesh`
  files that set `ReadWritePaths=` and other user-namespace-forcing
  directives). A matching executable is no longer treated as an idempotent
  no-op while those leftovers remain. Operator-written drop-ins are left
  in place; if they still force a user namespace, install fails closed
  instead of reporting `ok: true`. The shipped user unit also sets
  `StartLimitBurst=5` / `StartLimitIntervalSec=30` so a custody-fail cannot
  restart every three seconds forever. See ADR 0011.
- Darwin PTY terminate no longer treats a completed `try_wait` as proof of
  death when the process table still shows the child live, and uses BSD
  process-group kill syntax. `PtySession` drop now last-resort `SIGKILL`s
  the recorded child after terminate.
- Release publish installs the same hash-pinned minisign 0.11 linux binary
  the installer already uses, instead of `apt-get install minisign` (which
  can stall indefinitely on `ubuntu-latest`).

## v1.2.14 — Detached commands, hashed overwrite, bounded grants

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
  or the five-minute dispatch / poll expiry. Device Room keeps the pending
  correlation past the ordinary 15-minute TTL; the hard cap is 24 hours or
  cancel. Agent reconnect does not start a second spawn of an in-process
  job (that would fail the op-journal as CONFLICT); if the live loop is
  gone the completion is parked and published on the next session. Every
  live-loop turn publishes every parked row (not only the inbound
  correlation), so a dropped `Notify` wakeup cannot strand a detached
  result until the 24h expiry.
  Completion is retrieved with `ownmesh_get_operation`. Concurrent
  detached jobs per device are capped fail-closed. The synchronous
  `timeout_ms` clamp is configurable via Worker env `MCP_MAX_TIMEOUT_MS`
  (default 300000, hard ceiling 3600000). Timed-out synchronous commands
  include hint `use detach:true or a session for long-running commands`.
- An unreadable, over-budget, or unremovable-backup op-journal no longer
  refuses `ownmeshd` startup. The daemon starts read-only (`OWNMESH_E_JOURNAL_DEGRADED`
  for side effects) and surfaces `journal_degraded` in `system_diagnose` /
  `ownmesh doctor`. Local repair is `ownmesh doctor --repair-journal
  --i-understand-replay-risk`.
- Bounded tool grants (`grant_type: "bounded_tool"`) lift policy **Ask** only
  for an explicit tool allowlist, optional workspace, TTL ≤ 4 hours, and
  optional max-use count. Matching requires the mint device id and the
  request's canonical tool plus capability/kind; a client-supplied tool name
  cannot lift a different capability. Principal and device id are stamped on
  the mint approval at enqueue from the verified remote dispatch, not reread
  from the live session at recovery execute. Deny still wins, including
  recommended/workspace_only `command.run`. Minting is the same fresh-passkey
  admin path as policy preset (`ownmesh grants mint` / `ownmesh_grants_mint`).
  Revoke and lockdown are local tightening. See ADR 0012.
- `/approve` lists pending operations for an authenticated human session.
  Selected sets are bound by a v2 presence cookie whose commitment is SHA-256
  of server-looked-up `operation_id:payload_hash` lines (max 32). Each decision
  is still consumed per operation. Deny-all of the listed pending set requires
  session + CSRF + same-origin, not a passkey. Notification channels never
  carry approval authority.

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
