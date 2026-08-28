# OwnMesh v1.2.24

OwnMesh v1.2.24 is the next stable release after v1.2.23. It focuses on two
things: keeping long-running command/session paths from stalling the device, and
making the nine official coding-agent profiles report and execute only the
structured contracts that are actually supported.

No privacy or authorization default is loosened. Telemetry, cloud file relay,
and unsolicited network checks remain off by default. The machine-checked
product contract remains [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Device availability and command concurrency

- Non-elevated `command.run` no longer holds the daemon runtime mutex while the
  child is running. Policy admission, revocation/lockdown checks, exact-once
  reservation, executable identity checks, and custody still occur under the
  authority-bearing path; only the external child wait is moved outside the
  mutex (#160, ADR 0015).
- The authenticated Control Plane `approval.decision` path now follows the same
  unlocked execution model when an approval releases a deferred non-elevated
  command. A command that required Ask therefore no longer has a special path
  that can stall every unrelated operation on the device (#160).
- Off-lock commands are bounded by an explicit global semaphore acquired before
  the runtime mutex, journal reservation, and executable preparation. Capacity
  waits therefore do not consume an idempotency key or pin executable custody.
  If a queued remote operation is cancelled before capacity becomes available,
  it never spawns later. Detached commands retain their own stricter cap.
- Finalization keeps the exact-once in-progress marker as the compare-and-swap
  target. Approval/journal rollback is scoped to the entries owned by that
  operation, so an interleaved unrelated commit is never overwritten by a
  whole-map snapshot restore.
- `system.diagnose` keeps the bounded `runtime_queue` view from #169 so a live
  unlocked execution is distinguishable from a stale in-progress journal row
  without exposing argv, paths, output, or other command content.

## Session and process-state honesty

- `session.open` refuses to publish `running` when the attested child is already
  dead, including the short-lived zombie race covered by the #169 path.
- The structured-session supervisor now also folds OS liveness into its status
  boundary. An exited-but-unreaped child is reported exited even when a
  descendant still holds stdout/stderr open, while the durable process-birth
  witness remains the plain PID-reuse witness (#31).
- Linux `/proc` state `Z` and absence/probe ambiguity are explicitly documented;
  a probe failure is not silently promoted into a successful reap claim.

## Windows installer readiness

- The portable installer continues polling authenticated `ownmesh --json status`
  until the daemon reports the version that was just installed, rather than
  relying on the old fixed 500 ms delay (#154).
- The readiness deadline now uses a monotonic `Stopwatch`, so wall-clock/NTP
  changes cannot silently extend the wait. Native stderr, partial JSON, and
  not-yet-ready replies remain retryable startup states.
- Task Scheduler state is interpreted from authoritative result/state values,
  not localized display text. A task probe that itself fails is not treated as
  proof that the task disappeared. The existing 20-second default and
  `OWNMESH_DAEMON_READY_TIMEOUT_SECONDS` override are preserved.

## Official nine-profile adapter correctness

- Codex, Claude Code, Kimi, OpenCode, Pi, AGY, Qwen Code, Hermes Agent, and
  Qoder now use source-backed, dialect-aware structured adapter contracts rather
  than one generic JSON classifier (#170/#171).
- Versioned fixtures cover ACP v1, Codex app-server, Claude stream-json, Pi RPC,
  and AGY stream-json. Malformed, oversized, unknown, and future records remain
  bounded typed adapter errors, and a bad record does not hide a later valid
  record.
- Detection, version probing, shebang interpreter resolution, and launch share a
  deterministic child `PATH`. A discovered npm-style wrapper can no longer be
  reported ready when its interpreter is not launchable from the service
  environment.
- `installed`, authentication evidence, and structured-protocol readiness are
  separate states. A version probe alone cannot become a false compatibility
  PASS.
- ACP filesystem/terminal requests and vendor permission/approval requests fail
  closed with correlated typed responses. OwnMesh does not auto-approve vendor
  requests or advertise client capabilities it does not implement.
- Resume and cancellation are dialect-specific, and local/remote structured
  profile sessions share the persistent supervisor path. Prompt text is passed
  as a protocol/argv value rather than shell syntax.

## Startup and custody diagnostics

- Setup, `ownmesh doctor`, and the TUI Repair Agent path inspect the same
  config/state/runtime ancestor custody requirements used at daemon start. A
  writable ancestor is surfaced as a dedicated `layout.custody` problem with a
  bounded non-recursive remediation path (#168/#169).
- macOS restricted Apple system binaries keep the #169/#164 backing-path custody
  behavior; the v1.2.24 availability changes do not weaken executable identity
  or prepared-image guarantees.

## Verification

The merged pull requests were gated on Linux, macOS, and Windows with Rust 1.92,
workspace tests, Clippy with warnings denied, frozen pnpm tests/typecheck/lint,
dependency audits, SAST, secret scanning, strict CycloneDX SBOM generation,
release-quality checks, and the release/security dependency graph. Focused
regressions cover Control Plane approved-command lock release, queued
cancellation without idempotency burn, entry-scoped rollback, supervisor zombie
attestation, and delayed Windows readiness.

Formal release assets remain tag-gated by both CI and Security workflows. The
release job produces Windows x64, macOS arm64/x64, and Linux musl arm64/x64
archives, signed SHA-256 metadata, strict SBOMs, installers/Homebrew metadata,
and GitHub build provenance.

## Compatibility and remaining gaps

- No protocol version or public CLI command is removed by this release.
- Clients holding an MCP session from an older catalog revision still need to
  reinitialize after a deployment, as documented in v1.2.23.
- Authenticode, Apple notarization/native installers, macOS/Windows native broker
  receipts, fully automated external ChatGPT verification, and independent
  external security review remain separately disclosed evidence/packaging gaps.
- The nine-profile implementation/fixture coverage does not fabricate live
  provider credentials or receipts that were not collected; evidence claims
  remain bounded by the release-quality registry and waiver structure.
