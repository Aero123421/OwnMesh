# ADR 0015: Release the daemon runtime mutex across `command.run` waits

- Status: Accepted
- Date: 2026-08-27
- Deciders: OwnMesh runtime maintainers

## Context

`runtime_handler` and the Agent transport acquired one `Mutex<DaemonRuntime>`
and held it across the full asynchronous dispatch, including the wait for a
spawned child. A remotely launched program that synchronously re-entered
daemon IPC (notably `ownmesh doctor`) waited on that same mutex, so neither
side could progress and every later filesystem, Git, session, and diagnosis
request for the device queued behind the deadlock (#160).

v1.2.23 added a pre-spawn `OWNMESH_E_SELF_REENTRANT_EXEC` guard for OwnMesh
binaries identified by OS file identity. That is a bounded mitigation: it
cannot see an OwnMesh CLI invocation inside a shell string or a copied
executable, and it does not let an unrelated read complete while a permitted
`sleep` (or any other long child) is running.

Exact-once journaling, cancellation identity, workspace generation, policy
admission, and executable pinning must remain fail-closed while the wait
moves off the mutex.

## Decision

1. **Admit under the lock, execute without it, finalize under the lock.**
   Policy evaluation, grant consumption, executable pinning, and
   `begin_idempotent` still run while `DaemonRuntime` is exclusively held.
   Non-elevated `command.run` then releases the mutex, waits on the child,
   and reacquires only to persist the terminal journal receipt.
2. **The in-progress journal marker is the compare-and-swap target.**
   Finalization succeeds only when that principal-namespaced key is still
   the same operation's `in_progress` marker. A raced or already-terminal
   marker is left untouched and the outcome is reported uncertain — the
   same ADR 0010 posture as a crash between reserve and receipt.
3. **Request-scoped cancel/remote facts are snapshotted into the admitted
   plan** before the mutex is released, so a concurrent dispatch cannot
   clobber `active_cancel` / `active_remote_*` for the in-flight child.
4. **Elevated broker execution uses the same split (2026-08-28 amendment).**
   Request-scoped operation id, payload hash, device, principal, credential
   generation, expiry, cancellation receiver, executable pins, and immutable
   broker facts are captured during admission. Broker connect/write/wait,
   cancellation delivery, output collection, and post-response custody
   re-attestation run after the runtime mutex is released; finalization still
   compares and commits only this operation's marker. Session supervisor RPCs
   remain bounded by the IPC client's five-second request timeout but still
   serialize on the runtime mutex; moving session transitions to a narrower
   state owner remains separate work and is not claimed complete here.
5. **The self-reentrant pre-spawn guard stays.** A typed refusal is still
   better than spawning a known-deadly child. `system.diagnose` exposes a
   bounded `runtime_queue` check (`idle` / `executing` / `self_reentrant_exec`)
   without argv, paths, environment, or user output. Diagnosis subtracts only
   unlocked execs that reserved a journal marker, so a leftover marker plus a
   keyless exec stays visible as stuck.
6. **Command execution has an explicit global capacity bound.** A permit is
   acquired before the runtime mutex, policy admission, journal reservation,
   or executable custody, and held through finalization. Eight ordinary
   command slots remain available when all four separately capped detached
   jobs are active. A remote cancellation while queued wins before admission,
   so it cannot spawn later or consume an idempotency key.
7. **Approved non-elevated commands use the same typed completion path.**
   Local and control-plane approval decisions admit under the lock, execute
   without it, and finalize after reacquiring it. Approval bridges order the
   target completion before the outer bridge completion. A failed completion
   restores only its own journal entry and approval record, never a whole-map
   snapshot that could erase unrelated work committed during the child wait.

## Consequences

- An IPC-reentrant child, or a long permitted `command.run`, no longer
  starves filesystem, Git, or diagnosis tools for that device.
- Concurrent `command.run` executions can overlap within the explicit global
  bound. Admission remains exclusive; only the child wait is concurrent.
  The separate detached-command cap and journal exact-once semantics are
  unchanged.
- Callers that still invoke `dispatch` / `dispatch_cancellable` on a
  `&mut DaemonRuntime` (unit tests, in-process helpers) execute the same
  plan inline. Production IPC and Agent paths use `dispatch_unlocked`.
- Session open/close still hold the mutex across bounded supervisor RPCs. That
  is a disclosed remainder, not a claim that every external wait has moved.

## Alternatives considered

- **Keep the global mutex and only refuse OwnMesh binaries.** Already
  shipped as a mitigation; it does not satisfy concurrent unrelated tools
  or shell-wrapped re-entry.
- **Fine-grained locks per subsystem (journal, sessions, policy).** Larger
  refactor, easier to introduce TOCTOU between policy and spawn. Deferred.
- **Reader-writer lock.** Child waits are not reads of shared state; they
  still need exclusive mutation at finalize. An RW lock would not remove
  the need for the admit/execute/finalize split.
