# ADR 0012: Bounded tool grants and batch approval

- Status: Accepted
- Date: 2026-08-18
- Deciders: OwnMesh runtime maintainers

## Context

Every sensitive Ask currently needs a fresh, operation-bound human decision.
That binding is the right security design, but an approval-heavy policy makes
routine work a biometric or browser round-trip per tool call. Users then loosen
policy globally — a worse outcome than a short, explicit standing exception.

Temporary grants (`TemporaryGrant`, ADR 0006) cannot fill this gap:
`command.run` / `command.*` grants are refused outright, filesystem grants are
path-scoped from one approved operation, and there is no tool allowlist, use
count, or admin mint flow. Reusing that type would smuggle command reuse through
a constructor that was designed to forbid it.

The approval page is also one operation at a time. The owner presence cookie
binds a scalar `operation_id`, so a burst of pending Asks cannot share one
fresh user-verification.

## Decision

### 1. Bounded tool grants are a distinct stored type

`grants.json` remains the device-local grant file and keeps its existing byte
and entry budgets. Rows are a tagged union:

- Legacy rows with **no** `grant_type` deserialize as `TemporaryGrant`
  (unchanged ADR 0006 semantics, including the `command.*` refusal).
- Rows with `grant_type: "bounded_tool"` deserialize as `BoundedToolGrant`.
- Any other `grant_type` fails closed at load (daemon startup still fail-closed
  for `grants.json`; this is not the op-journal degraded path).

A bounded tool grant is minted only by a typed admin mutation using the same
fresh-passkey, exact-bound flow as `ownmesh_policy_preset`. It is never minted
from an ordinary `approval.approve --grant`. Required fields:

- `grant_type: "bounded_tool"`
- explicit tool allowlist (canonical names such as `command_run`; no `*`, no
  `capability.*` wildcards, no risk-class buckets)
- device id (the device that stores the row)
- optional workspace id
- hard TTL, server-clamped to ≤ 4 hours
- optional max-use count

Matching happens at the same policy-decision point as temporary grants, after
document evaluation:

- **Deny still wins.** A bounded grant never lifts a Deny (including
  recommended/workspace_only `command.run` until confinement). To use a
  `command_run` grant the document must Ask, not Deny.
- **Ask only.** A matching unexpired grant with remaining uses converts Ask to
  Allow for that principal, device, optional workspace, and listed tool.
  The request's canonical tool must also agree with the operation
  capability/kind (a client-supplied tool name cannot lift a different
  capability). Matching is fail-closed without the mint device id.
- Each Allow-via-grant consumes one use when `max_uses` is set; persist failure
  refuses the operation (fail-closed) rather than allowing an uncounted use.
- Lockdown clears **all** stored grants (temporary and bounded) as part of
  tightening. Revoke is local and immediate; minting remains a loosening
  mutation and stays on the fresh-passkey admin path.

### 2. Batch approval binds a set commitment

Single-operation `/approve?operation_id=` presence cookies (v1) stay valid.

A selected set of pending operations is bound by a v2 presence claim whose
`commitment` is SHA-256 of the canonical, sorted lines
`operation_id:payload_hash` (lowercase hex hash). The control plane looks up
hashes server-side; the client cannot supply them. Each decision is still
delivered and consumed per operation, exactly once.

Deny-all of the listed pending set requires no passkey assertion: denial has
no side effect. It still requires an independently authenticated human
session, CSRF, and same-origin POST.

Notification channels never carry approval authority.

## Consequences

- Approval fatigue has a middle path that does not weaken exact action binding
  or turn temporary grants into command reuse.
- Operators who stay on recommended/workspace_only still cannot grant
  `command_run` until they replace the Deny rule; that is intentional.
- Presence cookies are purpose-separated: v1 signs `operation_id`, v2 signs
  the set commitment, with distinct HMAC contexts so a v1 verifier cannot
  accept a v2 cookie.

## Alternatives considered

- **Reuse `TemporaryGrant` with a tool list.** Rejected: the type and
  constructor exist to forbid `command.*` reuse and to require a path scope
  from one approved file operation.
- **Lift Deny as well as Ask.** Rejected: Deny is the confinement/fail-closed
  document decision; a time-bounded overlay must not silently punch through it.
- **Notification-tap approve.** Rejected: notification channels must never
  carry approval authority.
