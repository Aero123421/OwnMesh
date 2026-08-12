# ADR 0008: Control-plane authorization is scopes plus action binding, not a second policy engine

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers

## Context

Two parts of the specification describe cloud-side authorization in a shape the
implementation does not have.

**§6.6 — OAuth scopes.** The specification defines fourteen scopes
(`devices:read`, `filesystem:read`, `filesystem:write`, `commands:run`,
`commands:shell`, `commands:elevated`, `sessions:control`, `policies:manage`,
`tenant:admin`, …) plus Observe / Develop / Full connection presets. The shipped
control plane defines six: `ownmesh.read`, `ownmesh.write`, `ownmesh.exec`,
`ownmesh.session`, `ownmesh.device`, and `offline_access`. In particular there is
no separate scope for raw shell or for elevated execution.

**§7.2 — policy composition.** The specification says cloud policy and local
policy are both evaluated and the most restrictive decision wins. The control
plane has no `PolicyDocument`. `ownmesh_policy::evaluate_combined` exists and
implements the composition, but nothing in the shipped runtime calls it: the
device evaluates one document.

Both divergences grew during implementation without a decision record, so the
specification reads as if a cloud policy engine exists.

## Decision

### 1. The device is the only policy engine

The control plane authorizes **who may ask** — a valid OAuth token, the scope
the tool declares, tenant/device ownership, and an operation bound to an exact
payload hash, device, expiry, and one-time execution state. It does not decide
**whether the action is permitted**. That decision belongs to `ownmeshd`, which
is the only component that can see the resolved path, the pinned executable
identity, the workspace custody result, and the operator's local preset.

This is stricter than §7.2's composition, not weaker: a cloud `allow` never
authorizes anything on its own, so there is no path where a compromised or
misconfigured control plane widens device authority. The composition §7.2
describes is what the device already performs between its preset rules, its
user-authored overlay rules, and its grants.

`evaluate_combined` is retained as the reference implementation of the
most-restrictive rule and is used by tests. Callers must not read its presence
as evidence that a cloud policy document is fetched or honored.

### 2. Six coarse scopes, with risk separated by tool and by device policy

Scopes are coarse capability families that a human can reason about on a consent
screen. Risk separation happens twice, and neither place is the scope:

- **Tool identity.** Raw shell is `ownmesh_command_shell`, distinct from
  `ownmesh_command_run`, with its own annotations. Elevation is an explicit
  `elevated: true` argument bound into the action hash. A client cannot reach
  either by accident.
- **Device policy.** `command.run` and `session.open` are denied outright under
  the restricted presets ([ADR 0007](./0007-restricted-presets-deny-command-execution.md)),
  and elevation additionally requires an installed, attested broker. A token
  carrying `ownmesh.exec` grants nothing on a device whose preset denies
  execution.

Fourteen scopes would imply a granularity the consent screen cannot usefully
convey and the device would override anyway. Fourteen scopes with the device
still holding final authority is worse than six: it suggests the token is the
control when it is not.

§6.6 of the specification is updated with an implementation-status note listing
the shipped scopes and this mapping.

### 3. Scope names are a stable wire contract

The `ownmesh.*` names are already registered in deployed OAuth clients, refresh
token families, and third-party MCP client configurations. Renaming them to the
specification's `family:verb` form would break every existing connector for a
cosmetic change, exactly as rejected in ADR 0004 for tool names.

Adding a scope remains possible and is a compatible change. Splitting an existing
scope is not, and requires a new ADR plus a migration path for issued tokens.

## Consequences

- Reviewing "can this client do X" means reading two artifacts, not one: the
  token's scopes and the device's preset. Documentation that presents scopes
  alone as the authorization answer is misleading, and
  [`mcp-clients.md`](../mcp-clients.md) states the two-layer rule explicitly.
- A future multi-tenant deployment that genuinely needs server-side restriction
  (an auditor who must not reach `ownmesh.exec` regardless of device policy) can
  add scopes without revisiting this ADR. A server-side *policy document* is a
  different decision and needs its own.
- `evaluate_combined` stays until either a cloud policy document exists or a
  cleanup removes it. Its doc comment records that it is currently unused by the
  runtime so the next reader does not infer a live cloud policy path.

## Alternatives considered

**Implement the fourteen specified scopes.** Rejected: it multiplies the consent
surface without moving any authorization boundary, because the device decides
regardless. The two cases that actually matter — raw shell and elevation — are
already separated where a client can see them, at the tool.

**Implement a cloud policy document and compose it.** Deferred. It is a real
feature for multi-admin tenants, and it is the only thing that would make §7.2
literally true. It is not needed for the single-owner deployment v1.2 targets,
and shipping a second policy engine that can only ever be overridden by the
first would add attack surface for no authorization gain.

**Delete §6.6 and §7.2 from the specification.** Rejected, consistent with ADR
0005: the goals are legitimate. They are marked as not-yet-shipped, with the
shipped mapping recorded, rather than deleted.
