# OwnMesh v1.2.0-beta.9

## Summary

Integrity visit focused on Terra blockers for E3 principal binding, E4 session
workspace enforcement, and E5 ordered controller input. ChatGPT remains the
primary operational UI via public MCP; no second OwnMesh approval UI is required
for normal use after device setup.

Unsupported surface contract (authoritative):
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**32 explicit unsupported CLI surfaces** plus 7 additional hard-error surfaces
(**39 total**). Those surfaces remain excluded from completeness claims.

## Production path changes

### E3 — remote principal binding + minimal team operate

- After `authorization.bound_action` verification, ownmeshd runs side effects as
  `client:remote:<tenant_id>:<principal_id>` (never a single device-wide
  remote-agent principal).
- Local op-journal receipts are namespaced by that principal so colliding
  idempotency keys cannot cross callers.
- Minimal `tenant_members` (owner/admin/member) plus `canOperateDevice` allow
  same-tenant members to call MCP device tools and receive `session.give`
  handoffs. Device Agent enrollment remains owner-bound.
- `session.give` normalizes bare principal ids into the remote runtime namespace
  under the controller's tenant.

### E4 — session workspace list/show bind

- `ownmesh_session_list` requires `workspace_id`.
- List filters to that workspace; show rejects mismatched binds.
- Remote MCP cannot omit workspace on list/show (no cross-workspace metadata leak).

### E5 — ordered controller input/resize

- MCP requires monotonic `input_seq` / `resize_seq` (start at 1) on write/resize.
- ownmeshd persists last-applied values and rejects gaps and stale sequences
  under the runtime lock.
- Public two-principal handoff proof: non-controller denial, give, next-seq write.

## Proof

`scripts/tests/test_e2_workerd_loopback.py` covers workspace list/show isolation,
input_seq gap/stale/accept, two-principal non-controller denial, handoff, and
cross-principal operation non-leak via public `/mcp`.

## Still open (gate remains RED)

- E4 CLI workspace CRUD + full custody matrix promotion
- E5 full controller lease reconnect matrix
- E6 nine official profile adapters
- E7 bounded unified-diff apply + Git review flow
- E8 networkless elevated broker mint/custody
- E9 authenticated resumable transfer
- E10 live ChatGPT + Cloudflare account proof
