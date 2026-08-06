# ownmesh-domain

Domain types, stable identifiers, shared models, error taxonomy, and exit codes for OwnMesh.

## Modules

- **IDs** — `ten_`, `prin_`, `mem_`, `dev_`, `ws_`, `grant_`, `rule_`, `apr_`, `op_`, `sess_`, `aud_`, `msg_`, `cur_`, `pol_`
- **Entities** — Tenant, Principal, Membership, Device, Workspace, CapabilityGrant, PolicyRule, Approval, Operation, Session, AuditEvent
- **Time / pagination** — `Timestamp`, `Expiry`, `Cursor`, `PageRequest`, `Page`
- **Errors** — `ErrorCode` (`OWNMESH_E_*`), `ExitCode` (0/2–9), `DomainError`, MCP error envelope

Shared JSON fixtures: `spec-bundle/examples/fixtures/`.
JSON Schemas: `spec-bundle/schemas/`.

```bash
cargo test -p ownmesh-domain
```
