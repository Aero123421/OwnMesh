# OwnMesh schemas and fixtures

This directory holds machine-readable schemas, shared fixtures, and example
configuration. Two kinds of artifact live here and they are **not**
interchangeable: some are validated contracts that both implementations honor,
and some describe the target specification and are not what the shipped code
reads.

Check which list an artifact is in before treating it as authoritative.

## Validated contracts

These are exercised by tests in both languages. A change here must keep the Rust
and TypeScript sides agreeing.

| Artifact | Enforced by |
| --- | --- |
| `schemas/domain-ids.schema.json` | `packages/ownmesh-schema` `schema-files.test.ts` |
| `schemas/domain-entities.schema.json` | `ownmesh-domain` `schema_validates_domain_fixtures`, `fixtures-roundtrip.test.ts` |
| `schemas/common-types.schema.json` | `packages/ownmesh-schema` `schema-files.test.ts` |
| `schemas/errors.schema.json` | `ownmesh-domain` error taxonomy tests, `errors.test.ts` |
| `schemas/protocol-envelope.schema.json` | `ownmesh-protocol` envelope tests, `fixtures-roundtrip.test.ts` |
| `schemas/operation-envelope.schema.json` | `ownmesh-protocol` operation contract tests |
| `schemas/workspace-registry.schema.json` | `ownmesh-protocol` registry schema test, `packages/ownmesh-schema` `schema-files.test.ts` — payload contract for `ready.workspace_registry` and the incremental `workspace.registry` refresh ([ADR 0014](../docs/adr/0014-agent-initiated-workspace-registry-refresh.md)) |
| `examples/fixtures/*.json` | Round-tripped by Rust and TypeScript against the schemas above |

## Specification targets (not shipped contracts)

These describe the design in `OWNMESH_SPECIFICATION.ja.md`. No shipped code
loads them, no test validates them, and the shipped implementation deliberately
differs. Do not derive a client, a config file, or a policy file from them.

| Artifact | What actually ships |
| --- | --- |
| `schemas/policy.schema.json` | The engine evaluates `ownmesh_policy::PolicyRule` (capability, `when_elevated`, `when_kind`, `path_prefix`, `program_equals`, `when_tag`), persisted by `ownmesh-config` as `PolicyFile` in `policy.toml`. The schema's `operation_classes` / `path_globs` / `principal_ids` model is not implemented. |
| `examples/policy.recommended.toml`, `examples/policy.full-access.toml` | Illustrations of the schema above. They are **not** loadable as a real `policy.toml`. Generate a real one with `ownmesh policy preset <name>`. |
| `schemas/config.schema.json` | `ownmesh-config` `OwnMeshConfig` is the shipped shape and validates itself. |
| `schemas/mcp-tool-catalog.json` | Generic MCP command, session, filesystem, transfer, and policy capability catalog. |
| `schemas/mcp-tool-catalog.json` | The shipped catalog is `MCP_TOOLS` in `packages/control-plane/src/mcp.ts`; `tools/list` publishes `PUBLISHED_MCP_TOOLS`. See [ADR 0004](../docs/adr/0004-mcp-tool-naming-and-aliases.md). |
| `examples/ownmesh.example.toml` | Illustrative only; `ownmesh setup` writes the authoritative file. |

Moving an artifact from the second table to the first means adding a test that
validates the shipped shape against it — not editing this README.

Related prose documentation:

- `OWNMESH_SPECIFICATION.ja.md`
- `docs/SECURITY_REVIEW_CHECKLIST.md`

Architecture decisions live under `/docs/adr/`.
