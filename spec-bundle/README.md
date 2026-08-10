# OwnMesh schemas and fixtures

This directory is the source of truth for machine-readable schemas, shared
fixtures, and example configuration used by the Rust and TypeScript packages.

## Expected layout

```text
spec-bundle/
├── README.md                 (this file)
├── schemas/
│   ├── config.schema.json
│   ├── policy.schema.json
│   ├── profile.schema.json
│   ├── protocol-envelope.schema.json
│   └── mcp-tool-catalog.json
├── examples/
│   ├── ownmesh.example.toml
│   ├── policy.recommended.toml
│   ├── policy.full-access.toml
│   └── profile.custom.toml
```

Related prose documentation:

- `OWNMESH_SPECIFICATION.ja.md`
- `docs/SECURITY_REVIEW_CHECKLIST.md`

Architecture decisions live under `/docs/adr/`.
