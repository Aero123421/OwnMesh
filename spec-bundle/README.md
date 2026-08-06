# OwnMesh specification bundle (extracted)

This directory holds the machine-readable and example materials from
`ownmesh-specification-bundle.zip`, plus pointers used by implementation tickets.

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
└── docs/
    ├── ADR_TEMPLATE.md
    └── SECURITY_REVIEW_CHECKLIST.md
```

Authoritative prose specifications remain at the repository root:

- `OWNMESH_SPECIFICATION.ja.md`
- `IMPLEMENTATION_CHECKLIST.md`
- `SECURITY_REVIEW_CHECKLIST.md`

ADRs for the live repository live under `/docs/adr/` (not only here).
