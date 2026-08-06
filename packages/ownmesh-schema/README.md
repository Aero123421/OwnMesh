# @ownmesh/schema

TypeScript domain types, stable ID parsers, protocol envelope helpers, and
shared-fixture round-trip tests for OwnMesh.

Fixtures live in `spec-bundle/examples/fixtures` and are shared with the Rust
crates `ownmesh-domain` and `ownmesh-protocol`.

```bash
pnpm --filter @ownmesh/schema test
pnpm --filter @ownmesh/schema typecheck
```
