# OwnMesh v1.2.16

OwnMesh v1.2.16 is a security release for approval-bound executable identity
and the final verify-to-spawn boundary. Users who allow or approve command
execution should upgrade promptly. It preserves the v1.2 product surface,
OAuth/passkey model, MCP protocol, policy defaults, and Control Plane storage
schema. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Security fixes

- **[GHSA-46j2-vr92-gfcw](https://github.com/Aero123421/OwnMesh/security/advisories/GHSA-46j2-vr92-gfcw): executable drift now fails closed.** An approved structured command keeps
  its exact invocation entry, backing executable identity, classification, and
  `argv[0]`. If a proxy, shim, symlink, reparse target, or backing object changes
  before execution, OwnMesh returns `OWNMESH_E_EXECUTABLE_IDENTITY_DRIFT` and
  requires a fresh request and approval. It never substitutes the canonical
  backing executable for a changed invocation.
- **[GHSA-2qvv-5qjm-c48w](https://github.com/Aero123421/OwnMesh/security/advisories/GHSA-2qvv-5qjm-c48w): verification is bound to the image opened for execution.** Generic and
  review commands consume a non-cloneable prepared executable whose verified
  image remains under custody through spawn. Linux executes a sealed anonymous
  image, macOS uses an owner-only verified snapshot, and Windows holds target,
  proxy-entry, and ancestor handles without write/delete sharing until process
  creation completes. Raw-shell execution applies the same custody to the
  selected shell executable.

The first issue affects v1.2.13 through v1.2.15. The verify-to-spawn race affects
v1.1.0 through v1.2.15. Exploitation requires command authority or approval plus
the ability to mutate the executable path as the local user; this is not an
unauthenticated remote execution claim.

## Verification evidence

- A deterministic multicall fixture verifies that unchanged proxy semantics
  execute exactly once and that deletion, replacement, and retargeting never
  start the backing behavior.
- Deterministic post-prepare tests cover atomic replacement, same-size content
  replacement, in-place write/truncate, parent-directory replacement, Unix
  symlinks, and Windows junction/reparse custody.
- The stable error is aligned across Rust domain/IPC/CLI, TypeScript schemas,
  and the JSON error schema. ADR 0013 records the platform design and its
  narrowly scoped Linux launcher `unsafe` boundary.

## Compatibility and migration

- No D1 migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- A command waiting for approval across the upgrade may receive executable
  identity drift and must be submitted again. This is intentional fail-closed
  behavior.
- macOS binaries that require resources relative to their physical executable
  directory can fail closed under private-snapshot execution; use a stable
  launcher that does not depend on that layout.
- Authenticode, Apple notarization, MSI/NSIS, and native macOS packages remain
  out of scope.

## Upgrade

1. Run `ownmesh update` or install the signed v1.2.16 archive.
2. Restart the user service if the updater does not do so automatically.
3. Confirm `/health/ready` and run `ownmesh doctor --check-network`.

The v1.2.15 release notes remain available for the previous stable patch.
