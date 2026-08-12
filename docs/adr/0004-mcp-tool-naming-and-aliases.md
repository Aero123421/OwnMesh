# ADR 0004: MCP tool naming and compatibility aliases

- Status: Accepted
- Date: 2026-08-12
- Deciders: OwnMesh maintainers

## Context

`OWNMESH_SPECIFICATION.ja.md` §14.2–14.3 specifies MCP tool names in a
verb-first form and lists a catalog built that way: `ownmesh_read_file`,
`ownmesh_run_command`, `ownmesh_open_session`, `ownmesh_close_session`.

The shipped catalog in `packages/control-plane/src/mcp.ts` uses a noun-first
form instead — `ownmesh_fs_read`, `ownmesh_command_run`, `ownmesh_session_open`,
`ownmesh_session_close` — and carries only six of the specified names as
aliases. The divergence grew during implementation without a decision record,
so the specification and the shipped surface disagreed on the catalog and
neither was clearly authoritative.

Two forces drove the drift:

1. The catalog reached ~50 tools. Verb-first names scatter related tools across
   an alphabetically sorted list, so `tools/list` no longer grouped the session
   surface, the filesystem surface, or the transfer surface together. Noun-first
   names sort into their capability family, which is how a model scanning the
   list actually navigates it.
2. Some pairs were published twice with byte-identical `inputSchema`,
   `annotations`, `scope`, and `risk`, differing only in prose. That gave the
   model no basis to choose between them while doubling the schema bytes on
   every request, and several of the duplicated pairs were `destructiveHint:
   true` exec tools, so the ambiguity was not merely a context cost.

## Decision

1. **Noun-first names are canonical.** `ownmesh_<family>_<verb>` is the naming
   rule for new tools: `ownmesh_fs_read`, `ownmesh_session_open`,
   `ownmesh_transfer_plan`. The `ownmesh_` prefix and snake_case from §14.2 are
   unchanged.
2. **Specified verb-first names remain callable as aliases.** `MCP_TOOLS`
   retains them so `tools/call` never breaks a client written against the
   specification or against an earlier release.
3. **Aliases are withheld from `tools/list`.** `PUBLISHED_MCP_TOOLS` filters
   entries carrying `aliasOf`. Advertising both halves of an identical pair is
   the failure mode this ADR exists to prevent.
4. **§14.2–14.3 of the specification are updated** to record the naming rule and
   to mark the aspirational catalog entries that are not shipped.

## Consequences

- Clients written against the specification's names keep working through
  `tools/call`, but a client that enumerates `tools/list` sees only canonical
  names. That is the intended behavior and is documented in
  [`mcp-clients.md`](../mcp-clients.md).
- Adding a tool now requires choosing its family prefix. Where a family does not
  exist yet, prefer creating one over reaching for a verb-first name.
- The alias list is frozen. New aliases are not accepted: they reintroduce the
  ambiguity this decision removed. Renaming a tool means a new canonical name
  plus one alias, not a growing set.
- `spec-bundle/schemas/mcp-tool-catalog.json` continues to hold the
  specification's catalog including entries that are not implemented; it is a
  target document, not the shipped contract. The shipped contract is
  `MCP_TOOLS`.

## Alternatives considered

**Rename the implementation back to the specification's names.** Rejected: it
would break every deployed client for a naming preference, and it would restore
the alphabetical scattering that motivated the change.

**Publish both names and let the model choose.** Rejected: this was the prior
state. Identical schemas with different names measurably wasted context and
created ambiguity between destructive exec tools.

**Drop the aliases entirely.** Rejected: a client written against the published
specification would break with no migration path. Keeping them callable costs
nothing at request time because they are not advertised.
