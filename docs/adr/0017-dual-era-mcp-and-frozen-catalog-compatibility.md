# ADR 0017: Dual-era MCP and frozen catalog compatibility

- Status: Accepted
- Date: 2026-08-28
- Deciders: OwnMesh maintainers

> Amendment (2026-09-01): [ADR 0018](./0018-generic-external-cli-sessions.md)
> intentionally ends catalog-v1 callable compatibility and establishes the
> removed-Profile catalog-v2 baseline. The dual MCP transport decision below
> remains accepted; catalog v1 is historical release evidence only.

## Context

OwnMesh shipped the initialization-based MCP revision `2025-03-26`. The current
stable MCP specification is now `2026-07-28`; the official
[`/specification`](https://modelcontextprotocol.io/specification) redirect and
[2026-07-28 changelog](https://modelcontextprotocol.io/specification/2026-07-28/changelog)
were re-verified on 2026-08-28. The modern revision removes protocol sessions
and initialization, requires per-request metadata and mirrored HTTP headers,
adds `server/discover`, `resultType`, and cache hints, and assigns typed errors
for header mismatch and unsupported versions.

A flag-day replacement would break deployed ChatGPT and other clients. A second
compatibility problem is independent of MCP transport: OpenAI's current
first-party plugin documentation says developer-mode connections can be
refreshed manually, while published MCP plugins use reviewed metadata
snapshots. Updating the server does not update an approved snapshot; publishers
must scan, submit, and publish a new metadata version. Returning 404 for a stale
legacy MCP session therefore cannot make a published snapshot acquire new tool
definitions.

## Decision

### One registry and authorization path, two protocol adapters

`MCP_TOOLS`, its canonical published view, scope mapping, action binding,
operation envelope, device policy route, and invocation handlers remain the
single source of truth.

The HTTP boundary selects one of two adapters:

| Era | Version | Contract |
| --- | --- | --- |
| Legacy | `2025-03-26` | `initialize`, optional `Mcp-Session-Id`, JSON text compatibility, catalog-revision session fencing |
| Modern | `2026-07-28` | stateless requests; required `_meta`, `MCP-Protocol-Version`, `Mcp-Method`, and applicable `Mcp-Name`; `server/discover`; `resultType`; no protocol session |

Modern header/body mismatch is HTTP 400 / `HeaderMismatch` (`-32020`). An
unsupported version is HTTP 400 / `UnsupportedProtocolVersion` (`-32022`) with
the supported list. Unknown modern methods are HTTP 404 / `-32601`. Results
carry request-local server identity; cacheable discovery/list results carry
`ttlMs` and `cacheScope`. No Worker-isolate or prior-request state is authority.

DCR remains for legacy clients and current ChatGPT interoperability, but is
now explicitly the compatibility fallback. The authorization server advertises
and validates Client ID Metadata Documents (CIMD) using bounded, no-redirect,
credential-free HTTPS retrieval after owner authentication. Authorization
responses include RFC 9207 `iss`; redirect matching, issuer/resource binding,
PKCE S256, and refresh rotation remain unchanged.

### Frozen catalog contract

Catalog version 1 has these compatibility rules:

1. Existing tool names remain accepted by `tools/call` for the 1.x window,
   including deprecated aliases hidden from the latest `tools/list`.
2. Additive tools and optional fields are compatible.
3. A new required field, removal/change of an existing property, effect-hint
   change, or removal from `tools/call` is breaking. CI compares the current
   registry with `release/mcp-catalog-baseline-v1.json` and rejects it.
4. `catalog_version`, digest, compatibility range, and selected surface are
   exposed in bounded discovery metadata.
5. A published ChatGPT plugin metadata change requires **Scan Tools → submit a
   new version → publish the approved version**. Server session invalidation is
   only a legacy transport recovery mechanism.

The default endpoint remains the complete backward-compatible catalog. Optional
`?surface=core`, `?surface=admin`, and `?surface=agents` endpoints expose and
enforce smaller capability-oriented registries. A call outside the selected
surface is rejected; hiding alone is never treated as authorization.

## Consequences

- Existing clients continue to initialize and invoke old names.
- Modern clients are stateless and can use a Worker instance different from the
  one that answered a previous request.
- Tool implementation and authorization logic are not duplicated between eras.
- Published plugin snapshots remain usable against additive server releases,
  but do not see additions until the publisher completes OpenAI's metadata
  version workflow.
- `subscriptions/listen`, MCP resources/prompts, and optional extensions are not
  claimed. `listChanged` remains false; the deterministic short TTL is the
  modern refresh hint.

## References

- MCP 2026-07-28 versioning and dual-era matrix:
  <https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning>
- MCP Streamable HTTP headers and stateless compatibility:
  <https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http>
- MCP caching:
  <https://modelcontextprotocol.io/specification/2026-07-28/server/utilities/caching>
- MCP client registration:
  <https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration>
- OpenAI connection refresh and published snapshots:
  <https://developers.openai.com/plugins/deploy/connect-chatgpt>
- OpenAI published metadata versions:
  <https://developers.openai.com/plugins/deploy/submission#how-published-mcp-metadata-versions-work>
