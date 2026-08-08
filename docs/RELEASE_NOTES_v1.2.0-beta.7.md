# OwnMesh v1.2.0-beta.7

## Summary

Worker visit advancing E2 surface completeness, E4 workspace selection/custody,
bounded Git I/O, and partial E5/E7 remote mappings. The mandatory
`test_v12_e2_e9_workerd_loopback.py` gate remains **RED** (exit 2): partial
rows are not completion.

## Production path evidence

Public MCP → local Wrangler/workerd → DeviceRoom → Agent WSS → ownmeshd:

- Filesystem list/stat/read/write/**patch**/delete
- Structured command + **raw shell**
- Binary range + 512 KiB multi-chunk read
- Resume / idempotency / cancel / required-key fail-closed
- **workspace_id** selection (`ws_default` / `ws_alt`) with cross-root denial
- **session.open** (metadata + controller lease; live PTY host still partial)

## Custody / bounds

- Hardlink and cross-mount fail-closed in restricted mode
- Directory pagination past 4_000+ entries without silent omission
- Git capture streamed with stdout/stderr ceilings

## Explicitly not claimed

- CLI `workspace` / `profile` / `transfer` CRUD (registry unsupported)
- Full cloud PTY host ownership + reconnect proof (E5 incomplete)
- Nine profile adapters (E6)
- Unified-diff apply + full Git review product flow (E7 incomplete)
- Elevated broker mint / Full Access completion (E8)
- Resumable authenticated transfer protocol (E9)
- Live ChatGPT + Cloudflare account E10

Unsupported surface registry remains fail-closed:
**32 explicit unsupported CLI surfaces** and **39 total** unsupported
surfaces per [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).
No surface is promoted from parsers, schemas, markers, or unit tests alone.

## Docs

- [`docs/V1.2_E4_WORKSPACE_CUSTODY.md`](./V1.2_E4_WORKSPACE_CUSTODY.md)
- [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json)
