# OwnMesh v1.2.0-beta.11

## Highlights

1. **Handle-held directory listing (E4)** — Restricted workspace directory
   enumeration retains the validated directory descriptor through the side-effect
   boundary. A rename of the checked path to an outside symlink/junction fails
   closed (regression covered).
2. **PTY mutation at-most-once (E5/E3)** — When a controller `input_seq` /
   `resize_seq` is left `Pending` after an uncertain final persist, retries do
   **not** re-write the live PTY. Callers receive an explicit conflict/uncertain
   error and must reconcile before advancing with a new sequence.
3. **Workspace CRUD (E4)** — Device-local workspace registry is configurable via
   CLI, ownmeshd IPC, and ChatGPT MCP tools (`ownmesh_workspace_list|show|add|
   update|remove`). Ownership remains the authenticated device/tenant path;
   `ws_default` is protected.

## Still open

- E6 nine profile adapters on the remote production path
- E7 bounded unified-diff apply + full review flow
- E8 networkless elevated broker Full Access mint/custody
- E9 authenticated resumable transfer
- E10 live ChatGPT + Cloudflare account proof

The E2–E9 workerd gate stays **red** until every row is evidenced.

## Surface registry

[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json) records
**27 explicit unsupported CLI surfaces** and **34 total** unsupported surfaces
after promoting device-local workspace CRUD. Profile/transfer/broker install
remain unsupported. Completeness claim remains false.

