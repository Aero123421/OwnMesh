# Claude Code plugin: OwnMesh (experimental)

Status: experimental, unverified live. Compatibility row and receipt format:
`docs/client-compatibility.md`. Endpoint contract: `docs/mcp-clients.md`.

This plugin ships configuration placeholders only. It never contains a Worker
URL, token, device ID, or private path, and installing it never
auto-authorizes or silently enables destructive tools.

## Prerequisites

- OwnMesh control plane deployed to your Cloudflare account.
- `OWNMESH_WORKER_URL` set to your Worker origin, for example:

  ```bash
  export OWNMESH_WORKER_URL="https://<your-worker>"
  ```

## Option A: direct setup (no plugin install)

```bash
claude mcp add --transport http ownmesh "$OWNMESH_WORKER_URL/mcp"
claude mcp login ownmesh
```

Complete OAuth in the browser (owner sign-in, explicit scope consent).
Request the narrowest scopes the task needs (`ownmesh.read` first;
add `ownmesh.write` / `ownmesh.exec` / `ownmesh.session` / `offline_access`
only when required). `offline_access` is needed for rotating refresh tokens.

## Option B: shareable `.mcp.json`

Copy `.mcp.json` from this directory. It contains only
`${OWNMESH_WORKER_URL}/mcp` and no secrets. Each user exports their own
`OWNMESH_WORKER_URL`, then runs `claude mcp login ownmesh`.

## Option C: install this plugin

Install through Claude Code's plugin flow and then run
`claude mcp login ownmesh` manually. Installation alone performs no OAuth
and grants nothing: the first authenticated call still requires the
explicit browser consent above.

## Guard example

Keep the endpoint a placeholder and prove it before sharing:

```bash
grep -rE 'OWNMESH_WORKER_URL' .mcp.json
# expected: "${OWNMESH_WORKER_URL}/mcp" only — no token, device ID, or private path
```

Never paste tokens, device IDs, or private paths into shared files.

## Owner-provisioned fallback

If automatic registration is unavailable in your environment, the owner
provisions a client per `docs/mcp-clients.md` (route 1 or authenticated
DCR route 2) and you log in against that client ID. Do not paste tokens
or device IDs into shared files.

## Timeout and catalog notes

- Per-server tool/idle timeouts apply client-side. For long work pass
  `async: true` (or `detach: true`) and poll `ownmesh_get_operation`.
- If tools look stale or disappear, re-initialize and compare
  `catalog_revision` (`GET /mcp` vs `tools/list`) before changing anything.

## Safety

Every write/exec/session call needs explicit user confirmation plus a
passing device policy. Claude's approval UI is not device authorization;
an `ask` result stays `approval_required` until the owner approves via
TUI/CLI or the recovery page.
