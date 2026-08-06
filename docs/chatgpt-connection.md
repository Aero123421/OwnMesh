# Connecting ChatGPT to OwnMesh

## Overview

ChatGPT (normal Chat) connects to **your** OwnMesh control plane via Streamable HTTP MCP + OAuth.

```
ChatGPT → https://<your-worker>/mcp → Durable Object device room → ownmeshd on your PC
```

## Checklist

1. Control plane deployed ([deploy-cloudflare.md](./deploy-cloudflare.md))
2. Local agent running: `ownmeshd run`
3. Device enrolled: `ownmesh device enroll --issuer https://<your-worker>`
4. Access preset chosen (Workspace Only → Full Access)
5. MCP URL added in ChatGPT as a Personal Plugin / remote MCP server

## Tools

See MCP catalog in the Worker (`tools/list`). Notable splits:

- `ownmesh_command_run` — structured argv (no shell)
- `ownmesh_command_shell` — raw shell (separate capability)
- Session tools support observer attach and controller claim/handoff

## Approvals

If policy decision is `ask`, MCP returns `approval_required`. Approve via TUI/CLI/browser one-time page before the device executes.

## Security

- Do not paste secrets into ChatGPT prompts and expect OwnMesh to treat them as policy.
- Prompt injection in tool outputs must not bypass local policy (enforced on device).
