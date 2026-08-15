# OwnMesh v1.2.12

OwnMesh v1.2.12 is a stable workspace-activation and transfer-correctness
release. It keeps the v1.2 product surface, OAuth/passkey model, MCP protocol,
and Control Plane storage schema unchanged. The machine-checked contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Fixed

- A newly registered workspace can appear in `workspace_list` only as
  `pending_activation` until the Agent advertises an opaque local generation.
  Command and filesystem tools refuse that id with
  `OWNMESH_E_WORKSPACE_PENDING_ACTIVATION` and `next_action: retry_activation`
  instead of a bare `workspace_not_available`.
- Completed `workspace.add` / `workspace.list` results observe that generation
  immediately, so Agent reconnect is no longer required for the first successful
  use. Missing the workspace from a later ready snapshot still does not cancel a
  pending cloud reservation.
- `workspace_root_enforcement` is labeled independently of `access_preset`.
  Switching to Full Access updates the observed enforcement flag without waiting
  for the next Agent handshake, and absolute Full Access paths remain
  `workspace_id: null`.
- Fresh-passkey `approval_required` results always persist a same-origin
  `approval_url` (`/approve?operation_id=...`). The CLI no longer fails with
  `OWNMESH_E_BAD_ENVELOPE: approval response omitted approval_url`.
- Linux device enrollment reads the OS hostname (uname / `/etc/hostname`)
  instead of defaulting to `unknown-host`. Interactive enroll prompts when the
  candidate would still be generic.

## Reliability

- Transfer plan/send/status expose typed `next_action` semantics and advance
  send as far as durable child results allow.
- Non-terminal transfers expire on status, send, and list, including after a
  missed alarm.
- The immutable transfer source is revalidated at the send/ticket boundary and
  again on source start admission.
- The TUI Devices screen refreshes the authenticated Control Plane inventory on
  an explicit `r` keypress without background polling.

## Compatibility and migration

- No D1 migration is required.
- Existing OAuth clients, passkeys, refresh tokens, enrolled devices,
  workspaces, policies, sessions, transfers, and ChatGPT connectors remain
  compatible.
- Operators should redeploy the Control Plane so `/health` and MCP advertise
  version `1.2.12`. Existing Agents remain compatible; workspace activation is
  fastest when both sides are on this release.

## Upgrade

1. Run `ownmesh update` or install the signed v1.2.12 archive.
2. Deploy the v1.2.12 Control Plane.
3. Confirm `/health/ready` and run `ownmesh doctor --check-network`.

The v1.2.11 release notes remain available for the previous stable update.
