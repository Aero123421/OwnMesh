# OwnMesh v1.2.0-beta.2 — E1 Agent transport candidate

This internal beta candidate adds the authenticated Agent WebSocket transport
on top of the E0 operation contract. It is not a production-complete release.

## Included

- Active-instance `ownmeshd` connection to `/agent/connect` using the stored,
  issuer/device-bound credential.
- Ed25519 challenge proof and explicit protocol selection.
- Rustls/native-root TLS, 1 MB inbound bounds, heartbeat, capped reconnect, and
  shutdown coordination.
- Durable outbound/inbound sequence state, bounded message replay protection,
  reconnect resume metadata, and correlation-result deduplication.
- Real debug `ownmeshd` binary × local Wrangler/workerd coverage provisions an
  isolated native keychain identity and temporary D1, then proves authenticated
  ready and durable sequence resume across a process restart.
- Native `keyring` 3.x backends are enabled for Windows Credential Manager,
  macOS Keychain, and Unix Secret Service; without an enabled store the crate
  selects its process-local mock backend.
- Explicit E2 fail-closed behavior: no remote request reaches the local runtime.

## Open gates

- Live-account E2E.
- Fresh independent E1 security sign-off after the remaining runtime gate.
- E2 remote fs/command routing and operation tracking.

No entry is removed from `release/SUPPORTED_SURFACES.json`; its **32 explicit unsupported CLI surfaces** and 39 total hard-error surfaces remain unchanged.
