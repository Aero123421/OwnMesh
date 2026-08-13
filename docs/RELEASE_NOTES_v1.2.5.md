# OwnMesh v1.2.5

OwnMesh v1.2.5 is a stable reliability and authentication-UX patch. It keeps
the v1.2 supported surface and protocol contract unchanged. The machine-checked
contract remains [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Improvements

- Authenticated remote operation polling now runs at a control-plane-safe
  interval. HTTP 429 responses honor a bounded `Retry-After` value while the
  original operation deadline remains authoritative.
- The TUI always offers **Re-authenticate** for a recorded account. This fixes
  recovery when the non-secret session marker remains but the OS credential
  store entry was removed, expired, or became unreadable.
- Owner passkey login, ChatGPT OAuth consent, and device authorization now use
  the selected browser language for their primary UI in English, Japanese,
  Simplified Chinese, and Russian.
- Passkey login explains the headless `ownmesh login --device` path and the
  explicit deployment-owner recovery command when every passkey is lost.
- Device authorization now offers both **Authorize** and **Deny**. Either
  decision consumes the same short-lived, CSRF-protected, principal-bound
  transaction exactly once; a denied device code terminates with
  `access_denied` and cannot receive tokens.

## Security and compatibility

- No credential is copied into TUI state, configuration files, URLs, logs, or
  release output. Re-authentication delegates to the existing OS-keychain-aware
  device flow.
- OAuth client, redirect, scope, tenant, principal, expiry, and CSRF bindings
  are unchanged. The new deny path uses the existing atomic D1 transaction.
- Existing Cloudflare D1 data, OAuth clients, passkeys, refresh tokens,
  enrolled devices, protocol version 1, policies, workspaces, sessions, and
  transfers remain compatible. No D1 or local-state migration is required.
- Large authority-bearing modules remain a documented maintenance item rather
  than being riskily restructured in a patch release.

## Upgrade

1. Upgrade local binaries with the signed installer or release archive.
2. Redeploy the control plane to expose localized browser pages, device denial,
   and service version `1.2.5`.
3. Existing machines and ChatGPT connectors do not need to be re-enrolled.

The v1.2.4 release notes remain available for the previous stable patch.
