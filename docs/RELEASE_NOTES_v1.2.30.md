# OwnMesh v1.2.30

OwnMesh v1.2.30 fixes repeated ChatGPT authentication expiry for the stable
ChatGPT CIMD client. The shipped tool and device capability surface is
unchanged.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Persistent ChatGPT authorization

- ChatGPT's stable CIMD client ID
  `https://chatgpt.com/oauth/client.json` and callback
  `https://chatgpt.com/connector_platform_oauth_redirect` are now recognized as
  an exact trusted pair for refresh-token issuance.
- OwnMesh issues a rotating refresh token for that pair even when ChatGPT omits
  the optional `offline_access` scope. This prevents the connector from losing
  authorization when the 15-minute access token expires.
- Matching remains fail-closed and exact. Lookalike client IDs, callback path
  changes, and trailing-slash variants are not treated as ChatGPT.
- Legacy ChatGPT dynamic registration remains supported.

## Verification

- Added table-driven coverage proving both stable CIMD and legacy dynamic
  registration receive access and refresh tokens without `offline_access`.
- Added negative tests for a lookalike client ID and a non-exact callback.
- Control-plane tests, TypeScript type checking, lint, Wrangler dry-run, Rust
  metadata/format/Clippy, and release-quality checks pass. Cross-platform Rust
  build and test gates are enforced by CI.

The current OpenAI authentication contract is documented in
[Authentication — Plugins](https://developers.openai.com/plugins/build/auth).
