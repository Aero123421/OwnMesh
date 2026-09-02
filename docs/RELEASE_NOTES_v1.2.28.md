# OwnMesh v1.2.28

OwnMesh v1.2.28 restores ChatGPT OAuth linking after ChatGPT adopted the
current Client ID Metadata Document (CIMD) token-authentication capability
format. The shipped tool and device capability surface is unchanged.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## ChatGPT OAuth compatibility

- OwnMesh now reads `token_endpoint_auth_methods_supported` as the
  authoritative CIMD capability list when it is present.
- ChatGPT may keep `private_key_jwt` as its legacy singular preference while
  also advertising `none` in the plural capability list. OwnMesh selects only
  the shared `none` method because its token endpoint remains a public client
  with PKCE S256.
- Legacy CIMD documents that publish only
  `token_endpoint_auth_method: "none"` remain compatible.
- Documents without a public-client intersection still fail closed. Redirect
  URI exact matching, bounded/no-redirect metadata fetches, owner authentication,
  consent snapshots, and metadata revalidation remain unchanged.

## Verification

- Added a regression fixture matching ChatGPT's current production CIMD,
  including the plural method list and the legacy singular preference.
- Added a negative case proving that a confidential-only capability list is
  rejected even if a conflicting legacy field claims `none`.
- Control-plane tests, TypeScript type checking, lint, release-quality checks,
  and the live ChatGPT metadata probe pass for this release.

The current OpenAI authentication contract is documented in
[Authentication — Plugins](https://developers.openai.com/plugins/build/auth).
