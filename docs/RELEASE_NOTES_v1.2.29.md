# OwnMesh v1.2.29

OwnMesh v1.2.29 fixes ChatGPT OAuth linking on the production Cloudflare
Workers runtime. The shipped tool and device capability surface is unchanged.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Cloudflare CIMD compatibility

- ChatGPT identifies itself with the HTTPS CIMD URL
  `https://chatgpt.com/oauth/client.json` during OAuth authorization.
- Cloudflare Workers supports `follow` and `manual` for outbound `fetch`
  redirects, but not the browser/Node `error` mode. The previous mode threw a
  runtime `TypeError` before ChatGPT metadata could be read.
- OwnMesh now uses `manual` and rejects every redirect response as non-success.
  It does not follow `Location`, forward credentials, or loosen the existing
  16 KiB document bound, HTTPS client-id policy, exact redirect matching,
  public-client method intersection, owner authentication, or consent replay
  protections.

## Verification

- Added a regression assertion for the Cloudflare-compatible request mode.
- Added a negative test proving a 302 metadata response is rejected after one
  fetch without following the attacker-controlled destination.
- Ran the actual OwnMesh CIMD validator in a Cloudflare remote preview: the
  v1.2.28 implementation reproduced the Workers `TypeError`, while this release
  accepted ChatGPT's live production document.
- Control-plane tests, TypeScript type checking, lint, and release-quality
  checks pass for this release.

The current OpenAI authentication contract is documented in
[Authentication — Plugins](https://developers.openai.com/plugins/build/auth).
