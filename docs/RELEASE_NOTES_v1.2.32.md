# OwnMesh v1.2.32

OwnMesh v1.2.32 prevents benign duplicate OAuth refresh requests from
invalidating ChatGPT's newly issued credentials while preserving fail-closed
reuse detection.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Bounded refresh retry convergence

- A refresh rotation atomically stores one encrypted receipt for 60 seconds.
- Concurrent exact requests and response-loss retries return the same successor
  access/refresh token pair; no second successor is minted.
- The receipt is bound to the old refresh token, token family, client,
  principal, tenant, scope, and resource/audience context.
- Receipt ciphertext is protected with AES-256-GCM using key material derived
  from the presented old refresh token. Token plaintext and hashes are not
  written to logs or audit summaries.
- Expired receipts, binding mismatches, and old-token reuse after the family
  advances continue to revoke the entire family fail-closed.

## Cloudflare migration

- Migration `0021_refresh_rotation_receipts.sql` adds the bounded D1 receipt
  table and its expiry index.
- Receipt cleanup is TTL-bounded and indexed; the fix does not introduce an
  unbounded token history.

## Verification

- MemoryStore and SqlStore/D1 conformance tests cover concurrent refresh,
  response-loss retry, expiry, binding mismatch, and advanced-family reuse.
- The complete TypeScript suite, Rust cross-platform CI, dependency audits,
  SAST, secret scanning, SBOM, and release-quality gates are required before
  publication.
