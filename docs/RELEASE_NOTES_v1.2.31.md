# OwnMesh v1.2.31

OwnMesh v1.2.31 fixes completed device operation receipts accumulating until
the 4096-entry op-journal limit and bounds Cloudflare D1 audit retention.

The machine-checked shipped contract remains
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).

## Automatic journal recovery

- DeviceRoom acknowledges a terminal operation only after its authoritative D1
  result and outbound room sequence are durable.
- The Agent removes only a positively completed local receipt with the exact
  acknowledged operation id. In-progress, uncertain, malformed, missing,
  non-terminal, and foreign-device records are never removed.
- On reconnect, v1.2.31 Agents offer completed receipts in pages of at most 64,
  allowing an existing full journal to drain safely. Lost responses are retried
  on the next connection.
- The exchange is feature-negotiated, so newer Agents do not send the additive
  request to older control planes.

## Bounded D1 audit metadata

- Audit events default to 30-day retention and a 50,000-row per-tenant cap.
- A migration-maintained counter makes admission atomic without request-path
  `COUNT(*)` scans.
- Cleanup touches at most 128 rows through a retention index and is amortized by
  a per-tenant lease. Stored summaries are bounded as well.
- Operators may lower or raise the defaults with `AUDIT_RETENTION_DAYS` and
  `AUDIT_MAX_PER_TENANT`; hard ceilings prevent an accidental infinite setting.

## Verification

- TypeScript type checking and the complete control-plane suite pass.
- Rust test targets type-check, including rollback and fail-closed journal
  reconciliation coverage. Cross-platform execution remains enforced by CI.
- Wrangler configuration, migration application, release-quality, catalog, and
  packaging gates are enforced before publishing.
