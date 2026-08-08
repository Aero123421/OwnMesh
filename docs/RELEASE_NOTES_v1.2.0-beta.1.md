# OwnMesh v1.2.0-beta.1 — E0 contract freeze

This internal beta gate freezes the versioned operation-envelope/payload
contract needed by later v1.2 transport and routing work. It is not a public
production-complete claim and does not enable remote execution.

## E0 scope

- Preserve the outer `ownmesh.device/1.0` envelope and add the independently
  versioned `ownmesh.operation/1.0` payload contract.
- Define fail-closed request, progress, event, and terminal result payloads in
  Rust and TypeScript.
- Bind every operation envelope with
  `correlation_id == payload.operation_id`; require request expiry and
  idempotency; reject unknown fields and cross-runtime unsafe counters.
- Reserve optional `workspace_id` in the request contract without claiming E4
  propagation or policy enforcement.
- Validate four shared golden fixtures in Rust and TypeScript, including JSON
  Schema validation and typed round-trip equality.

## Explicit non-claims

- E1 Agent WSS transport, E2 remote routing, E3 durable hash-bound approval,
  E4 workspace enforcement, and E5 cloud PTY sessions are not completed here.
- The CLI contract remains **32 explicit unsupported CLI surfaces** plus 7
  additional hard-error surfaces (**39 total**), recorded in
  [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json).
- No supported surface is promoted based on parser/schema/fixture presence.
- Existing custody, no-hidden-fallback, policy composition, telemetry defaults,
  Minisign, SBOM, and provenance gates remain unchanged.

See [`docs/V1.2_E0_OPERATION_CONTRACT.md`](./V1.2_E0_OPERATION_CONTRACT.md) for
the frozen fields and invariants.
