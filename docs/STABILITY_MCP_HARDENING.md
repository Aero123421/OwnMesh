# Stability and MCP hardening status

**Released in:** v1.2.25 · **release review date:** 2026-09-01

This file records the evidence boundary for the hardening shipped in v1.2.25.
The authoritative shipped contract remains `release/SUPPORTED_SURFACES.json`;
the table below distinguishes implemented behavior from the work and external
receipts that remain open.

| Area | Status in v1.2.25 | Evidence / remaining boundary |
| --- | --- | --- |
| Non-elevated command lock scope | shipped | ADR 0015 and existing concurrency/cancel/finalization regressions |
| Elevated broker lock scope | implemented | Broker connect/wait/cancel/output/re-attestation now use captured request authority outside the runtime mutex. Native broker release receipts remain separate. |
| Session/PTY global lock scope | **partial** | Supervisor IPC is bounded (5 s) and session host/output custody is separate, but session open/transition methods still hold the runtime mutex across supervisor RPC. Per-session state ownership and 100-way session stress remain open. |
| Operation restart convergence | strengthened, **partial** | A loaded prior-process `in_progress` marker is durably classified `recoverable_orphaned`, surfaced as `OWNMESH_E_OPERATION_ORPHANED`, and never auto-retried. Generic command PID/birth identity is not journaled, so automatic process reattachment is not claimed. Session sidecars already use PID + birth identity and controller epochs. |
| Linux shebang custody | implemented | Script + interpreter compound pins, sealed interpreter/script memfds, proc-fd handoff, and a bounded Node loader preserving the approved module URL; Node relative-module and interpreter/script swap regressions cover the concrete failure. Unsupported `env` option syntax fails closed. macOS/Windows retain their existing prepared paths. |
| MCP protocol | implemented, dual era | Legacy `2025-03-26` plus modern stable `2026-07-28`; request-local metadata/header validation, typed negotiation errors, `server/discover`, result types and cache hints. Unit tests plus the real workerd E2E exercise both eras. Optional subscriptions/extensions are not claimed. |
| ChatGPT catalog snapshots | implemented server contract; external publication required | Catalog v1 compatibility gate, callable hidden aliases, digest/range metadata, Core/Admin/Agents surfaces. OpenAI's published metadata requires Scan Tools, review, and publish; no server response can perform that admin workflow. |
| OAuth modernization | implemented for public clients | CIMD advertisement and bounded validation, RFC 9207 `iss`, issuer-bound existing token contracts, DCR retained as compatibility fallback. Private-key JWT is not advertised or accepted. |
| Release binary E2E | implemented in release graph | Release waits for the downloaded, checksum-verified Linux x64 archive to pass workerd device/fs/command/session/restart/recovery and two-Agent transfer suites. Cross-platform archive construction remains gated by CI; the deterministic runtime E2E is Linux. |
| Edge observability | strengthened | Two HTTP stacks, stable machine categories (DNS/TLS/connect timeout, edge 1010/denial, Worker auth/4xx/5xx, malformed JSON, catalog mismatch), CF-Ray, bounded retries, JSON schema version. Multi-egress scheduling and WAF changes are operator infrastructure. |
| Release evidence | implemented | Release emits and signs/attests `ownmesh-release-evidence.json` from exact artifact hashes, the machine-checked current catalog receipt, its frozen compatibility baseline, and gate facts. `completeness_claim` remains false while listed waivers exist. |
| OS confinement middle preset | not implemented | Existing restricted-preset deny remains fail-closed (ADR 0007). Landlock/seccomp/Job Object/macOS confinement needs isolated per-platform design and was not mixed into execution custody. |
| Large authority-module decomposition | partial | MCP era validation is separated from the shared registry/invocation core, and execution plans capture remote broker authority. Runtime/session/store remain large; broad structural churn is deliberately not combined with this security patch. |

## External/human actions

- A Cloudflare administrator must run the probe from at least two egress
  locations and apply only the narrow WAF skip documented in
  `deploy-cloudflare.md` if an edge rule blocks machine traffic.
- A ChatGPT plugin publisher must scan, submit, and publish a new metadata
  version for catalog changes. A new conversation alone is insufficient for a
  published snapshot.
- Live vendor-profile, macOS/Windows broker, external ChatGPT, native-signing,
  and independent-review receipts remain the `W-*` waivers in the generated
  release evidence.
