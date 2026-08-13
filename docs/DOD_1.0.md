# OwnMesh 1.x Definition of Done — release-quality audit

**Release train:** v1.2.7

**Audit date:** 2026-08-12

**Authority:** `OWNMESH_SPECIFICATION.ja.md` §33 and the shipped-surface registry

**Shipped-surface authority:**
[`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json)

## Conclusion

OwnMesh v1.2.7 is a stable release for the product surface admitted by the
machine-checked registry. The Rust unsupported registries and the manifest both
contain zero intentionally unimplemented CLI surfaces. Parser acceptance alone
does not count: the admitted commands have fail-closed handlers and the relevant
local or authenticated control-plane route.

This scoped completeness claim is deliberately narrower than §33 of the full
target specification. Native code signing/notarization, some cross-platform
privileged-route receipts, a fully automated external ChatGPT receipt, and an
independent security review remain separate evidence or packaging work. Those
items do not make implemented v1.2.7 commands “beta”, but they also must not be
reported as completed proof.

Legend: **done** = shipped behavior and repository evidence cover the item ·
**partial** = useful shipped behavior exists, but the broader specification or
external evidence is incomplete · **out of scope** = explicitly not part of the
v1.2.7 stable product surface.

## §33 DoD (18 items)

| # | DoD item | Honest status | Evidence / remaining gap |
|---|---|---|---|
| 1 | Signed release Win/macOS/Linux | **partial** | Five portable archives (Windows x64, macOS arm64/x64, Linux musl arm64/x64) are gated with LICENSE/NOTICE/README/notes, non-empty CycloneDX SBOMs, SHA-256 checksums, mandatory minisign signature, and GitHub provenance. Authenticode, Apple notarization, universal/native installers remain out of scope. |
| 2 | Deploy to own Cloudflare | **done** | Guided deployment creates/reuses account resources, applies D1 migrations, deploys the Worker, provisions required secrets, and reports connection URLs. |
| 3 | D1/DO/Worker auto provision | **done** | Wrangler configuration, migrations, Durable Object binding, and guided resource provisioning are shipped; the user still supplies and owns the Cloudflare account. |
| 4 | OAuth ChatGPT Personal Plugin | **partial** | DCR, authorization-code/PKCE, rotating refresh, passkey owner login, and exact callbacks are implemented. A manual live ChatGPT compatibility receipt exists; reproducible automated external E10 evidence remains open. |
| 5 | Normal Chat read/write/command/session tools | **done** | Public MCP routing and bounded `ownmesh mcp serve --stdio` are implemented with authenticated issuer binding, bounded messages, and no local-routing fallback. |
| 6 | CLI/TUI set Full User / Full Access | **done** | No-argument TUI launch, setup policy selection, typed presets, and structured policy mutation are supported. Sensitive mutation uses fresh passkey approval. |
| 7 | Privileged Broker per OS | **partial** | Networkless native lifecycle is implemented on Linux, macOS, and Windows while `ownmeshd` remains unprivileged. Linux has a native root receipt; macOS/Windows native release receipts and the full public E8 route remain open evidence. |
| 8 | Generic command + arbitrary CLI PTY | **done** | Local exact-argv execution, authenticated remote exec/session creation, PTY lifecycle, bounded replay, process-tree termination, and explicit idempotency are supported. Raw shell is an explicit mode and never silently replaces structured execution. |
| 9 | Official 9 profiles conformance | **done** | Nine structured adapters, device detection, persistent profile sessions, public MCP routing, and CLI scan/list/show/login/test/start/resume are implemented. |
| 10 | Session observer/controller handoff | **done** | Session list/show/attach/claim/release/give/close/terminate, observer ACLs, expiring controller leases, durable handoff, and bounded replay are shipped and regression-tested. |
| 11 | TUI en/ja/zh-Hans/ru | **done** | The Ratatui UI and no-argument CLI handoff ship with en-US, ja-JP, zh-Hans, and ru-RU resources plus locale/snapshot coverage. |
| 12 | R2/TURN relay default disabled | **done** | Relay is absent/disabled by default and the fail-closed invariant is tested. LAN/P2P discovery depth is not required for the v1.2.7 transfer route. |
| 13 | Central telemetry default disabled | **done** | Setup defaults telemetry off; doctor and update keep network access off unless configured or explicitly requested. |
| 14 | Local file/log not cloud-persisted by default | **done** | Local-first defaults are regression-tested. Transfer persists only explicitly requested bounded artifact pages and excludes credentials/private key material. |
| 15 | Policy allow/ask/deny + temporary grant | **done** | Typed policy show/validate/explain/preset/rule mutation, exact approval decisions, and bounded temporary grants are shipped. Unsafe generic command/shell grants are deliberately refused while one-shot approval remains available. |
| 16 | Device revoke, lockdown, token revoke | **done** | Device lifecycle, lockdown/unlock, and typed token revoke are implemented. Security-sensitive recovery/mutation requires fresh operation-bound passkey approval. |
| 17 | Security tests, fuzz, audit, SBOM, signed update | **partial** | Blocking CI/security gates, fuzz targets, strict SBOM generation, signed update, and fail-closed release dependencies ship. Independent external review and native platform signing remain open. |
| 18 | Apache-2.0, SECURITY, CONTRIBUTING, threat model | **done** | Repository policy and security documentation exist and distinguish stable product scope from aspirational specification scope. |

## Release-quality gates

- Rust 1.92.0, Node 22, and pnpm 9.15.0 are pinned.
- CI requires Rust format, strict Clippy, build, and tests with lockfile
  enforcement, plus frozen TypeScript install/test/typecheck/lint and Wrangler
  dry-run.
- Release publication depends on both reusable CI and Security workflows. A
  failed prerequisite prevents build and publish.
- Every platform archive must contain the current LICENSE, NOTICE, README, and
  tag-selected release notes. Empty SBOM fallback is forbidden.
- Formal publication requires the enrolled minisign key; unsigned degraded
  release is forbidden. Provenance is attested by GitHub.
- `scripts/check_release_quality.py` checks the publish graph, fail-closed
  workflow patterns, toolchain/version alignment, release-note selection, and
  the registry-backed surface manifest. For v1.2.7 the unsupported counts are
  zero and `completeness_claim` is true.
- Release tags are annotated. Per
  [ADR 0001](./adr/0001-release-signing-sbom-provenance.md) they are also
  **signed** (GPG or SSH) when the release operator has signing configured:

  ```bash
  git tag -s "v${VERSION}" -m "OwnMesh v${VERSION}"
  git tag -v "v${VERSION}"   # verify before pushing
  ```

  Tag signing attests who cut the release; it complements and never replaces the
  mandatory minisign signature over `SHA256SUMS`, which is what consumers verify.
  Tag signatures are not yet enforced by CI and are therefore not claimed as a
  guarantee — see [`ROADMAP.md`](./ROADMAP.md).

## Explicit caveats and non-goals

| ID | Scope | What it means |
|---|---|---|
| W-SIGN | Authenticode / Apple signing and notarization | Portable minisign is enrolled and mandatory; native platform signing is not claimed. |
| W-E8-RECEIPTS | macOS/Windows native broker receipt and full public privileged route | Implementation and unit/loopback evidence do not substitute for the missing opt-in native/public receipts. |
| W-E10-AUTO | Automated external ChatGPT exercise | Manual live compatibility plus local reproducible suites do not equal a fully automated third-party receipt. |
| W-EXT-SEC | Independent external security review | Internal tests and review do not constitute an independent audit. |
| W-PACKAGING | MSI/NSIS and native/universal macOS package | Portable signed archives and verified one-line installers are the v1.2.7 distribution contract. |

These caveats disclose evidence and scope. They do not reclassify implemented,
registry-admitted v1.2.7 commands as unsupported, and they do not convert a
broader §33 **partial** row into **done**.

## Required regression invariants

- Full Access has no hidden hard denies.
- The privileged broker remains networkless and `ownmeshd` remains user-level.
- Relay, telemetry, and automatic update network access remain off by default.
- A requested remote target never falls back to a local action.
- Security mutations require a typed operation and fresh, operation-bound human
  approval; arbitrary method/parameter passthrough is forbidden.
- Apache-2.0 remains the repository license and secrets/private signing keys are
  never committed.
