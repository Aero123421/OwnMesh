# OwnMesh 1.0 Definition of Done — Release-quality audit

**Release train:** v1.1.0

**Audit date:** 2026-08-06

**Authority:** `OWNMESH_SPECIFICATION.ja.md` §33 and the shipped-surface registry below

**Scope authority:** [`release/SUPPORTED_SURFACES.json`](../release/SUPPORTED_SURFACES.json)

## Conclusion

OwnMesh 1.x is **not complete against the specification DoD**. The parsed CLI contains **22 explicit unsupported CLI surfaces** from the authoritative Rust registry plus 5 additional hard-error unsupported surfaces (**27 total**), recorded in `release/SUPPORTED_SURFACES.json`; these surfaces are excluded from the completeness claim and return explicit errors. Remote routing hard-fails rather than falling back locally, and `approval watch` does not degrade to a one-shot list.

The v1.0.2 remediation made build/security/release evidence fail-closed. v1.1.0 adds onboarding (setup/doctor/user-level service) and signed distribution/update without claiming full specification completeness. “Library exists”, “parser accepts a command”, and “workflow exists” are not counted as end-to-end completion.

Legend: **done** = current shipped behavior is covered · **partial** = useful implementation exists but the specification item is not complete · **unsupported** = excluded from 1.0.x.

## §33 DoD (18 items)

| # | DoD item | Honest status | Evidence / remaining gap |
|---|---|---|---|
| 1 | Signed release Win/macOS/Linux | **partial** | Five portable archives (Win x64, macOS arm64/x64, Linux musl arm64/x64) with LICENSE/NOTICE/README/notes, checksums, enrolled minisign trust root, strict SBOMs, and GitHub provenance are gated. Shell/PowerShell installers and Homebrew formula rendering ship. Universal macOS package and Authenticode/Apple notarization remain W-SIGN. |
| 2 | Deploy to own Cloudflare | **partial** | Wrangler config/docs and CI dry-run exist; live-account certification remains W-LIVE-E2E. |
| 3 | D1/DO/Worker auto provision | **partial** | Migrations and bindings exist; deployment still requires account-specific setup. |
| 4 | OAuth ChatGPT Personal Plugin | **partial** | Server/CLI automated flows exist; live ChatGPT account E2E remains W-LIVE-E2E. |
| 5 | Normal Chat read/write/command/session tools | **partial** | MCP harness covers routing; CLI `mcp serve` is explicitly unsupported and live integration is not certified. |
| 6 | CLI/TUI set Full User / Full Access | **partial** | Policy presets, `setup`, and TUI implementation exist; the CLI no-argument TUI handoff remains unsupported. |
| 7 | Privileged Broker per OS | **partial** | Security boundaries and transport implementations are tested. Native service activation/removal and verification are unsupported; templates/markers are never reported as installed service state. |
| 8 | Generic command + arbitrary CLI PTY | **partial** | Local structured/shell execution and session foundations exist. Remote `exec --device` is unsupported. |
| 9 | Official 9 profiles conformance | **partial** | Definitions/fixtures exist; all CLI profile commands are among the explicit unsupported surfaces. |
| 10 | Session observer/controller handoff | **partial** | Session library and CLI lifecycle paths exist; broad production restart/PTY certification remains. |
| 11 | TUI en/ja/zh-Hans/ru | **partial** | Separate TUI binary has completeness/snapshot tests; the combined CLI launch and all target UX depth are not complete. |
| 12 | R2/TURN relay default disabled | **done** | Fail-closed invariant is tested; LAN/P2P feature depth is unsupported under W-§12. |
| 13 | Central telemetry default disabled | **done** | Default-off invariant is tested; doctor/update ship with network-off defaults and opt-in probes. |
| 14 | Local file/log not cloud-persisted by default | **done** | No R2/TURN binding and local-first defaults are regression-tested. |
| 15 | Policy allow/ask/deny + temporary grant | **partial** | Library/daemon paths exist; policy rule mutation CLI is unsupported. |
| 16 | Device revoke, lockdown, token revoke | **partial** | Automated local/control-plane paths exist; live deployment behavior is not certified. |
| 17 | Security tests, fuzz, audit, SBOM, signed update | **partial** | CI/security are blocking, SBOM fallback is forbidden, and portable minisign-signed update is production-wired. External review is W-EXT-SEC; Authenticode/Apple notarization remain W-SIGN. |
| 18 | Apache-2.0, SECURITY, CONTRIBUTING, threat model | **done** | Repository documentation exists; it no longer asserts full product completeness. |

## Release-quality gates implemented for v1.0.2

- Rust is pinned to 1.92.0 in Cargo metadata, `rust-toolchain.toml`, CI, Security, Release, README, and CONTRIBUTING.
- CI requires `fmt`, `clippy -D warnings`, build, and tests with lockfile enforcement on Windows, Linux, and macOS.
- CI requires frozen pnpm install plus recursive test/typecheck/lint and a blocking Wrangler dry-run.
- Release calls CI and Security as reusable prerequisite jobs. Normal `needs` semantics prohibit build/publish after any prerequisite failure.
- Release requires all three portable platform archives, mandatory LICENSE/NOTICE/README/current notes in each archive, and both non-empty CycloneDX SBOMs; no empty SBOM fallback exists.
- Portable shell/PowerShell installers ship; universal macOS packaging remains unimplemented and is not a release-coverage claim.
- Release notes are selected from the current tag. Provenance is attested. Missing minisign credentials **fail** formal release publish (no degraded unsigned formal release).
- `scripts/check_release_quality.py` mechanically checks the publish dependency graph, fail-closed workflow patterns, toolchain pins, release-note scope, and the registry-backed unsupported surface manifest (currently 32 explicit / 39 total).

## Explicit waivers and non-goals

| ID | Scope | What the waiver does **not** mean |
|---|---|---|
| W-SIGN | Missing native platform signing/notarization (Authenticode / Apple) | Portable minisign is enrolled and required; checksums alone are not signatures. Native code-signing remains out of scope. |
| W-LIVE-E2E | Live Cloudflare/ChatGPT account exercise | Automated harnesses do not prove live-account operation. |
| W-EXT-SEC | External security review | Internal tests do not constitute an independent audit. |
| W-§12 | LAN discovery/direct encrypted transfer depth | Relay-off behavior is done; transfer completeness is not. |
| W-§14 | Residual update/doctor/support-bundle depth | Privacy defaults, doctor, and signed update ship; support-bundle depth and live multi-OS certification remain. |

Waivers disclose risk or defer scope. They do not convert a **partial** or **unsupported** item into **done**.

## Required regression invariants

- Full Access has no hidden hard denies.
- Broker remains networkless.
- Relay and telemetry remain off by default.
- Unsupported routing fails explicitly; it never silently changes the requested target.
- Apache-2.0 remains the repository license and secrets/private signing keys are never committed.
