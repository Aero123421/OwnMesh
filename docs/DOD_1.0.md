# OwnMesh 1.0 Definition of Done — Audit

**Baseline:** `main` @ `05b1c6c` (+ prior `38cd146` v1.0.0 core)  
**Audit date:** 2026-08-06  
**Authority:** `OWNMESH_SPECIFICATION.ja.md` §33 + `IMPLEMENTATION_CHECKLIST.md` §0–§16  
**Tests at audit:** `cargo test --workspace` green; `pnpm -r test` green (schema 25 + control-plane 4)

Legend: **done** | **partial** | **gap**

---

## §33 DoD (18 items)

| # | DoD item | Status | Evidence | Gap / next owner |
|---|---|---|---|---|
| 1 | Signed release Win/macOS/Linux | **partial** | `.github/workflows/release.yml`, ADR-0001 | Real multi-OS signed artifacts + provenance → **release-08 / harden-07** |
| 2 | Deploy to own Cloudflare | **partial** | `packages/control-plane/wrangler.jsonc`, `docs/deploy-cloudflare.md` | One-click button + real account dry-run docs polish → **cp-04** |
| 3 | D1/DO/Worker auto provision | **partial** | `migrations/0001_init.sql`, `DeviceRoom` DO stub, wrangler bindings | Wire D1 in runtime paths (not mem-only); DO routing E2E → **cp-04** |
| 4 | OAuth ChatGPT Personal Plugin | **partial** | OAuth metadata, PKCE code exchange, refresh reuse detection tests `packages/control-plane/src/oauth.test.ts` | Persist tokens in D1; exact redirect registry; live plugin checklist → **cp-04** |
| 5 | Normal Chat read/write/command/session tools | **partial** | MCP tools catalog + `/mcp` handlers in `packages/control-plane/src/index.ts` | Route ops to live device room; approval round-trip E2E → **mcp-profiles-05** |
| 6 | CLI/TUI set Full User / Full Access | **partial** | `ownmesh-policy` presets; TUI i18n strings | Wire presets into setup wizard + config save E2E → **ms1-02**, **tui-i18n-06** |
| 7 | Privileged Broker per OS | **partial** | `ownmesh-broker` loopback+signed req; networkless bind check | Windows Named Pipe ACL + macOS/Linux cfg services (not only loopback TCP) → **broker-session-03** |
| 8 | Generic command + arbitrary CLI PTY | **partial** | `ownmesh-exec` structured/shell; profiles generic launch | Daemon wiring + real PTY host path → **ms1-02**, **broker-session-03** |
| 9 | Official 9 profiles conformance | **partial** | `ownmesh-profiles` 9 defs + detect tests | Fixture conformance matrix per CLI version → **mcp-profiles-05** |
| 10 | Session observer/controller handoff | **partial** | `ownmesh-session` give/claim/observer tests | Persist across restart; wire session-host PTY → **broker-session-03** |
| 11 | TUI en/ja/zh-Hans/ru | **partial** | `crates/ownmesh-tui/src/i18n/mod.rs` | Full screens, Fluent, completeness CI, snapshots → **tui-i18n-06** |
| 12 | R2/TURN relay default disabled | **done** | `TransferConfig::default().relay_enabled == false`; tests `NoDirectPathRelayDisabled` | Keep in harden-07 regression |
| 13 | Central telemetry default disabled | **done** | `UpdateSettings::default()`; `default_sends_nothing_to_vendor` | Keep in harden-07 regression |
| 14 | Local file/log not cloud-persisted by default | **done** | No R2 bindings in wrangler; local journal/fs crates | Assert in cp-04 (no accidental R2) |
| 15 | Policy allow/ask/deny + temporary grant | **done** (library) | `ownmesh-policy` evaluate + grants tests | Wire through daemon approval queue → **ms1-02** |
| 16 | Device revoke, lockdown, token revoke | **partial** | OAuth revoke + device DELETE in control-plane mem store | D1-backed revoke immediate; CLI lockdown → **cp-04**, **ms1-02** |
| 17 | Security tests, fuzz, audit, SBOM, signed update | **partial** | protocol fuzz harness; update signature helpers | Expand suite + CI audit/SBOM → **harden-07** |
| 18 | Apache-2.0, SECURITY, CONTRIBUTING, threat model | **partial** | LICENSE, SECURITY.md, CONTRIBUTING.md, SECURITY_REVIEW_CHECKLIST.md | Publish `docs/THREAT_MODEL.md` → **harden-07** |

---

## IMPLEMENTATION_CHECKLIST by section

| Section | Status | Notes | Owner ticket |
|---|---|---|---|
| §0 Repo foundation | **partial** | LICENSE/CI/workspace exist; some checklist boxes still `[ ]` | release-08 checkbox pass |
| §1 Domain/Schema/Protocol | **done** | domain+protocol+schema fixtures/tests | — |
| §2 Local IPC / process | **partial** | ipc+daemon+cli+tui skeletons with status IPC | ms1-02 wire exec path |
| §3 Config/Identity/Keychain | **partial** | config+identity crates; OS keychain via keyring | ms1-02 / cp-04 enrollment |
| §4 Control plane | **partial** | Worker MCP/OAuth/health; D1 SQL; DO stub; mem token store | **cp-04** |
| §5 OAuth/Login/Enrollment | **partial** | flows + reuse detection tests; CLI login modules incomplete | **cp-04** |
| §6 Command/FS/Logs | **partial** | libs implemented+tested; **not fully wired in ownmeshd** | **ms1-02** |
| §7 Policy/Approval/Full Access | **partial** | evaluator+presets+tests; approval queue/CLI incomplete | **ms1-02** |
| §8 Privileged Broker | **partial** | client+broker binary; OS service/pipe production path gap | **broker-session-03** |
| §9 PTY/Session/Handoff | **partial** | session manager tests; host PTY thin | **broker-session-03** |
| §10 MCP/ChatGPT | **partial** | tool catalog + handlers; device routing stub | **mcp-profiles-05** |
| §11 Official 9 profiles | **partial** | definitions+detect; deep adapters gap | **mcp-profiles-05** |
| §12 P2P transfer | **partial** | plan/fail-closed tests; LAN encrypt path thin | **harden-07** |
| §13 Rich TUI/i18n | **partial** | i18n strings; not full 11 screens/wizard | **tui-i18n-06** |
| §14 Update/Diag/Audit/Privacy | **partial** | update+diagnostics libs+tests | **harden-07** |
| §15 Security hardening | **partial** | some tests; threat model/SBOM/audit CI gap | **harden-07** |
| §16 Packaging/Release | **partial** | v1.0.0 released; need v1.0.1 DoD release | **release-08** |

---

## Priority gap list (execution order)

1. **ms1-02** — Wire `ownmeshd` + CLI: policy → exec/fs/logs; approval queue; idempotency E2E; Full Access conformance remains green  
2. **broker-session-03** — Production broker transport (pipe/socket), session-host PTY, handoff persistence  
3. **cp-04** — D1-backed OAuth/devices; DO device room real WS routing; wrangler verify; no R2/TURN  
4. **mcp-profiles-05** — MCP tools hit device path; 9-profile fixture conformance; prompt-injection tests  
5. **tui-i18n-06** — Screens, wizard, Ctrl+K, 4-locale completeness CI  
6. **harden-07** — Threat model, expanded security tests, SBOM/audit CI, relay/telemetry locks  
7. **release-08** — Bump 1.0.1, notes with DoD table, tag+GitHub Release (no force-push)

### Explicit waivers (until human/external)

| Item | Waiver |
|---|---|
| External security firm review | Internal checklist + tests; note in release notes |
| Live ChatGPT account E2E | Automated MCP client tests + `docs/chatgpt-connection.md` manual steps |
| Multi-OS signed notarization | CI builds + checksums first; signing keys user-provided |

---

## Invariants (must not regress)

- Full Access has **no hidden hard denies** (`ownmesh-policy`)
- Broker **networkless** (no non-loopback listen)
- Relay **default off**; telemetry **default off**
- Apache-2.0; no secrets in git
