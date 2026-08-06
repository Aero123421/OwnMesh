# IMPLEMENTATION_CHECKLIST Coverage Map (v1.0.1)

**Source:** [`IMPLEMENTATION_CHECKLIST.md`](../IMPLEMENTATION_CHECKLIST.md)  
**Authority:** meta-loop board plan (run `2026-08-06T10-56-25-625Z-phl3z8`) + [`docs/DOD_1.0.md`](./DOD_1.0.md)  
**Purpose:** release-08 起動前ゲート。未チェック項目を **担当チケット ID** または **waiver** のどちらか一つに漏れなく対応付ける。  
**Rule:** `Owner` 列は ticket ID **または** `waiver` のみ。補足・二次担当は `Notes` に書く。

## Confirmed dispositions (pre–release-08)

| Area | Disposition | Owner |
|---|---|---|
| §5 server (OAuth/metadata/D1/device endpoints) | implement | **cp-04** |
| §5-CLI (`login` / device-code / enrollment / revoke CLI) | implement | **cli-auth-09** |
| §6 remainder (git status/diff, Event Log, journald, Docker/process/file log providers) | implement | **logs-git-10** |
| §12 LAN direct / P2P transfer feature depth | **waiver** (v1.0.1) | waiver |
| §12 fail-closed invariants (relay default OFF, no silent R2/TURN) | regression lock | **harden-07** (+ cp-04 no-R2 binding test) |
| §13 Transfers screen | implement UI to match reality (no fake LAN promises) | **tui-i18n-06** |
| §14 feature completeness (update modes/doctor wiring 等) | **waiver** (v1.0.1) | waiver |
| §14 implemented privacy defaults (telemetry OFF, redaction, audit retention) | regression lock | **harden-07** |

### Standing waivers (open_questions / DOD explicit)

| Waiver ID | Scope | Reason |
|---|---|---|
| W-SIGN | Multi-OS signed notarization / real signing keys | User-provided keys pending; checksums + release.yml first |
| W-LIVE-E2E | Live Cloudflare account dry-run + live ChatGPT Personal Plugin E2E | Manual docs substitute this sprint |
| W-EXT-SEC | External security firm review before 1.0 | Internal checklist + tests; note in release notes |
| W-§12 | LAN discovery / direct encrypted P2P / chunking-resume depth | v1.0.1 ships local plan + fail-closed relay; full P2P → 1.1+ |
| W-§14 | Update channels/rollback/doctor/support-bundle feature sufficiency | v1.0.1 keeps library defaults; no new feature work in harden-07 |

---

## Coverage table (unchecked items only)

Legend for `Kind`: `impl` = implement in ticket · `waiver` = accepted deferral · `regress` = lock existing behavior in tests/CI

### §0 Repository と開発基盤

*All items checked — no open rows.*

### §1 Domain、Schema、Protocol

*All items checked — no open rows.*

### §2 Local IPC とプロセス構成

*All items checked — no open rows.*

### §3 Config、Identity、Keychain

*All items checked — no open rows.*

### §4 Cloudflare Control Plane

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Workers entrypoint と `/mcp` | cp-04 | impl | Entrypoint/wiring; deep tool behavior → mcp-profiles-05 (§10) |
| OAuth metadata endpoints | cp-04 | impl | |
| D1 migrations | cp-04 | impl | |
| Device registry | cp-04 | impl | |
| Principal / OAuth client / grant tables | cp-04 | impl | |
| Durable Object device room | cp-04 | impl | |
| WebSocket hibernation 対応 | cp-04 | impl | |
| operation routing | cp-04 | impl | Device path completion also mcp-profiles-05 |
| audit metadata | cp-04 | impl | |
| Deploy to Cloudflare configuration | cp-04 | impl | docs/deploy-cloudflare.md |
| R2/TURN が標準 provision されないことを test | cp-04 | impl | Invariant; harden-07 keeps regression |

### §5 OAuth、Login、Enrollment

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Authorization Code + PKCE | cp-04 | impl | **Server** endpoints + token issue; CLI browser callback → cli-auth-09 |
| Device Authorization flow | cp-04 | impl | **Server** device-code issue/poll; CLI fallback → cli-auth-09 |
| OAuth Protected Resource Metadata | cp-04 | impl | Server-only |
| Dynamic Client Registration / Client ID Metadata Document 対応方針 | cp-04 | impl | Server policy/docs |
| refresh token rotation と reuse detection | cp-04 | impl | Server; CLI stores refresh via cli-auth-09 |
| redirect URI exact match | cp-04 | impl | Server-only |
| CLI browser callback | cli-auth-09 | impl | **§5-CLI** |
| CLI device-code fallback | cli-auth-09 | impl | **§5-CLI** |
| device enrollment challenge/proof | cli-auth-09 | impl | **§5-CLI**; server challenge shape fixed by cp-04 |
| device revoke と key rotation | cli-auth-09 | impl | **§5-CLI** revoke/rotate commands; server revoke persistence → cp-04 tables |
| ChatGPT Personal Plugin 接続手順を integration test する | mcp-profiles-05 | impl | Automated MCP client tests; **live account E2E → W-LIVE-E2E** |

### §6 Command、Process、Filesystem、Logs

*Checked items (exec/fs/cursor log query 等) remain owned by completed ms1-02. Open remainder only:*

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Git status/diff | logs-git-10 | impl | **§6残り** |
| Windows Event Log provider | logs-git-10 | impl | **§6残り** |
| journald/systemd provider | logs-git-10 | impl | **§6残り** (cfg-gated on non-Linux CI) |
| Docker/process/file log providers | logs-git-10 | impl | **§6残り** |

### §7 Policy、Approval、Full Access

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Custom policy editor API | tui-i18n-06 | impl | Settings/wizard surfaces for presets + custom rules UX; evaluator semantics unchanged (ms1) |
| TUI approval queue | tui-i18n-06 | impl | Approvals screen |
| one-time browser approval page | cp-04 | impl | Worker-hosted approval page; TUI/CLI paths already exist |

### §8 Privileged Broker

| Item | Owner | Kind | Notes |
|---|---|---|---|
| protocol と capability token | broker-session-03 | impl | |
| networkless design を enforcement | broker-session-03 | impl | harden-07 regression lock |
| Windows Service + Named Pipe ACL | broker-session-03 | impl | |
| macOS LaunchDaemon + Unix socket + code signature check | broker-session-03 | impl | |
| Linux systemd service + `SO_PEERCRED` | broker-session-03 | impl | |
| nonce / expiry / replay protection | broker-session-03 | impl | |
| structured elevated command | broker-session-03 | impl | |
| elevated process tree lifecycle | broker-session-03 | impl | |
| install/uninstall/status CLI | broker-session-03 | impl | |
| malformed request fuzzing | broker-session-03 | impl | |
| unprivileged caller rejection test | broker-session-03 | impl | |

### §9 PTY、Session、Handoff

| Item | Owner | Kind | Notes |
|---|---|---|---|
| PTY/ConPTY abstraction | broker-session-03 | impl | |
| session host supervision | broker-session-03 | impl | |
| detached session persistence | broker-session-03 | impl | |
| output sequence と replay buffer | broker-session-03 | impl | |
| observer attach | broker-session-03 | impl | |
| controller lease | broker-session-03 | impl | |
| claim/release/give | broker-session-03 | impl | |
| stale controller recovery | broker-session-03 | impl | |
| resize/input/close/terminate | broker-session-03 | impl | |
| raw/cooked view | broker-session-03 | impl | |
| native agent session id mapping | broker-session-03 | impl | Profile mapping depth also mcp-profiles-05 |
| context bundle | broker-session-03 | impl | |

### §10 MCP と ChatGPT

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Streamable HTTP `/mcp` | mcp-profiles-05 | impl | Builds on cp-04 Worker entry |
| OAuth scopes と tool authorization | mcp-profiles-05 | impl | |
| discovery/read tools | mcp-profiles-05 | impl | |
| write/execute tools | mcp-profiles-05 | impl | |
| raw shell と elevated tool の分離 | mcp-profiles-05 | impl | |
| annotations (`readOnlyHint` 等) | mcp-profiles-05 | impl | |
| stable result/error envelope | mcp-profiles-05 | impl | |
| pagination と truncation | mcp-profiles-05 | impl | |
| asynchronous operation pattern | mcp-profiles-05 | impl | |
| approval-required response | mcp-profiles-05 | impl | |
| Personal Plugin 接続テスト | mcp-profiles-05 | impl | Live account → **W-LIVE-E2E** |
| 通常 Chat での read/write/session 実地テスト | waiver | waiver | **W-LIVE-E2E**; automated harness in mcp-profiles-05 |
| permission mode 別の挙動確認 | mcp-profiles-05 | impl | docs/chatgpt-connection.md |
| prompt-injection security tests | mcp-profiles-05 | impl | harden-07 may extend |

### §11 公式 Profile 9 種

| Item | Owner | Kind | Notes |
|---|---|---|---|
| detect/version/auth status | mcp-profiles-05 | impl | Common |
| best interface selection | mcp-profiles-05 | impl | Common |
| structured event normalization | mcp-profiles-05 | impl | Common |
| PTY fallback | mcp-profiles-05 | impl | Common; host PTY from broker-session-03 |
| native resume（利用可能なもの） | mcp-profiles-05 | impl | Common |
| version compatibility matrix | mcp-profiles-05 | impl | Common; docs also release-08 |
| fixture-based conformance tests | mcp-profiles-05 | impl | Common |
| Codex CLI | mcp-profiles-05 | impl | |
| Claude Code | mcp-profiles-05 | impl | |
| Kimi Code | mcp-profiles-05 | impl | |
| OpenCode | mcp-profiles-05 | impl | |
| Pi Coding Agent | mcp-profiles-05 | impl | |
| Antigravity CLI (`agy`) | mcp-profiles-05 | impl | |
| Qwen Code | mcp-profiles-05 | impl | |
| Hermes Agent | mcp-profiles-05 | impl | |
| Qoder CLI | mcp-profiles-05 | impl | |
| Profile なしの任意 command 実行 | mcp-profiles-05 | impl | Generic |
| Profile なしの任意 interactive CLI session | mcp-profiles-05 | impl | Generic |

### §12 P2P File Transfer

| Item | Owner | Kind | Notes |
|---|---|---|---|
| transfer plan | waiver | waiver | **W-§12**; existing local `plan_transfer` kept; no LAN plan expansion. UI → tui-i18n-06 |
| sender/receiver consent と capability | waiver | waiver | **W-§12** |
| local/LAN discovery | waiver | waiver | **W-§12** (core deferral) |
| direct encrypted transfer | waiver | waiver | **W-§12** (core deferral) |
| chunking、resume、hash verification | waiver | waiver | **W-§12** |
| rate/size limits | waiver | waiver | **W-§12** |
| destination path policy | waiver | waiver | **W-§12**; local copy policy remains |
| relay addon interface | waiver | waiver | **W-§12**; interface stub may remain |
| relay disabled default | harden-07 | regress | Invariant already true; **must not regress** |
| R2/TURN が勝手に fallback されない test | harden-07 | regress | Also asserted in cp-04 (no bindings) |

**§12 UI note (not a §12 checklist row):** §13 `Transfers` screen → **tui-i18n-06** must show only real capabilities (local plan + fail-closed relay OFF), never promise LAN direct transfer.

### §13 Rich TUI と多言語

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Obsidian theme | tui-i18n-06 | impl | |
| 24-bit/256/16-color fallback | tui-i18n-06 | impl | |
| ASCII fallback | tui-i18n-06 | impl | |
| Dashboard | tui-i18n-06 | impl | |
| Devices | tui-i18n-06 | impl | |
| Workspaces | tui-i18n-06 | impl | |
| Sessions | tui-i18n-06 | impl | |
| Profiles | tui-i18n-06 | impl | |
| Approvals | tui-i18n-06 | impl | §7 TUI approval queue |
| Transfers | tui-i18n-06 | impl | Facts-only vs **W-§12** |
| Activity/Audit | tui-i18n-06 | impl | |
| Diagnostics | tui-i18n-06 | impl | Surfaces existing diagnostics; no §14 feature build |
| Settings | tui-i18n-06 | impl | Includes policy preset selection |
| `Ctrl+K` command palette | tui-i18n-06 | impl | |
| setup wizard | tui-i18n-06 | impl | Full Access / presets |
| context help / F1 | tui-i18n-06 | impl | |
| responsive 80x24 / wide layout | tui-i18n-06 | impl | |
| mouse optional support | tui-i18n-06 | impl | |
| en-US | tui-i18n-06 | impl | |
| ja-JP | tui-i18n-06 | impl | |
| zh-Hans | tui-i18n-06 | impl | |
| ru-RU | tui-i18n-06 | impl | |
| translation completeness CI | tui-i18n-06 | impl | |
| CJK width and Russian overflow snapshots | tui-i18n-06 | impl | |
| no-color / high-contrast / reduced-motion modes | tui-i18n-06 | impl | |

### §14 Update、Diagnostics、Audit、Privacy

| Item | Owner | Kind | Notes |
|---|---|---|---|
| update mode: off/check/notify/download/auto | waiver | waiver | **W-§14** feature sufficiency; library defaults remain |
| stable/beta/nightly channels | waiver | waiver | **W-§14** |
| signature verification | waiver | waiver | **W-§14** / **W-SIGN**; helpers may exist, no new feature work |
| rollback | waiver | waiver | **W-§14** |
| protocol compatibility warning | waiver | waiver | **W-§14** |
| `ownmesh doctor` | waiver | waiver | **W-§14** (no daemon wiring expansion in this train) |
| support bundle preview/redaction | waiver | waiver | **W-§14**; redaction invariants → harden-07 where already present |
| local metrics | waiver | waiver | **W-§14** |
| central telemetry disabled by default | harden-07 | regress | **Must not regress**; core privacy invariant |
| crash report explicit opt-in | harden-07 | regress | Default-off / opt-in lock |
| audit retention and pruning | harden-07 | regress | Lock existing behavior |
| sensitive output redaction | harden-07 | regress | Lock existing behavior |

### §15 Security Hardening

| Item | Owner | Kind | Notes |
|---|---|---|---|
| threat model review | harden-07 | impl | docs/THREAT_MODEL.md |
| auth/token tests | harden-07 | impl | |
| replay/idempotency tests | harden-07 | impl | |
| path traversal/symlink/race tests | harden-07 | impl | |
| command argument injection tests | harden-07 | impl | |
| privileged broker boundary tests | harden-07 | impl | Complements broker-session-03 |
| local IPC spoofing tests | harden-07 | impl | |
| WebSocket parser fuzzing | harden-07 | impl | |
| adapter isolation tests | harden-07 | impl | |
| prompt-injection scenarios | harden-07 | impl | Overlaps mcp-profiles-05 |
| dependency audit | harden-07 | impl | CI job |
| SAST/secret scanning | harden-07 | impl | CI job |
| SBOM | harden-07 | impl | CI job |
| signed artifacts/provenance | release-08 | impl | Checksums + workflow; real keys → **W-SIGN** |
| external security review before 1.0 | waiver | waiver | **W-EXT-SEC** |

### §16 Packaging と OSS Release

| Item | Owner | Kind | Notes |
|---|---|---|---|
| Windows installer/package | release-08 | impl | Via release.yml artifacts |
| macOS universal binaries/package | release-08 | impl | |
| Linux packages/binaries | release-08 | impl | |
| shell completions | release-08 | impl | Ship if present; else document gap in notes |
| signed checksums | release-08 | impl | Real notarization → **W-SIGN** |
| install/uninstall documentation | release-08 | impl | README / release notes |
| Cloudflare deployment guide | cp-04 | impl | release-08 verifies link from notes |
| ChatGPT connection guide | mcp-profiles-05 | impl | docs/chatgpt-connection.md |
| profile compatibility table | mcp-profiles-05 | impl | release-08 may mirror in notes |
| troubleshooting guide | release-08 | impl | |
| architecture diagrams | release-08 | impl | |
| contributor setup | release-08 | impl | CONTRIBUTING already exists; refresh |
| release notes | release-08 | impl | docs/RELEASE_NOTES_v1.0.1.md + DoD/waiver table |
| public roadmap/issues | release-08 | impl | |

---

## Section rollup (Owner ticket column for DOD)

| Section | Primary owner(s) | Waiver? |
|---|---|---|
| §0–§3 | done (ms1 / foundation) | — |
| §4 | **cp-04** | — |
| §5 | **cp-04** (server) + **cli-auth-09** (CLI) | W-LIVE-E2E (live plugin only) |
| §6 | done core + **logs-git-10** (remainder) | — |
| §7 | **tui-i18n-06** (queue/settings) + **cp-04** (browser approval) | — |
| §8–§9 | **broker-session-03** | — |
| §10–§11 | **mcp-profiles-05** | W-LIVE-E2E (live Chat) |
| §12 | **waiver (W-§12)** + **harden-07** regress + **tui-i18n-06** Transfers UI | yes |
| §13 | **tui-i18n-06** | — |
| §14 | **waiver (W-§14)** + **harden-07** regress | yes |
| §15 | **harden-07** (+ release-08 artifacts, W-EXT-SEC, W-SIGN) | partial |
| §16 | **release-08** (guides: cp-04 / mcp-profiles-05) | W-SIGN |

## Unresolved

**None.** Every unchecked checklist row has exactly one `Owner` (ticket ID or `waiver`).

## Ticket index (this train)

| ID | Role |
|---|---|
| checklist-coverage-00 | This map + DOD owner column refresh |
| broker-session-03 | §8 / §9 |
| cp-04 | §4 + §5 server (+ browser approval page) |
| tui-i18n-06 | §13 + §7 TUI queue + Transfers facts-only |
| cli-auth-09 | §5-CLI |
| logs-git-10 | §6 remainder |
| mcp-profiles-05 | §10 / §11 |
| harden-07 | §15 + §12/§14 invariant regression (no feature build) |
| release-08 | §16 + version/tag; gated on this document |

## Notes for release-08 gate

1. Do **not** tag v1.0.1 until cli-auth-09 and logs-git-10 are green (no login/log-provider stubs).
2. Do **not** tag until release notes explicitly list **W-§12**, **W-§14**, **W-SIGN**, **W-LIVE-E2E**, **W-EXT-SEC**.
3. Checkbox updates in `IMPLEMENTATION_CHECKLIST.md` are release-08's job, aligned to this map (waiver rows stay unchecked or marked waived in notes — do not fake `[x]` for waived LAN/update depth).
