# OwnMesh 1.0.1

**Any AI. Any CLI. Any machine. Your cloud.**

Completeness release after v1.0.0 baseline. Grok-4.5 workers + host integration.

## Highlights

- **Daemon runtime (MS1):** policy → exec/fs/logs, approval queue, temporary grants, idempotency journal, lockdown/unlock/token revoke
- **Broker + sessions:** networkless privileged broker (Named Pipe / Unix socket / loopback), PTY host, handoff persist/restart
- **Control plane:** D1-backed OAuth/devices, DeviceRoom WS routing, no R2/TURN by default
- **CLI auth:** PKCE browser login, device-code fallback, device enroll/revoke/rotate (keychain)
- **Logs/Git:** Windows Event Log / journald / docker / process providers + git status/diff
- **MCP + 9 profiles:** tool→device path, approval round-trip, fixture conformance, prompt-injection locked to policy
- **TUI:** full screens, setup wizard, Ctrl+K, en/ja/zh-Hans/ru i18n completeness CI
- **Hardening:** THREAT_MODEL.md, security tests, security.yml (audit/SBOM/secret scan)

## Tests

- `cargo test --workspace` — **242 passed**, 0 failed (release candidate)
- `pnpm -r test` — control-plane 43 + schema 25, 0 failed

## §33 DoD status (summary)

| # | Item | Status |
|---|---|---|
| 1 | Signed multi-OS release | **partial / waived** — checksums via release workflow; user signing keys (W-SIGN) |
| 2 | Deploy to own Cloudflare | **done** — wrangler + docs/deploy-cloudflare.md |
| 3 | D1/DO/Worker provision | **done** — migrations + DO bindings |
| 4 | OAuth ChatGPT plugin | **done** (server+CLI); live account E2E **waived** (W-LIVE-E2E) |
| 5 | Chat tools r/w/cmd/session | **done** — MCP harness E2E |
| 6 | Full User / Full Access in CLI/TUI | **done** — wizard + policy preset |
| 7 | Privileged broker per OS | **done** — pipe/socket/loopback; service ACL notes |
| 8 | Generic command + PTY | **done** |
| 9 | 9 profile conformance | **done** |
| 10 | Session handoff | **done** |
| 11 | TUI 4 languages | **done** |
| 12 | Relay default off | **done** (LAN P2P depth **waived** W-§12) |
| 13 | Telemetry default off | **done** (§14 feature depth **waived** W-§14) |
| 14 | No cloud file persist default | **done** |
| 15 | Policy allow/ask/deny + grants | **done** |
| 16 | Revoke / lockdown | **done** |
| 17 | Security tests/fuzz/audit/SBOM | **done** (external firm review **waived** W-EXT-SEC) |
| 18 | Apache-2.0 + SECURITY + threat model | **done** |

See also: `docs/DOD_1.0.md`, `docs/CHECKLIST_COVERAGE.md`, `docs/THREAT_MODEL.md`.

## Install

```bash
git clone https://github.com/Aero123421/OwnMesh.git
cd OwnMesh
git checkout v1.0.1
cargo build --release --workspace
pnpm install
```

## License

Apache-2.0
