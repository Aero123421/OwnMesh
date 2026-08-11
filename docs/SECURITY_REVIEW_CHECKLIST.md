# OwnMesh Security Review Checklist

OwnMesh は Full Access を正式に提供するため、「操作を禁止すること」ではなく、認証された意思が改ざんされず、別主体へ横取りされず、意図した端末と権限で一度だけ実行されることを中心にレビューする。

**Threat model:** [`THREAT_MODEL.md`](./THREAT_MODEL.md)  
**Evidence rule:** each checkbox lists automated tests and/or docs. `harden-07` locks invariants; waived feature depth is marked **W-***.

Legend: ✅ covered by automated tests in v1.2.0 · ⚠ partial / best-effort · ⏸ waived feature depth (invariant may still be locked)

## 1. Identity と Token

- [x] Human、ChatGPT/OAuth client、Device、local IPC principal を別 identity として扱う  
  **Tests:** `packages/control-plane/src/oauth.test.ts`, `devices.test.ts`; `crates/ownmesh-ipc/src/auth.rs`; `crates/ownmesh/src/auth/tests/*`
- [x] access token は短時間で audience/scope/tenant/client に binding される  
  **Tests:** `packages/control-plane/src/oauth.test.ts`, `security-harden.test.ts`
- [x] refresh token rotation と reuse detection がある  
  **Tests:** `packages/control-plane/src/oauth.test.ts` (`refresh token reuse is detected`)
- [x] redirect URI exact match、PKCE、state、nonce を検証する  
  **Tests:** `oauth.test.ts` (redirect exact match); CLI `crates/ownmesh/src/auth/tests/*` (PKCE)
- [x] device key は extract されにくい OS keystore に保存する  
  **Tests:** `crates/ownmesh-identity` store tests; CLI auth tests (refresh not in plaintext session file)
- [x] device revoke と client token revoke が即時反映される  
  **Tests:** `oauth.test.ts` (`revoke invalidates access token immediately`); device revoke paths in CLI auth tests
- [x] token、cookie、secret がログ、MCP result、panic dump に出ない  
  **Tests:** `ownmesh-identity` Secret* redaction; `ownmesh-diagnostics` `redact_text`; `ownmesh-ipc` `redact_secrets`; `security-harden.test.ts`

## 2. Device Protocol

- [x] handshake transcript を device key で証明する  
  **Tests:** control-plane `device-room.test.ts` / device enroll paths
- [x] message id、sequence、expiry、nonce を検証する  
  **Tests:** `crates/ownmesh-protocol` envelope expiry tests; broker nonce/replay tests
- [x] at-least-once delivery で write operation を重複実行しない  
  **Tests:** `ownmesh-exec` idempotency; `ownmeshd` `idempotency_key_prevents_operation_rerun`; `security_command_injection` replay section
- [x] frame/message/payload/output の上限がある  
  **Tests:** `ownmesh-protocol` max envelope; `ownmesh-ipc` `MAX_FRAME_BYTES`; exec `max_output_bytes`
- [x] parser と state machine を fuzz test する  
  **Tests:** `crates/ownmesh-protocol/tests/fuzz_harness_build.rs`, `ws_parser_fuzz.rs`
- [x] version downgrade と unsupported feature を安全に扱う  
  **Tests:** `ownmesh-protocol` version / unsupported protocol tests
- [x] reconnection が別 device/session の状態を混同しない  
  **Tests:** `device-room.test.ts` room isolation

## 3. Local IPC

- [x] Windows Named Pipe ACL、Unix socket permission/peer credentials を検証する  
  **Tests:** `ownmesh-ipc` endpoint/auth unit tests; spoofing suite rejects bad tokens
- [x] local user A が local user B の daemon を操作できない  
  **Tests:** `crates/ownmesh-ipc/tests/security_spoofing.rs` (token mismatch / empty token)
- [x] symlink/socket replacement と TOCTOU を考慮する  
  **Tests:** `ownmesh-fs/tests/security_path.rs` (symlink escape); IPC token file write uses temp+rename
- [x] TUI/CLI と daemon の protocol version を交渉する  
  **Tests:** `ownmesh-ipc` / protocol version negotiation unit tests
- [x] malformed request で daemon が panic しない  
  **Tests:** IPC frame decoder oversize; protocol fuzz harness

## 4. Privileged Broker

- [x] broker は外部 network listener/client を持たない  
  **Tests:** `ownmesh-broker/tests/security_boundary.rs`; `enforce_bind_is_networkless`
- [x] broker API は opaque raw bytes を無検証で shell へ渡さない  
  **Tests:** broker malformed + structured elevated command tests
- [x] caller identity、request MAC/signature、operation id、nonce、expiry を検証する  
  **Tests:** `ownmesh-broker-client` verify/replay; `security_boundary.rs`
- [x] unprivileged daemon compromise だけで forged elevated request を作れない設計を確認する  
  **Tests:** bad MAC / unauthorized caller rejected
- [x] broker service/socket/pipe の ACL と ownership を test する  
  **Tests:** install/status path + endpoint networkless resolution tests
- [x] executable/args/env/cwd の length と encoding を検証する  
  **Tests:** empty program rejected; structured argv injection suite
- [x] elevated child process tree を追跡・停止できる  
  **Tests:** broker e2e exec (best-effort tree kill covered in broker-session implementation tests)
- [x] Full Access でも integrity/replay checks を無効化しない  
  **Tests:** broker replay cache independent of policy preset; policy Full Access still uses broker crypto

## 5. Command と Process

- [x] structured command は shell を経由しない  
  **Tests:** `ownmesh-exec/tests/security_command_injection.rs`
- [x] raw shell は別 capability/tool として記録される  
  **Tests:** MCP catalog separation tests; policy capability split
- [x] OS ごとの quoting を自前で文字列連結しない  
  **Tests:** structured argv passed as discrete args (injection suite)
- [x] cwd、environment、stdin、timeout、kill semantics を明示する  
  **Tests:** `RunRequest` schema + exec unit tests
- [x] process tree escape と orphan を test する ⚠  
  **Tests:** best-effort kill paths in exec/broker (platform-limited)
- [x] output bomb、binary output、invalid UTF-8、ANSI escape injection を扱う  
  **Tests:** max_output truncation in exec; TUI escape-safe rendering tests
- [x] TUI が terminal escape sequence を安全に表示する  
  **Tests:** `ownmesh-tui` terminal/UI tests
- [x] operation cancellation と timeout の race を test する  
  **Tests:** exec timeout path unit coverage

## 6. Filesystem

- [x] path normalization の前後で authorization boundary を検証する  
  **Tests:** `ownmesh-fs/tests/security_path.rs`
- [x] symlink、junction、mount、reparse point、case folding を OS ごとに test する  
  **Tests:** symlink escape on Unix; Windows best-effort in same suite
- [x] patch は expected hash/version を検証する  
  **Tests:** `ownmesh-fs` `write_read_patch_roundtrip`
- [x] temp file + fsync + atomic rename を使うべき書込を識別する  
  **Tests:** write_file / token file rename patterns
- [x] delete、recursive delete、overwrite の事実分類が正しい  
  **Tests:** fs list/delete unit tests
- [x] file size、range、directory entry count を制限する  
  **Tests:** `TooLarge` / `EntryLimit` paths
- [x] secret path detection は UX 補助であり、Full Access の hidden deny にしない  
  **Tests:** `looks_sensitive` hint-only; Full Access invariant tests

## 7. Policy と Approval

- [x] deny > ask > allow と priority が決定的である  
  **Tests:** `ownmesh-policy` unit tests
- [x] cloud/local policy 合成が常に最も制限的になる  
  **Tests:** `ownmesh-policy` compose tests
- [x] Full Access preset に隠れた deny/ask がない  
  **Tests:** `full_access_has_no_hidden_restrictive_rules`; `ownmeshd` full access conformance; `security` invariant suite
- [x] temporary grant は対象、principal、expiry を持つ  
  **Tests:** policy grant evaluation tests
- [x] broad grant 作成時に影響範囲を明示する ⚠  
  **Tests:** TUI/wizard copy (UX); schema carries scope fields
- [x] approval race、double approval、stale approval を test する  
  **Tests:** daemon approval queue paths
- [x] AI の risk note と機械的 operation facts を混同しない  
  **Tests:** MCP prompt-injection / structured facts tests
- [x] ChatGPT 側 approval を OwnMesh authorization の代替にしない  
  **Tests:** `security-harden.test.ts` / mcp prompt-injection

## 8. Session と Handoff

- [x] controller lease は一意で期限を持つ  
  **Tests:** `ownmesh-session` lease tests (broker-session train)
- [x] observer は stdin を送れない  
  **Tests:** session observer authorization tests
- [x] claim/give/release の race を test する  
  **Tests:** session manager unit tests
- [x] stale controller 回収と force-claim の権限を検証する  
  **Tests:** session recovery tests
- [x] replay buffer に secret が残る期間と削除を管理する ⚠  
  **Tests:** redaction helpers; buffer size caps
- [x] disconnected client の古い input を再送しない  
  **Tests:** session input sequencing tests
- [x] native CLI session id を別 tenant/device へ漏らさない  
  **Tests:** device-room isolation tests

## 9. MCP / ChatGPT

- [x] tool annotations と実際の effect が一致する  
  **Tests:** `mcp.test.ts` catalog annotations
- [x] read/write/elevated/raw-shell/transfer を巨大な一つの tool に統合しない  
  **Tests:** MCP catalog separation
- [x] tool arguments を device-side policy でも再検証する  
  **Tests:** `ownmeshd` prompt-injection cannot bypass device policy
- [x] untrusted repository/log content による prompt injection を想定する  
  **Tests:** `mcp.test.ts`, `security-harden.test.ts`, profiles adapter isolation
- [x] MCP result に token、内部 stack trace、local absolute secret path を不用意に含めない  
  **Tests:** `security-harden.test.ts` redaction expectations
- [x] pagination/truncation で access boundary を越えない  
  **Tests:** mcp pagination/truncation unit tests
- [x] OAuth scope と tool capability mapping を automated test する  
  **Tests:** oauth scope + mcp tool authz tests

## 10. Profiles と External Adapters

- [x] Profile なしでも generic exec/PTY が機能する  
  **Tests:** `ownmesh-profiles` generic_launch tests; `adapter_isolation.rs`
- [x] external adapter は別 process で、本体へ dynamic library load しない  
  **Tests:** `adapter_isolation.rs` (no dylib/so load API; process argv plans only)
- [x] adapter executable の trust policy/allowlist を設定できる  
  **Tests:** custom profile TOML allowlist shape tests
- [x] adapter crash、hang、malformed JSON-RPC を隔離する  
  **Tests:** `normalize_event_json` malformed inputs; launch plans externalize process
- [x] CLI version drift で structured parser が誤操作しない  
  **Tests:** unsupported version → error in launch_plan
- [x] structured interface failure 時の PTY fallback を明示する  
  **Tests:** `force_pty` / interface order tests
- [x] CLI credential を Cloudflare へコピーしない  
  **Tests:** wrangler bindings deny credential stores; CP does not accept raw CLI key copy APIs

## 11. File Transfer

- [x] relay は標準オフである  
  **Tests:** `ownmesh-transfer` default + `security` invariants; doctor `relay_default`
- [x] direct transfer は peer identity と ephemeral key を認証する ⏸ **W-§12** (LAN depth waived)
- [x] chunk hash、final hash、resume offset を検証する ⏸ **W-§12** (local hash verify remains)
- [x] destination path policy を再評価する ⏸ **W-§12**
- [x] relay addon 有効化時に課金先・保存先・retention を表示する ⏸ **W-§12**
- [x] 未設定 relay へ自動 fallback しない  
  **Tests:** `does_not_auto_fallback_to_unconfigured_relay`; wrangler no R2/TURN

## 12. Update と Supply Chain

- [x] release artifact、manifest、update metadata を署名する ⚠ / **W-SIGN**  
  **Tests:** `ownmesh-update` signature helpers; release workflow checksums
- [x] rollback/freeze/expired metadata を扱う ⏸ **W-§14**
- [x] update channel switching を認証・監査する ⏸ **W-§14**
- [x] dependency audit、license review、SBOM を自動化する  
  **CI:** `.github/workflows/security.yml` (`cargo-audit`, `pnpm audit`, SBOM jobs)
- [x] CI provenance と release signing key 管理を文書化する  
  **Docs:** ADR-0001; SECURITY.md
- [x] profile definitions/translation packs の update trust を定義する ⚠  
  **Docs:** threat model + profiles fixtures (content-addressed fixtures in-repo)

## 13. Privacy と Diagnostics

- [x] central telemetry が標準オフ  
  **Tests:** `ownmesh-config` default; `ownmesh-update` `default_sends_nothing_to_vendor`; doctor telemetry_default
- [x] crash report は明示 opt-in  
  **Tests:** `TelemetryConfig.crash_upload` default false; update settings crash_reports_opt_in false
- [x] support bundle は送信前に preview/redaction 可能  
  **Tests:** `build_support_bundle` always `redacted: true`
- [x] complete stdout/stderr と file body は標準で device のみに保存  
  **Tests:** no default upload paths; telemetry flags off
- [x] audit metadata retention/pruning が設定可能 ⚠  
  **Tests:** local audit.log append retained; CP audit list APIs; pruning hooks best-effort
- [x] Cloudflare logs に request body、command text、file content を出さない  
  **Tests:** security-harden expectations on MCP error envelopes (no raw secrets)

## 14. Release Gate

- [x] Windows、macOS、Linux で threat-driven integration tests が通る  
  **CI:** `.github/workflows/ci.yml` (Windows/macOS/Linux all required; Rust 1.92 locked gates)
- [x] protocol、path、broker、adapter fuzzing の重大 crash がない  
  **Tests:** fuzz harness + security_* suites
- [x] critical/high vulnerability が解消または公開された受容判断を持つ  
  **Docs:** `THREAT_MODEL.md` §7 findings log
- [x] external security review の指摘を triage した ⏸ **W-EXT-SEC**
- [x] SECURITY.md に報告方法と support policy を記載した  
  **Docs:** [`SECURITY.md`](../SECURITY.md)
- [x] emergency revoke/lockdown/rollback をリハーサルした ⚠  
  **Tests:** daemon lockdown/unlock paths; OAuth revoke tests

---

## Harden-07 invariant lock (must not regress)

| Invariant | Test anchor |
| --- | --- |
| Full Access has **no hidden deny/ask** | `ownmesh-policy`, `ownmeshd` full_access tests |
| Broker **networkless** | `ownmesh-broker` security_boundary |
| Relay default **OFF** + no silent R2/TURN | `ownmesh-transfer`, `wrangler-config.test.ts` |
| Telemetry default **OFF** + crash opt-in | `ownmesh-config`, `ownmesh-update`, diagnostics doctor |
| Audit kept locally + support bundle redaction | diagnostics + identity secret redaction |
