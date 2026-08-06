# OwnMesh 1.0 実装チェックリスト

このチェックリストは [`OWNMESH_SPECIFICATION.ja.md`](./OWNMESH_SPECIFICATION.ja.md) の実装進行用です。機能を削った MVP ではなく、OwnMesh 1.0 全体を安全な依存順で完成させるために使用します。

## 0. Repository と開発基盤

- [x] Apache-2.0 `LICENSE` を追加する
- [x] `README.md`、`SECURITY.md`、`CONTRIBUTING.md`、`CODE_OF_CONDUCT.md` を追加する
- [x] Rust workspace と TypeScript workspace を初期化する
- [x] `rust-toolchain.toml` と Node/pnpm バージョンを固定する
- [x] formatter、linter、unit test、schema validation を CI に追加する
- [x] Renovate または Dependabot を設定する
- [x] ADR ディレクトリを作成する
- [x] release signing、SBOM、provenance の方式を ADR で確定する

**完了条件:** 空の skeleton が Windows、macOS、Linux、Cloudflare Worker の CI を通る。

## 1. Domain、Schema、Protocol

- [x] `Tenant`、`Principal`、`Membership`、`Device`、`Workspace` を実装する
- [x] `CapabilityGrant`、`PolicyRule`、`Approval` を実装する
- [x] `Operation`、`Session`、`AuditEvent` を実装する
- [x] 安定 ID 形式と parser を実装する
- [x] 時刻、expiry、cursor、pagination 型を共通化する
- [x] エラー taxonomy と exit code を実装する
- [x] Device Protocol envelope と version negotiation を実装する
- [x] JSON Schema と Rust/TypeScript 型の整合性 test を追加する
- [x] protocol parser fuzz target を追加する

**完了条件:** Rust と TypeScript が同じ fixtures を読み書きし、round-trip test に成功する。

## 2. Local IPC とプロセス構成

- [x] `ownmesh` CLI skeleton
- [x] `ownmesh-tui` skeleton
- [x] `ownmeshd` user daemon skeleton
- [x] `ownmesh-session-host` skeleton
- [x] OS ごとの local IPC transport
- [x] peer credential / ACL verification
- [x] request correlation、timeout、cancellation
- [x] daemon restart と client reconnect
- [x] panic/abnormal exit 時の terminal restoration

**完了条件:** TUI と CLI が daemon の status を取得し、認証されていない local process は IPC を利用できない。

## 3. Config、Identity、Keychain

- [x] OS ごとの config/state/runtime path
- [x] TOML loader、migration、atomic write、backup
- [x] config/policy schema validation
- [x] device key generation と rotation
- [x] Windows Credential Manager / DPAPI
- [x] macOS Keychain
- [x] Linux Secret Service
- [x] headless Linux encrypted keystore fallback
- [x] secret をログ・config へ平文出力しない test

**完了条件:** device credential と human refresh token が用途別に保存され、再起動後も安全に復元できる。

## 4. Cloudflare Control Plane

- [ ] Workers entrypoint と `/mcp`
- [ ] OAuth metadata endpoints
- [ ] D1 migrations
- [ ] Device registry
- [ ] Principal / OAuth client / grant tables
- [ ] Durable Object device room
- [ ] WebSocket hibernation 対応
- [ ] operation routing
- [ ] audit metadata
- [ ] Deploy to Cloudflare configuration
- [ ] R2/TURN が標準 provision されないことを test

**完了条件:** 新しい Cloudflare account へ one-click deploy し、health check と migration が成功する。

## 5. OAuth、Login、Enrollment

- [ ] Authorization Code + PKCE
- [ ] Device Authorization flow
- [ ] OAuth Protected Resource Metadata
- [ ] Dynamic Client Registration / Client ID Metadata Document 対応方針
- [ ] refresh token rotation と reuse detection
- [ ] redirect URI exact match
- [ ] CLI browser callback
- [ ] CLI device-code fallback
- [ ] device enrollment challenge/proof
- [ ] device revoke と key rotation
- [ ] ChatGPT Personal Plugin 接続手順を integration test する

**完了条件:** CLI、ChatGPT、device agent が別 credential と scope で接続でき、失効が即時反映される。

## 6. Command、Process、Filesystem、Logs

- [x] structured command execution
- [x] raw shell execution
- [x] environment と working directory
- [x] timeout、cancel、process tree kill
- [x] stdout/stderr 分離
- [x] bounded output と local spool
- [x] idempotency journal
- [x] file list/stat/search/read/write/delete
- [x] hash-checked patch apply
- [x] canonical path と symlink/junction/reparse-point test
- [ ] Git status/diff
- [ ] Windows Event Log provider
- [ ] journald/systemd provider
- [ ] Docker/process/file log providers
- [x] cursor-based log query

**完了条件:** 3 OS で generic command と file/log 操作が同じ契約で動き、重複 operation が再実行されない。

## 7. Policy、Approval、Full Access

- [x] allow / ask / deny evaluator
- [x] cloud policy と local policy の合成
- [x] rule priority と deny > ask > allow
- [x] operation facts classifier
- [x] Recommended preset
- [x] Workspace Only preset
- [x] Full User Access preset
- [x] Full Access preset
- [ ] Custom policy editor API
- [x] temporary grant と scope
- [ ] TUI approval queue
- [x] CLI approval commands
- [ ] one-time browser approval page
- [x] lockdown / unlock / token revoke
- [x] Full Access に隠れた hard deny がないことを conformance test

**完了条件:** ユーザーが全 allow を選択した場合は追加確認なしで実行され、ask rule の場合だけ明示承認が必要になる。

## 8. Privileged Broker

- [ ] protocol と capability token
- [ ] networkless design を enforcement
- [ ] Windows Service + Named Pipe ACL
- [ ] macOS LaunchDaemon + Unix socket + code signature check
- [ ] Linux systemd service + `SO_PEERCRED`
- [ ] nonce / expiry / replay protection
- [ ] structured elevated command
- [ ] elevated process tree lifecycle
- [ ] install/uninstall/status CLI
- [ ] malformed request fuzzing
- [ ] unprivileged caller rejection test

**完了条件:** `ownmeshd` は一般ユーザーのまま、Full Access 時だけ broker 経由で管理者/root 操作を実行できる。

## 9. PTY、Session、Handoff

- [ ] PTY/ConPTY abstraction
- [ ] session host supervision
- [ ] detached session persistence
- [ ] output sequence と replay buffer
- [ ] observer attach
- [ ] controller lease
- [ ] claim/release/give
- [ ] stale controller recovery
- [ ] resize/input/close/terminate
- [ ] raw/cooked view
- [ ] native agent session id mapping
- [ ] context bundle

**完了条件:** ChatGPT が開始した session を人間が取得し、人間の操作中も ChatGPT が observer として出力を読める。

## 10. MCP と ChatGPT

- [ ] Streamable HTTP `/mcp`
- [ ] OAuth scopes と tool authorization
- [ ] discovery/read tools
- [ ] write/execute tools
- [ ] raw shell と elevated tool の分離
- [ ] annotations (`readOnlyHint` 等)
- [ ] stable result/error envelope
- [ ] pagination と truncation
- [ ] asynchronous operation pattern
- [ ] approval-required response
- [ ] Personal Plugin 接続テスト
- [ ] 通常 Chat での read/write/session 実地テスト
- [ ] permission mode 別の挙動確認
- [ ] prompt-injection security tests

**完了条件:** ChatGPT の通常 Chat から device、file、command、session の主要操作が行え、OwnMesh policy が最終的に強制される。

## 11. 公式 Profile 9 種

共通:

- [ ] detect/version/auth status
- [ ] best interface selection
- [ ] structured event normalization
- [ ] PTY fallback
- [ ] native resume（利用可能なもの）
- [ ] version compatibility matrix
- [ ] fixture-based conformance tests

個別:

- [ ] Codex CLI
- [ ] Claude Code
- [ ] Kimi Code
- [ ] OpenCode
- [ ] Pi Coding Agent
- [ ] Antigravity CLI (`agy`)
- [ ] Qwen Code
- [ ] Hermes Agent
- [ ] Qoder CLI

Generic:

- [ ] Profile なしの任意 command 実行
- [ ] Profile なしの任意 interactive CLI session

**完了条件:** 公式 9 Profile が対応 version で test を通り、未知 CLI は登録なしで実行できる。

## 12. P2P File Transfer

- [ ] transfer plan
- [ ] sender/receiver consent と capability
- [ ] local/LAN discovery
- [ ] direct encrypted transfer
- [ ] chunking、resume、hash verification
- [ ] rate/size limits
- [ ] destination path policy
- [ ] relay addon interface
- [ ] relay disabled default
- [ ] R2/TURN が勝手に fallback されない test

**完了条件:** 直接経路がない場合は明確に失敗し、未設定のクラウド中継へデータを送らない。

## 13. Rich TUI と多言語

- [ ] Obsidian theme
- [ ] 24-bit/256/16-color fallback
- [ ] ASCII fallback
- [ ] Dashboard
- [ ] Devices
- [ ] Workspaces
- [ ] Sessions
- [ ] Profiles
- [ ] Approvals
- [ ] Transfers
- [ ] Activity/Audit
- [ ] Diagnostics
- [ ] Settings
- [ ] `Ctrl+K` command palette
- [ ] setup wizard
- [ ] context help / F1
- [ ] responsive 80x24 / wide layout
- [ ] mouse optional support
- [ ] en-US
- [ ] ja-JP
- [ ] zh-Hans
- [ ] ru-RU
- [ ] translation completeness CI
- [ ] CJK width and Russian overflow snapshots
- [ ] no-color / high-contrast / reduced-motion modes

**完了条件:** 初見の利用者が英語以外でも説明を読みながら setup、権限設定、profile 検出、ChatGPT 接続確認を完了できる。

## 14. Update、Diagnostics、Audit、Privacy

- [ ] update mode: off/check/notify/download/auto
- [ ] stable/beta/nightly channels
- [ ] signature verification
- [ ] rollback
- [ ] protocol compatibility warning
- [ ] `ownmesh doctor`
- [ ] support bundle preview/redaction
- [ ] local metrics
- [ ] central telemetry disabled by default
- [ ] crash report explicit opt-in
- [ ] audit retention and pruning
- [ ] sensitive output redaction

**完了条件:** 更新、診断、監査を利用でき、OwnMesh 運営者へ標準状態で何も送信されない。

## 15. Security Hardening

- [ ] threat model review
- [ ] auth/token tests
- [ ] replay/idempotency tests
- [ ] path traversal/symlink/race tests
- [ ] command argument injection tests
- [ ] privileged broker boundary tests
- [ ] local IPC spoofing tests
- [ ] WebSocket parser fuzzing
- [ ] adapter isolation tests
- [ ] prompt-injection scenarios
- [ ] dependency audit
- [ ] SAST/secret scanning
- [ ] SBOM
- [ ] signed artifacts/provenance
- [ ] external security review before 1.0

**完了条件:** critical/high finding が解消または公開された受容判断を持ち、再現可能な検証証拠が残る。

## 16. Packaging と OSS Release

- [ ] Windows installer/package
- [ ] macOS universal binaries/package
- [ ] Linux packages/binaries
- [ ] shell completions
- [ ] signed checksums
- [ ] install/uninstall documentation
- [ ] Cloudflare deployment guide
- [ ] ChatGPT connection guide
- [ ] profile compatibility table
- [ ] troubleshooting guide
- [ ] architecture diagrams
- [ ] contributor setup
- [ ] release notes
- [ ] public roadmap/issues

**OwnMesh 1.0 完了条件:** 総合仕様書の「OwnMesh 1.0 Definition of Done」を全項目満たす。
