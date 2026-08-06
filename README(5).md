# OwnMesh 仕様書バンドル

このディレクトリは、OwnMesh 1.0 を実装し、Apache-2.0 の OSS として公開するための設計基準一式です。

## 最初に読む文書

- [`OWNMESH_SPECIFICATION.ja.md`](./OWNMESH_SPECIFICATION.ja.md) — 製品、アーキテクチャ、認証、権限、実行、セッション、MCP、ChatGPT、CLI/TUI、多言語、テスト、リリースまでを含む総合仕様書。
- [`IMPLEMENTATION_CHECKLIST.md`](./IMPLEMENTATION_CHECKLIST.md) — 総合仕様を実装作業へ分解した完了条件付きチェックリスト。
- [`docs/SECURITY_REVIEW_CHECKLIST.md`](./docs/SECURITY_REVIEW_CHECKLIST.md) — 特権境界、認証、コマンド実行、パス処理、更新などのセキュリティ確認表。
- [`docs/ADR_TEMPLATE.md`](./docs/ADR_TEMPLATE.md) — 重要な設計変更を記録する ADR テンプレート。

## 固定済みの主要方針

- **製品名:** OwnMesh
- **目的:** AI や人間が、ユーザー所有のコントロールプレーン経由で任意 PC の能力を利用する Capability Runtime
- **役割:** ChatGPT、各コーディング CLI、人間の上下関係や役割を固定しない
- **ローカル実装:** Rust
- **TUI:** Rust / Ratatui / Crossterm。リッチ、かっこよく、シンプル
- **コントロールプレーン:** TypeScript / Cloudflare Workers / D1 / Durable Objects
- **ChatGPT:** Personal Plugin + Remote MCP + OAuth。通常 Chat を主対象
- **権限:** Workspace Only から Full Access まで初期設定で選択可能
- **管理者権限:** ネットワークを持たない独立 Privileged Broker
- **確認:** allow / ask / deny。Full Access では全 allow を選択可能
- **セッション:** 複数 observer、原則一つの controller lease
- **ファイル中継:** 標準オフ
- **テレメトリ:** 標準オフ
- **ライセンス:** Apache-2.0
- **公式言語:** English、日本語、简体中文、Русский

## 公式 CLI Profile

OwnMesh 1.0 は次の 9 種を公式に対応します。

1. OpenAI Codex CLI
2. Claude Code
3. Kimi Code
4. OpenCode
5. Pi Coding Agent
6. Antigravity CLI (`agy`)
7. Qwen Code
8. Hermes Agent
9. Qoder CLI

Gemini CLI、Cline、Goose、Kiro CLI、Amp は公式同梱 Profile に含めません。任意 CLI は Profile 登録なしで `ownmesh exec` または `ownmesh session open` から直接実行できます。Profile は自動検出、認証状態、構造化出力、native resume などを追加するための任意機能です。

## 設定例

- [`examples/ownmesh.example.toml`](./examples/ownmesh.example.toml) — ローカル設定例
- [`examples/policy.recommended.toml`](./examples/policy.recommended.toml) — 推奨プリセット相当の確認ポリシー
- [`examples/policy.full-access.toml`](./examples/policy.full-access.toml) — 追加確認なしの Full Access 例
- [`examples/profile.custom.toml`](./examples/profile.custom.toml) — 任意 CLI に補助情報を与える Profile 例

## 機械可読ファイル

- [`schemas/config.schema.json`](./schemas/config.schema.json)
- [`schemas/policy.schema.json`](./schemas/policy.schema.json)
- [`schemas/profile.schema.json`](./schemas/profile.schema.json)
- [`schemas/protocol-envelope.schema.json`](./schemas/protocol-envelope.schema.json)
- [`schemas/mcp-tool-catalog.json`](./schemas/mcp-tool-catalog.json)

これらは初期コード生成の参考定義です。実装開始後は Rust 型、TypeScript 型、JSON Schema を同じ正本から生成し、手作業の重複を減らしてください。

## 推奨する実装開始順

```text
1. domain / error / schema / protocol
2. local IPC / daemon / TUI skeleton
3. identity / keychain / config
4. Cloudflare control plane
5. OAuth / CLI login / device enrollment
6. command / process / filesystem / logs
7. policy / approval / Full Access
8. privileged broker
9. PTY / session / handoff
10. MCP / ChatGPT integration
11. official profiles
12. P2P transfer
13. rich TUI / i18n
14. update / diagnostics / audit
15. security hardening / cross-platform verification
16. signed OSS release
```

## 文書と実装の更新ルール

- 破壊的なプロトコル変更、権限境界変更、OAuth 方針変更、公式 Profile の追加・削除は ADR を必須とします。
- MCP、Cloudflare、各 CLI の外部仕様は変化するため、実装時とリリース前に公式資料で再検証します。
- 本書とコードが食い違った場合、黙ってコードへ合わせず、仕様更新または ADR で意図を記録します。
