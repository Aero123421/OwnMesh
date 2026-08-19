# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh は、セルフホスト型のオープンソース capability runtime です。
ChatGPT などの MCP クライアントから、自分が所有する Windows / macOS /
Linux マシンを、自分の Cloudflare アカウントに置いたコントロールプレーン
経由で利用できます。

OwnMesh は AI オーケストレータでも、ベンダー管理の中央 SaaS でもありません。
通常の Agent はユーザー権限で動き、明示的に承認された特権処理だけを、任意導入の
ネットワークレス・ブローカーに渡します。

## ステータス

**v1.2.16 正式安定版** — Apache-2.0 モノレポ（Rust + Cloudflare Worker）。

公開する CLI サーフェスに、意図的な未実装項目は残っていません。機械検査される
正本は [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json)
です。ここでの「完成」は、この公開対象がすべて fail-closed で実装されているという
意味です。将来仕様の全項目や、すべてのネイティブ配布形式まで完了したという意味では
ありません。

### 主な機能

- デスクトップと SSH/Ubuntu Server の1コマンド初期設定、read-only の
  `doctor`、ユーザーサービス管理、統一されたダーク系 TUI。
- ChatGPT 対応 MCP OAuth、動的クライアント登録、ローテーションする refresh
  token、単一オーナー向け passkey ログイン、厳密な callback 検証。
- device の enroll/list/show/rename/labels/key rotation/revoke。
- ローカル実行と認証済み remote exec/session。remote mutation は明示的な
  idempotency key が必須で、ローカル実行へ黙ってフォールバックしません。
- 承認済み command は invocation entry、backing executable、classification、
  `argv[0]` を厳密に拘束し、実行ファイルの drift は spawn 前に拒否します。
- 9種類の AI CLI profile と、scan/list/show/login/test/start/resume。
- approval list/show/watch/approve/deny、policy の検査・preset・構造化 rule 更新、
  lockdown/unlock、token revoke。
- セキュリティ管理操作は、対象操作に結び付いた fresh passkey 承認後に1回だけ実行。
- 認証済み・再開可能・上限付きの端末間 transfer と
  plan/send/list/status/cancel CLI。宛先の置換は `overwrite_expected_sha256` が一致するときのみ。盲上書き/force フォールバックなし。
- `ownmesh mcp serve --stdio`。設定済み issuer と OS credential store を使う
  上限付き JSONL bridge で、stdout に秘密や診断ログを混ぜません。

## インストール

通常インストーラーは、リリース署名と checksum を検証してから導入します。

Linux / macOS:

```bash
curl -fsSL https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh | sh
```

Windows PowerShell:

```powershell
$p="$env:TEMP\ownmesh-installer.ps1"; Invoke-WebRequest https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

macOS の 1 行インストールは、署名検証用の `minisign` を入手するために
[Homebrew](https://brew.sh) を必要とします。自分で `minisign` を導入するか、
`OWNMESH_MINISIGN` で既存のバイナリを指定すれば不要です。Linux では、
`minisign` が無い場合に hash 固定の版を installer が取得します。

より厳密に確認する場合は、installer と `SHA256SUMS`、`SHA256SUMS.minisig`
をダウンロードし、署名と installer の checksum を検証してから実行してください。

公開鍵は、検証対象のリリースからではなく **帯域外** で入手してください。
リリース資産は自分自身を保証できません。クローンした
[`docs/release-keys/minisign.pub`](./docs/release-keys/minisign.pub) を使い、
key ID が `C596813EFB0946A4` であることを確認します。同じ鍵が installer と
`ownmesh update` にも埋め込まれており、3 つの経路が同一の trust root を共有
します。リリースに同梱される `minisign.pub` は、key ID を既に知っている人向けの
補助にすぎません。

installer 本体も、展開数/サイズ上限、許可ファイル一覧、path traversal・link・
device・重複拒否を適用します。既存のportable installを更新するときは、導入先と
完全一致するOwnMesh processだけを停止し、以前動いていたserviceを再起動してversion
を確認します。更新後のhealth確認に失敗した場合は旧バイナリへ戻します。

初回インストール後は、Windows / macOS / Linux のすべてで次の1コマンドです。

```bash
ownmesh update
```

同じ署名チェーンを再検証し、session の終了、ユーザーサービスの停止、5バイナリの
一括置換、以前動作していたサービスの再起動、CLI/daemon のversion確認までを自動で
行います。失敗時は旧バイナリへrollbackします。Windowsではprivateな一時workerへ
引き継いでから親CLIを終了するため、導入済み`ownmesh.exe`自身によるfile lockを
避けます。進行状況は`ownmesh update status`で確認できます。Homebrew管理下では
引き続き`brew upgrade ownmesh`を使います。

## 初回セットアップ

### 1. コントロールプレーンを導入する

以降のすべての手順でその URL が必要になるため、ここから始めます。クローンから:

```bash
cd packages/control-plane && corepack enable && pnpm install --frozen-lockfile && pnpm run deploy:guided
```

guided deploy は D1 を作成または再利用し、migration、Worker deploy、必要な
secret 設定を行い、オーナーログイン URL、ChatGPT MCP URL、そして手順 2 で
そのまま使える `ownmesh setup` コマンドを表示します。詳細は
[`docs/deploy-cloudflare.md`](./docs/deploy-cloudflare.md) と
[`docs/chatgpt-connection.md`](./docs/chatgpt-connection.md) を参照してください。

### 2. マシンを接続する

デスクトップでは TUI を起動し、**セットアップ**を選びます。Worker URL と
アクセス範囲を選ぶと、ログイン・PC登録・Agentの自動起動まで順番に行います:

```bash
ownmesh
```

同じ処理を直接CLIで行う場合:

```bash
ownmesh setup --control-plane-url https://your-worker.example --quickstart
```

SSH / Ubuntu Server（URL と短いコードを表示し、別端末から承認）。TUIでも
同じURL＋コード方式を使えます:

```bash
ownmesh setup --control-plane-url https://your-worker.example --quickstart --device-login --non-interactive --force
```

### 3. 確認する

読み取り専用で、状態を変更しません。`--check-network` を付けると
コントロールプレーンの `/health` も確認します:

```bash
ownmesh doctor --json
```

## セキュリティ設計

- 必須の中央 SaaS はなく、コントロールプレーンはユーザー所有。
- telemetry、cloud relay、自動 update のネットワーク確認は既定 OFF。
- 明示的な処理を除き、ファイル・コマンド出力・ログはローカルに保持。
- OAuth/device credential は `config.toml` ではなく OS credential store に保存。
- セキュリティ管理操作は型付きです。任意の method/params を通す裏口はありません。
  同一ユーザーのローカル socket だけでは、人間の存在証明として扱いません。
- 通常の `ownmeshd` は全 OS でユーザー権限。任意の特権ブローカーはネットワークレス。
- Full Access に隠れた hard deny はありません。選択した policy の
  allow/ask/deny はそのまま適用されます。

特権実行が必要な場合だけ、別途導入します。

```bash
sudo ownmesh privileged install && ownmesh service install
```

Windows では Administrator PowerShell で `ownmesh privileged install` を実行し、
通常ユーザーに戻って `ownmesh service install` を実行します。

## 実装と実機証跡の区別

Windows x64、macOS arm64/x64、Linux musl arm64/x64 の portable archive を
対象に、LICENSE/NOTICE/release notes、CycloneDX SBOM、SHA-256 checksum、必須の
minisign 署名、GitHub build provenance を生成します。

ネットワークレス特権ブローカーの lifecycle は Linux / macOS / Windows に
実装済みです。Linux は root 実機 receipt 取得済みですが、macOS/Windows の
native release receipt と、公開 MCP → installed Agent → broker の E8 receipt は
未取得です。これらの経路を実機証明済みとは表現しません。Authenticode、Apple
notarization、MSI/NSIS、macOS native package は v1.2.16 の対象外です。

ChatGPT の動的登録、OAuth、passkey return、refresh、MCP link は手動の live
互換 receipt があります。local workerd suite は再現可能ですが、外部 ChatGPT を
含む完全自動 E10 receipt は今後の検証項目です。

## 開発ゲート

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
pnpm install --frozen-lockfile
pnpm -r test
pnpm -r typecheck
pnpm -r lint
```

## ドキュメント

- [English README](./README.md)
- [公開サーフェス](./release/SUPPORTED_SURFACES.json)
- [初期設定とサービス](./docs/onboarding.md)
- [Cloudflare deployment](./docs/deploy-cloudflare.md)
- [ChatGPT connection](./docs/chatgpt-connection.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [ロードマップ](./docs/ROADMAP.md) — 次に何をやり、何をやらないか
- [v1.2.16 release notes](./docs/RELEASE_NOTES_v1.2.16.md)
- [目標仕様](./OWNMESH_SPECIFICATION.ja.md) — 将来ロードマップの正本

## ライセンス

Apache License 2.0 — [LICENSE](./LICENSE)。
