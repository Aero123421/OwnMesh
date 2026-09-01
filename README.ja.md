# OwnMesh

OwnMesh は、ChatGPT などの AI クライアントから、自分の Windows / macOS /
Linux マシンを使えるようにするソフトウェアです。すべてセルフホストです。
各デバイスにはオープンソースの Agent を入れ、コントロールプレーンは
自分の Cloudflare アカウントにデプロイした Cloudflare Worker として動きます。
ベンダー管理のサービスはなく、テレメトリも送信もありません。

AI オーケストレータでもリモートデスクトップでもありません。ローカルの
Agent はユーザー権限で動作し、特権処理は任意導入の別プロセス(ネットワーク
アクセスなしのブローカー)だけが担当します。

## できること

- **ChatGPT がそのままクライアントになる。** MCP エンドポイントを OAuth・
  動的クライアント登録・オーナー向け passkey ログイン付きで公開します。
- **複数マシンの操作。** CLI または内蔵 TUI でデバイスを登録すると、
  コマンド実行、許可パスの読み書き、ログ照会、対話セッション、マシン間
  ファイル転送ができます。
- **ポリシーは自分で決める。** すべての要求が allow/ask/deny ルールを通過
  します。承認・ポリシー変更・解除などの敏感な操作は、その操作専用の
  fresh passkey 承認を追加で要求します。
- **表示と実際の一致。** UI は検証済みの事実だけを表示します。出荷される
  CLI サーフェスは機械検査され、
  [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json)
  に正本があります。

## インストール

Linux / macOS:

```bash
curl -fsSL https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh | sh
```

Windows PowerShell:

```powershell
$p="$env:TEMP\ownmesh-installer.ps1"; Invoke-WebRequest https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

どちらの installer も、署名と checksum の検証が通ってからインストールしま
す。macOS の 1 行インストールは署名検証用の `minisign` を Homebrew で取得
します(`minisign` を自分で入れるか `OWNMESH_MINISIGN` で指定すれば不要)。
Linux では見つからない場合に hash 固定の `minisign` を取得します。

手動で確認したい場合は、installer 本体と `SHA256SUMS`、`SHA256SUMS.minisig`
をダウンロードし、実行前に検証してください。

公開鍵は、検証対象のリリースではなくリポジトリのクローンから取ってくださ
い。リリース資産は自分自身を保証できません。
[`docs/release-keys/minisign.pub`](./docs/release-keys/minisign.pub)、
key ID `C596813EFB0946A4` を確認します。同じ鍵が installer と
`ownmesh update` にも埋め込まれており、3 経路が同一の trust root を共有し
ます。

初回インストール後の更新は、全 OS 共通で 1 コマンドです。

```bash
ownmesh update
```

署名チェーンの再検証、session の終了、5 バイナリの原子置換、サービスの再
起動、version 確認までを行い、失敗時は旧バイナリへ戻します。進行状況は
`ownmesh update status` で見られます。Homebrew 管理下では引き続き
`brew upgrade ownmesh` を使います。

## セットアップ

### 1. コントロールプレーンを導入する

以降の手順で URL が必要になるため、最初に行います。

```bash
cd packages/control-plane && corepack enable && pnpm install --frozen-lockfile && pnpm run deploy:guided
```

guided deploy は D1 の作成/再利用、migration、Worker deploy、secret 設定を
行い、オーナーログイン URL と ChatGPT MCP URL、そして次のコマンドを表示し
ます。詳細は
[`docs/deploy-cloudflare.md`](./docs/deploy-cloudflare.md) と
[`docs/chatgpt-connection.md`](./docs/chatgpt-connection.md)。

### 2. マシンを接続する

デスクトップなら TUI を起動して「Finish setup」を選びます。

```bash
ownmesh
```

SSH やヘッドレス環境では、URL と短いコードが表示され、別のデバイスから承認
します。

```bash
ownmesh setup --control-plane-url https://your-worker.example --quickstart --device-login --non-interactive --force
```

### 3. 確認する

読み取り専用で、状態は変えません。`--check-network` を付けるとコントロー
ルプレーンの `/health` も確認します。

```bash
ownmesh doctor --json
```

## セキュリティ設計

- コントロールプレーンの所有者はユーザー自身。中央 SaaS は不要です。
- telemetry・cloud relay・update の自動確認は既定 OFF。ファイル、コマンド
  出力、ログは、明示的に転送しない限りローカルに留まります。
- credential は OS credential store に保存され、`config.toml` には書きませ
  ん。
- 管理操作は型付きの操作として定義されており、任意の method/params を通す
  経路はありません。同一ユーザーのローカル socket だけでは人の存在として
  扱いません。
- `ownmeshd` は常にユーザー権限です。任意の特権ブローカーはネットワークア
  クセスを持たず、必要な場合だけ別途導入します:

```bash
sudo ownmesh privileged install && ownmesh service install
```

(Windows では最初のコマンドを Administrator PowerShell で、次を通常ユーザー
で実行します。)

- Full Access に隠れた hard deny はありません。選択した policy の
  allow/ask/deny は記載どおりに適用されます。

## リリース保証と未完了項目

リリースは Windows x64 / macOS arm64・x64 / Linux musl arm64・x64 の
portable archive で提供され、SHA-256 checksum、minisign 署名、CycloneDX
SBOM、GitHub build provenance が付きます。

検証済みのことと、まだ残っていること:

- ネットワークレス特権ブローカーの lifecycle は 3 OS 実装済みです。Linux
  は root 実機 receipt を取得済み。macOS/Windows の native receipt と
  MCP → Agent → broker の一連の receipt は未取得で、実機証明済みとは表現し
  ません。
- ChatGPT の動的登録・OAuth・passkey return・refresh・MCP link には手動の
  live 互換性 receipt があります。完全自動の外部検証は今後の項目です。
- Authenticode、Apple notarization、MSI/NSIS、macOS native package はこの
  リリース列の対象外です。

## 開発

Rust 1.92 / Node 22 / pnpm 9.15.0 をリポジトリ側で固定しています。品質ゲー
ト:

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

セットアップと PR の方針は [CONTRIBUTING](./CONTRIBUTING.md) を参照。

## ドキュメント

- [English README](./README.md)
- [公開サーフェス](./release/SUPPORTED_SURFACES.json)
- [初期設定とサービス](./docs/onboarding.md)
- [Cloudflare deployment](./docs/deploy-cloudflare.md)
- [ChatGPT connection](./docs/chatgpt-connection.md)
- [Threat model](./docs/THREAT_MODEL.md)
- [ロードマップ](./docs/ROADMAP.md) — 次に何をやり、何をやらないか
- [v1.2.25 release notes](./docs/RELEASE_NOTES_v1.2.25.md)
- [目標仕様](./OWNMESH_SPECIFICATION.ja.md) — 将来ロードマップの正本

## ライセンス

Apache License 2.0 — [LICENSE](./LICENSE)。
