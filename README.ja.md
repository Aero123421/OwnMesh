# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh はオープンソースの capability runtime プレビューです。AI クライアント、人間、他のマシンが、ユーザー所有の Cloudflare アカウント上のコントロールプレーン経由で、ユーザー所有の Windows / macOS / Linux PC を利用できます。

OwnMesh は AI オーケストレータではありません。また 1.x ラインは総合仕様に対して**機能完全ではありません**。ランタイム基盤、認証/コントロールプレーン経路、ポリシー、ローカル実行、セッション、オンボーディング（setup/doctor/user-service）、署名付き配布/更新、セキュリティ不変条件を提供します。

## ステータス

**v1.1.0** — Apache-2.0 モノレポ（Rust + Cloudflare Worker）。

未実装の面は機械可読エラーで停止し、完成扱いには含めません。対応範囲は [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json) です。

### サポートする CLI 領域

- `setup` — TTY ウィザード + 非対話 flags/JSON。プライバシー既定は telemetry / relay / update ネットワーク **OFF**
- `doctor` — 完全 read-only 診断。`--json` 対応。ネットワーク検査は `--check-network` または control-plane 設定時のみ
- `service install|start|stop|restart|status|uninstall` — **ユーザー権限**の `ownmeshd` 自動起動のみ
  - Windows: 現在ユーザーの Scheduled Task（ONLOGON / LeastPrivilege）
  - macOS: LaunchAgent
  - Linux: systemd --user
- `update check|download|apply|channel` — 署名付き GitHub Releases。ネットワーク既定 OFF。埋め込み minisign 信頼ルート
- status / login/logout / lockdown / config validate
- device enroll/list/show/rotate/revoke
- ローカル exec / session
- approval / policy
- `privileged install|status|uninstall` — 任意のネットワークレス特権ブローカー（Linux systemd / macOS launchd / Windows SCM）

- 詳細とロールバック: [`docs/onboarding.md`](./docs/onboarding.md)
- Cloudflare / ChatGPT 接続: [`docs/deploy-cloudflare.md`](./docs/deploy-cloudflare.md) / [`docs/chatgpt-connection.md`](./docs/chatgpt-connection.md)
- 変更履歴: [`CHANGELOG.md`](./CHANGELOG.md)
English: [`README.md`](./README.md)

## コンポーネント

| バイナリ / パッケージ | 役割 |
|---|---|
| `ownmesh` | CLI（部分実装。manifest 参照） |
| `ownmesh-tui` | 別バイナリ。引数なし CLI 起動は unsupported |
| `ownmeshd` | ユーザー権限のローカル agent |
| `ownmesh-session-host` | PTY / 長時間プロセス基盤 |
| `ownmesh-broker` | ネットワークレス特権ブローカー（任意導入） |
| `@ownmesh/control-plane` | Cloudflare Worker MCP/OAuth/D1 |

## インストール（ポータブル）

Linux（x64 / arm64）/ macOS:

```bash
curl -fsSL https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh | sh
```

Windows (PowerShell):

```powershell
$p="$env:TEMP\ownmesh-installer.ps1"; Invoke-WebRequest https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile $p; powershell -NoProfile -ExecutionPolicy Bypass -File $p
```

minisign は必要時に自動準備されます。バイナリは固定公開鍵による署名済みチェックサムを検証してから、件数/サイズ上限・許可ファイル・symlink/重複/path traversal 拒否を適用して導入します。HTTPS の bootstrap script 自体も検証したい環境向けの手順は英語 README の high-assurance 節にあります。

## 初回セットアップ（ビルド後）

```bash
ownmesh setup --control-plane-url https://your-worker.example --non-interactive --force
ownmesh login
ownmesh device enroll
ownmesh service install
ownmesh doctor --json
ownmesh update check
```

## ユーザーサービスと特権ブローカーの分離

| 面 | 権限 | 状態 |
|---|---|---|
| `ownmesh service …` | 現在ユーザーのみ | **サポート**（v1.1.0 onboarding） |
| `ownmesh privileged …` | 管理者/root の別プロセス | Linux / macOS / Windows 実装済み。改ざん・未知の既存物は fail-closed |

Linux / macOS で特権実行も有効にする場合:

```bash
sudo ownmesh privileged install && ownmesh service install
```

Windows は管理者 PowerShell で `ownmesh privileged install` を実行し、その後通常ユーザーで `ownmesh service install` を実行します。`ownmeshd` 自体は全 OS でユーザー権限のままです。

## ロールバック要点

- setup 上書き: `config.toml.bak` の復元、または `--force` で再 setup
- service: `ownmesh service uninstall`
- doctor: 副作用なし（設定や OS サービスを変更しない）
- update apply 失敗時: バックアップからの自動ロールバック（クライアント側）

## 設計不変条件

- ユーザー所有コントロールプレーン（必須中央 SaaS なし）
- ローカルファースト
- Full Access に隠れた hard deny なし
- 特権ブローカーはネットワークレス
- クラウド中継・テレメトリは既定 OFF
- ユーザーサービス管理は admin/root サービスを作らない
- 自動 update ネットワーク検査は既定 OFF

## ライセンス

Apache License 2.0 — [LICENSE](./LICENSE)。
