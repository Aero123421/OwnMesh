# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh はオープンソースの capability runtime プレビューです。AI クライアント、人間、他のマシンが、ユーザー所有の Cloudflare アカウント上のコントロールプレーン経由で、ユーザー所有の Windows / macOS / Linux PC を利用できます。

OwnMesh は AI オーケストレータではありません。また 1.x ラインは総合仕様に対して**機能完全ではありません**。ランタイム基盤、認証/コントロールプレーン経路、ポリシー、ローカル実行、セッション、オンボーディング（setup/doctor/user-service）、署名付き配布/更新、セキュリティ不変条件を提供します。

## ステータス

**v1.1.0** — Apache-2.0 モノレポ（Rust + Cloudflare Worker）。

CLI には Rust ディスパッチ登録上 **32** の明示 unsupported 面に加え、追加 hard-error 面が **7**（合計 **39**）あります。機械可読な対応範囲は [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json) です。

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
- privileged broker は **status のみ**（install/uninstall は unsupported）

詳細とロールバック: [`docs/onboarding.md`](./docs/onboarding.md)
配布/更新: [`docs/RELEASE_NOTES_v1.1.0.md`](./docs/RELEASE_NOTES_v1.1.0.md)
English: [`README.md`](./README.md)

## コンポーネント

| バイナリ / パッケージ | 役割 |
|---|---|
| `ownmesh` | CLI（部分実装。manifest 参照） |
| `ownmesh-tui` | 別バイナリ。引数なし CLI 起動は unsupported |
| `ownmeshd` | ユーザー権限のローカル agent |
| `ownmesh-session-host` | PTY / 長時間プロセス基盤 |
| `ownmesh-broker` | ネットワークレス特権ブローカー基盤（本番 install は unsupported） |
| `@ownmesh/control-plane` | Cloudflare Worker MCP/OAuth/D1 |

## インストール（ポータブル）

macOS / Linux:

```bash
# リモートスクリプトをシェルに直接流し込まないこと（curl|sh / irm|iex 禁止）
curl -fsSL -o ownmesh-installer.sh \
  https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.sh
# SHA256SUMS + SHA256SUMS.minisig を minisign で検証し、スクリプトを確認してから:
sh ./ownmesh-installer.sh
```

Windows (PowerShell):

```powershell
Invoke-WebRequest -Uri https://github.com/Aero123421/OwnMesh/releases/latest/download/ownmesh-installer.ps1 -OutFile ownmesh-installer.ps1
# minisign で署名検証・内容確認の後:
powershell -NoProfile -File .\ownmesh-installer.ps1
```

可能なら installer を一度ダウンロードして内容を確認してから実行してください。minisign 必須。チェックサム検証後、updater と同等のアーカイブ契約（件数/展開サイズ上限・必須バイナリ+文書のみ・symlink/重複/path traversal 拒否）を**展開前**に強制し、メンバー単位でステージングします（フル `tar -xzf` / `Expand-Archive` は使いません）。`tar -tvzf` が安全に使えない環境では fail-closed します。

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
| `ownmesh privileged …` | 管理者/root が必要になり得る | install/uninstall **unsupported**、status は fail-closed |

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
