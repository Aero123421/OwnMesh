# OwnMesh

> **Any AI. Any CLI. Any machine. Your cloud.**

OwnMesh はオープンソースの capability runtime プレビューです。AI クライアント、人間、他のマシンが、ユーザー所有の Cloudflare アカウント上のコントロールプレーン経由で、ユーザー所有の Windows / macOS / Linux PC を利用できます。

OwnMesh は AI オーケストレータではありません。また現行ラインは総合仕様に対して**機能完全ではありません**。ランタイム基盤、認証/コントロールプレーン経路、ポリシー、ローカル実行、セッション、オンボーディング（setup/doctor/user-service）、セキュリティ不変条件を提供します。

## ステータス

**v1.1.0 onboarding train**（ワークスペースの package version はリリース切断まで 1.0.2 のままの場合があります）— Apache-2.0 モノレポ（Rust + Cloudflare Worker）。

CLI には Rust ディスパッチ登録上 **36** の明示 unsupported 面に加え、追加 hard-error 面が **7**（合計 **43**）あります。機械可読な対応範囲は [`release/SUPPORTED_SURFACES.json`](./release/SUPPORTED_SURFACES.json) です。

### サポートする CLI 領域

- `setup` — TTY ウィザード + 非対話 flags/JSON。プライバシー既定は telemetry / relay / update ネットワーク **OFF**
- `doctor` — 完全 read-only 診断。`--json` 対応。ネットワーク検査は `--check-network` または control-plane 設定時のみ
- `service install|start|stop|restart|status|uninstall` — **ユーザー権限**の `ownmeshd` 自動起動のみ  
  - Windows: 現在ユーザーの Scheduled Task（ONLOGON / LeastPrivilege）  
  - macOS: LaunchAgent  
  - Linux: systemd --user
- status / login/logout / lockdown / config validate
- device enroll/list/show/rotate/revoke
- ローカル exec / session
- approval / policy
- privileged broker は **status のみ**（install/uninstall は unsupported）

詳細とロールバック: [`docs/onboarding.md`](./docs/onboarding.md)  
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

## 初回セットアップ（ビルド後）

```bash
ownmesh setup --control-plane-url https://your-worker.example --non-interactive --force
ownmesh login
ownmesh device enroll
ownmesh service install
ownmesh doctor --json
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

## 設計不変条件

- ユーザー所有コントロールプレーン（必須中央 SaaS なし）
- ローカルファースト
- Full Access に隠れた hard deny なし
- 特権ブローカーはネットワークレス
- クラウド中継・テレメトリは既定 OFF
- ユーザーサービス管理は admin/root サービスを作らない

## ライセンス

Apache License 2.0 — [LICENSE](./LICENSE)。
