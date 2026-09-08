# OwnMesh 横断バグ調査（2026-09-07）

調査基点は `main@3a3f618d72b3869cb3796877bc0d21aa27ce8526`（v1.2.33）。
既存 PR #232 の入力処理レビューとは別に、通常操作の繰り返し、保存失敗、
改行と文字コード、保存先の切り替え、CI のイベント条件を横断して調査した。
全仕様の適合認証や本番環境の監査を意味するものではない。

## プロジェクトの構造と判断の根拠

OwnMesh は、ユーザー自身の Cloudflare 制御サーバーを通して端末の操作を
認証・配送する capability runtime である。AI オーケストレーターではなく、
外部 CLI を通常の実行ファイルとして扱う。操作の許可と実行の最終的な根拠は
端末側のポリシー、承認、実行対象への結び付けにある。

| 領域 | 主な実装・契約 | 今回確認したつながり |
| --- | --- | --- |
| 人の操作と設定 | `ownmesh`、`ownmesh-tui`、`ownmesh-config`、`ownmesh-identity` | CLI と TUI の認証更新・設定保存の整合性 |
| 端末の実行 | `ownmeshd`、IPC、policy、exec、session、broker | 認証済み要求、実行対象、承認、再実行防止の受け渡し |
| ファイルと転送 | `ownmesh-fs`、logs、transfer | バイト列、パスの保持、ハッシュ、差分の適用結果 |
| 制御サーバー | `packages/control-plane`、D1、DeviceRoom、OperationRoom | OAuth、配送、操作状態の正本、再試行、期限切れ処理 |
| 配布と検証 | `scripts/ci`、GitHub Actions、release、schema | 変更範囲からのテスト選択、レビュー起動、保護設定の証拠 |

仕様の意図は `OWNMESH_SPECIFICATION.ja.md`、提供範囲は
`release/SUPPORTED_SURFACES.json`、境界は `docs/THREAT_MODEL.md` と ADR を
照合した。特に ADR 0019 の処理量・再試行の上限、ADR 0021 の OperationRoom
導入後も、D1 を直接参照する経路が残っていないかを確認した。

## 修正対象の10件

数は失敗するテストの個数ではなく、独立した原因と利用者への影響で数える。
同じ原因に対する入力別の回帰テストは重複計上しない。

| ID | 不具合と影響 | 修正・回帰検証の対象 |
| --- | --- | --- |
| B01 | TUI の端末一覧更新が、OAuth 応答の新しい refresh token を保存しない。継続利用時に古い token を再利用する | 保存を一覧取得より先に行い、連続した rotation、未指定、壊れた応答、保存失敗を検証 |
| B02 | TUI の設定保存が既存 policy を作り直す。言語変更でもルール・委任設定を失い、壊れた config を初期値で上書きする | 読み込み失敗を返し、同一 preset のルールを保持。明示的な preset 変更と config/policy の一括保存を検証 |
| B03 | unified diff の旧行数がゼロの挿入 hunk で、挿入位置が1行前にずれる | 先頭・途中・末尾へのゼロ行挿入を Git の差分と比較 |
| B04 | unified diff の解析が CRLF の CR を落とし、正しい差分を拒否する | CRLF・混在改行を含む入力と適用後のバイト列を比較 |
| B05 | unified diff の最終改行マーカーを無視し、末尾改行の追加・除去・新規作成の結果を誤る | `No newline at end of file` を前後両側で検証し、内容とハッシュを照合 |
| B06 | CodeRabbit 自動呼び出しが `ready_for_review` を除外する。Draft 解除だけではレビューが始まらない | イベント条件そのものを評価する行列テストで、Draft・bot・ラベルの既存条件も検証 |
| B07 | ruleset 検証が評価モード等を有効な保護の証拠と扱う | 明示的な active、実際の default branch、ref 条件、除外とワイルドカードの否定テスト |
| B08 | 不確かな配送の再試行が、選択済み OperationStore でなく D1 を更新する | OperationRoom のみにある操作を poll し、同じ配送・状態更新が継続することを検証 |
| B09 | OperationRoom の期限処理が辞書順の先頭ばかり走査し、後方の期限切れレコードに届かない | 永続的な走査位置、バッチ上限、alarm 継続と期限後の掃除を検証 |
| B10 | MCP の結果サイズを UTF-16 の文字数で判定し、UTF-8 のバイト上限と一致しない | 日本語・絵文字、境界、ページカーソル、1要素が上限を超える場合を検証 |

## 共通原因の分析

**同じ仕事をする経路の実装が分岐している。** CLI には refresh token 保存や
設定の一括保存がある一方、TUI の別経路にはその一部が欠けていた。
画面単位のテストに加え、「同じ保存済み状態を次の操作でも使えるか」を
利用者の操作から確認する必要がある。

**抽象化の導入後に、以前の保存先を直接使うコードが残る。**
OperationStore の選択だけが正しくても、復旧経路が D1 を直接使えば正本を
更新できない。通常成功だけでなく、再試行・期限処理・再発見の各経路を
保存先ごとに照合することが必要になる。

**「件数を制限した」と「最後まで処理できる」は別の性質である。**
メンテナンスの1回あたりの件数が小さくても、走査位置が進まなければ後方は
永久に残る。処理量上限と、何回か実行した後の到達性を両方検証する。

**文字とバイト、行番号と挿入位置は同じ単位ではない。**
ASCII・LF・末尾改行ありの小さい fixture だけでは差が見えない。
Git が生成・適用した差分を比較対象にし、文字数ではなく実バイト列を確認する。

**検証コード自体にも独立した検証が要る。** 設定ファイル中に文字列が
存在するだけでは、そのイベントでジョブが動く証拠にはならない。
ruleset の存在も、対象ブランチへの強制の証拠とは限らない。
外部サービスの意味に沿った否定テストが必要である。
ref の判定は [GitHub の ruleset パターン仕様](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/creating-rulesets-for-a-repository)
と [Ruby の FNM_PATHNAME 仕様](https://docs.ruby-lang.org/en/master/file/filename_matching_md.html)
を照合し、検証器で解釈できない構文は保護の証拠として採用しない。

## 検証範囲と残る確認

修正前の失敗と修正後の成功を記録し、実装担当とは別のレビューで確認する。
Rust 1.92、ロックファイル固定の依存解決、TypeScript のテスト・型検査・lint、
CI 判定用 Python テスト、release quality 検証を使う。
各 PR の最新 commit に対応した GitHub Actions の結果を最終証拠とする。

作業環境は Unix socket の作成・接続を `EPERM` で拒否するため、該当する
IPC・PTY の統合検証は GitHub の Linux/Windows/macOS ジョブで行う。
実際のユーザー token、稼働中のサービス、Cloudflare 配備や ruleset は変更しない。

次の調査では、永続化の途中失敗、セッションの lease 引き継ぎ、
プロセス終了の失敗、ログの複数ページ、保存先切り替え時の競合について、
実際の公開経路を通る fault-injection テストを優先する。
今回の10件でそれらを網羅したとは扱わない。セキュリティに関わる未修正候補の
詳細は `SECURITY.md` の報告方針に従い、公開の調査記録には含めない。
