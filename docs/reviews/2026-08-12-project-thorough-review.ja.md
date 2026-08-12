# OwnMesh v1.2.2 プロジェクト徹底レビュー

**日付:** 2026-08-12
**対象:** `main` @ 59cdb5b(v1.2.2 安定版)
**方法:** 全ドキュメント・全 ADR・全クレート/パッケージの通読、CI/リリース基盤の精査、
および検証スイートのローカル実行(Rust 約 870 件・TypeScript 384 件・リリース品質
チェッカー・アクションピン検査)。サブエージェント不使用の単独レビュー。

---

## 総評

OwnMesh は、個人開発の OSS として**例外的に高い水準**にある。特筆すべきは
「正直さを機械検査する」文化 — `release/SUPPORTED_SURFACES.json` による出荷面の
機械検査、W-\* 免責の明示、「実装済み」と「受領証(receipt)あり」の区別 — であり、
これは商用製品を含めても稀有な実践である。セキュリティ工学(操作バインディング、
冪等ジャーナル、ハンドル基準のパス防御、ネットワークレス・ブローカー、passkey の
鮮度要求)は脅威モデルと対応テストで裏付けられ、レビューで実行した全テストは
グリーンだった。

一方で、**製品としての最大の弱点は「中間の梯子段が欠けている」こと**にある。
出荷版の `recommended` プリセットはコマンド実行と対話セッションを全面 deny する
ため、実質の選択肢が「読み取り+書き込み確認のみ」か「full_user_access(ほぼ全許可)」
の二択に近い。仕様書 §7.1 が約束する「Recommended = ユーザー権限の一般操作は許可」
とは大きく乖離しており、README の主要シナリオ(ChatGPT にテストを走らせて直させる)
が推奨設定では成立しない。fail-closed としての判断自体は誠実だが、これは v1.3 の
最優先課題とすべき製品形状の問題である。

整合性の面では、意欲的な仕様アーティファクト(spec-bundle のポリシースキーマ、
ドメイン層の豊富な `PolicyRule`、仕様 §6.6 の 14 スコープ)と、出荷された狭い実装
(エンジンの `PolicyRule`、6 スコープ)が**同名のまま併存**しており、ADR 0004–0006
で確立した「乖離を決定として記録する」規律をまだ適用できていない領域が残る。

| 観点 | 評価 | 一言 |
|---|---|---|
| 思想の一貫性 | ★★★★★ | 「能力を提供し役割を固定しない」が全層で貫徹 |
| セキュリティ工学 | ★★★★★ | 境界設計・テスト・文書の三点が揃う |
| リリース工学 | ★★★★★ | fail-closed 公開グラフ+変異テスト付き検査器 |
| 実装品質 | ★★★★☆ | unsafe 隔離・型付きエラー・網羅的テスト |
| 設計の完成度 | ★★★★☆ | 層分離は良好。二重ポリシーモデル等の負債あり |
| ドキュメント | ★★★★☆ | 誠実さは最高水準。数カ所の実装乖離ドリフト |
| UX(製品形状) | ★★★☆☆ | 中間プリセット欠落・インタープリタ raw 分類 |
| OSS 運営 | ★★★☆☆ | バス係数 1・履歴の placeholder 署名・日本語正本 |

---

## 1. 思想・方針のレビュー

### 1.1 貫徹されている中核思想(検証済み)

仕様書 §1.3 の 10 項目を実装と突き合わせた結果、以下はコードで裏付けられている。

- **役割を固定しない:** MCP `initialize` の instructions、Skill 相当の文書、
  profile 起動経路のいずれにも「ChatGPT がオーケストレーター」「Codex は worker」
  という強制はない。profile session は単に起動されるだけである。
- **ユーザー所有:** wrangler.jsonc は R2/TURN/Queue を作らず(コメントで
  fail-closed を明記)、`wrangler-config.test.ts` が中継バインディング不在を回帰
  テストしている。運営者 API キーや中央エンドポイントは存在しない。
- **ローカルファースト/テレメトリ OFF:** `TelemetryConfig` は全フィールド
  `#[serde(default)]` の bool(= false)。update は既定 `off`。ログ本文は D1 に
  保存されず(v1.2.2 で `logs query` をローカル IPC 限定にした判断は正しい)、
  MCP 側にログ本文ツールを意図的に作っていない。
- **Full Access に隠れ deny なし:** `preset_document(FullAccess)` は空ルール、
  `full_access_has_no_hidden_restrictive_rules()` + `full_access_invariant.rs` が
  回帰保証。sensitive 検出(`looks_sensitive`)も「UX ヒントであり hard deny には
  しない」とコメントで宣言されている。
- **AI の自己申告を境界にしない:** ポリシー facts はサーバー側で再分類され
  (`classify_from_request_in_dir`)、実行体は pin(SHA-256 + dev/ino)で TOCTOU
  検証される。クライアント供給の digest/facts を信用しない旨がコードコメントと
  型設計(`ExecutableIdentityBinding` のドクコメント)に明記されている。

この「思想 → 仕様 → 実装 → テスト → 文書」の一気通貫は、本プロジェクトの最大の
資産である。

### 1.2 思想レベルで再考の余地がある点

1. **「Recommended」という名前の約束と実装の乖離(最重要)。**
   仕様 §7.1: 「Recommended = ユーザー権限の一般操作は許可。管理者操作、認証情報、
   外部転送、重大な OS 変更は確認」。実装: `command.run` と `session.open` を
   **無条件 deny**(OS プロセス封じ込めが無いため)。fail-closed の論理は正当
   (cwd 束縛ではインタープリタ/絶対パス経由の脱出を防げない)だが、結果として
   README の看板シナリオが recommended では動かない。少なくとも(a) プリセット名を
   実態に合わせる(例: `restricted`)、(b) 仕様 §7.1 の表を実装状況注記で更新する、
   (c) OS 封じ込め(あるいは「workspace cwd + 実行体 allowlist + ask」の中間段)を
   ロードマップ最上位に置く、のいずれかが必要。現状は setup の説明文で開示している
   ものの(良い)、「推奨」の語が誤誘導になっている。

2. **クラウド+ローカルの「最も制限的な合成」(§7.2)の実装形。**
   `evaluate_combined()` はポリシークレートに存在するが**本番コードから未使用**。
   実際のアーキテクチャは「クラウド = OAuth スコープ + 操作バインディング/承認、
   ローカル = ポリシー最終権威」であり、クラウド側に PolicyDocument は存在しない。
   これは防御的には妥当な設計だが、仕様 §7.2 の記述と異なる形で実現されている。
   ADR で「クラウドポリシーはスコープ+バインディングとして実装する」と記録する
   べきである(ADR 0004/0005 と同じ規律の適用)。

3. **一時 grant と明示 deny の優先順位。**
   仕様 §7.7 の優先順位は「明示 deny > 明示 ask > 明示 allow」であり一時 grant は
   序列に現れないが、実装の `evaluate_with_grants()` は**grant を deny 評価より
   先に**適用する(grant がマッチすれば Allow を即返す)。つまり「approve --grant
   で発行された有効期限内の grant」は、その後に追加された明示 deny ルールを上書き
   する。最大 24 時間で失効し、lockdown は別経路で先に効くため実害は小さいが、
   §7.7 との不整合であり、deny ルール追加時に既存 grant を失効させる(または deny
   を grant より先に評価する)方が仕様に忠実である。

---

## 2. アーキテクチャ・設計の完成度

### 2.1 良い点

- **層分離は仕様 §28.1 の精神どおり。** domain(型・ID・エラー分類)→ protocol
  (エンベロープ・バージョン交渉)→ policy / fs / exec / logs / session(能力)→
  ipc / identity / config(基盤)→ ownmeshd / broker / CLI / TUI(組み立て)の
  依存方向は一貫している。TUI は IPC クライアントと view state のみを持つ(§17.2
  準拠)。
- **`unsafe` の隔離が模範的。** workspace lint で `unsafe_code = "forbid"`、
  例外 3 クレート(ipc / fs / broker)は CONTRIBUTING に列挙され「4 つ目の例外は
  ADR 必須」と明文化。実際の unsafe は OS API 直結箇所(SO_PEERCRED、
  GetFinalPathNameByHandle、renameat、fdopendir 等)に限定されている。
- **エラー分類と exit code(§16.3)が単一ソース。** `ErrorCode` → `ExitCode` の
  対応が domain クレートに集約され、CLI の JSON 失敗エンベロープが 1 種類に統一
  されている(v1.2.1 の修正)。
- **共有スキーマの往復検証。** domain エンティティと protocol エンベロープは
  Rust/TS 双方から同一 fixture で round-trip + JSON Schema 検証されている。
- **v1.2.2 の runtime 分割**(7,939 行の単一ファイル → session / transfer /
  workspace モジュール分離)は正しい方向。ただし `runtime.rs` は依然 7.8k 行あり、
  fs 系ハンドラと admin/approval 系の分離余地が残る。

### 2.2 設計負債(整合性の核心)

1. **同名二重の `PolicyRule` モデル。**
   - `ownmesh_domain::PolicyRule`: 仕様 §7.3 の豊富なモデル(principal_ids /
     device_ids / workspace_ids / capabilities[] / path_globs / executables /
     operation_classes / expires_at)。fixture・スキーマ検証あり。**本番未使用**。
   - `ownmesh_policy::PolicyRule`: 実際に評価される狭いモデル(capability /
     when_elevated / when_kind / path_prefix / program_equals)。
   同じ名前で形が違う 2 型の併存は、コントリビューターの誤解と「スキーマは合って
   いるのに動かない」事故の温床。どちらかへの統一、少なくとも rename と ADR を
   推奨する。

2. **spec-bundle の過大宣言。**
   `spec-bundle/README.md` は「Rust と TypeScript パッケージが使用する機械可読
   スキーマの正本」と述べるが、実際に検証されているのは domain / protocol / errors
   系のみ。`policy.schema.json`・`config.schema.json`・`profile.schema.json`・
   例 TOML(`policy.recommended.toml` は `operation_classes` や
   `sensitive_path_globs` を使う)は**出荷実装のどこからも読まれず、検証もされて
   いない**。例 TOML は出荷版 `policy.toml`(PolicyFile 形式)としてパースできない。
   → 対応案: (a) これらを `spec-bundle/aspirational/` に隔離して README で区別、
   (b) mcp-tool-catalog.json と同様の「目標文書であり出荷契約ではない」注記を付す、
   (c) 出荷形式のスキーマを別途追加して CI 検証する。

3. **OAuth スコープ粒度の乖離(ADR 不在)。**
   仕様 §6.6 は 14 スコープ(`commands:run` / `commands:shell` /
   `commands:elevated` を分離)+ Observe/Develop/Full プリセットを規定。実装は
   6 スコープ(`ownmesh.read/write/exec/session/device` + `offline_access`)で、
   raw shell と elevated はスコープではなくツール分離+ローカルポリシーで制御して
   いる。設計として成立しているが、仕様側の更新も ADR も無い。ADR 0004(ツール
   命名)と同格の決定記録が必要。

4. **仕様 §28 のリポジトリ構成・§4.1 の edition。**
   仕様のクレート一覧(ownmesh-core / -runtime / -filesystem / -auth / …)と実際
   (-domain / -exec / -fs / -identity / …)は対応関係が読み取りにくい。§4.1 の
   「Rust edition: 2024」に対し実装は 2021。§24.1「update 既定は notify」に対し
   実装は `off`(プライバシー側に倒しており妥当だが仕様未更新)。いずれも
   「仕様はロードマップ正本」の但し書きで免責されてはいるが、§28/§4 は規範文の
   体裁なので実装状況注記(§14.3 や §17.7 で既に行っている様式)を足すべき。

5. **ADR-0005 の記述精度。**
   「翻訳漏れはコンパイルエラー」とあるが、実装は `BTreeMap` カタログ+
   `completeness_report()`(CI ゲート)+ 実行時 `"[missing]"` フォールバック。
   つまり「rustc が落ちる」のではなく「CI が落ちる」。網羅 enum match(
   `match msg { … }` を各ロケール関数に持たせる)にすれば文字どおりコンパイル
   エラーにできる。現状でも防御は機能しているが、ADR の記述を実装に合わせるか
   実装を ADR に合わせるべき。

### 2.3 コード品質の実測

- `TODO`/`FIXME`/`unimplemented!`/`todo!`: **0 件**(crates/packages 全体)。
- 本番経路の `unwrap()`/`expect()`: runtime.rs の非テスト部で実質 0(検出された
  164 件はすべて `#[cfg(test)]` ブロック内)。
- 秘密情報の型防御: `RedactedSecret` / `SecretString` 系が Debug/Display を封じ、
  redaction テスト(diagnostics / ipc / identity)が存在。
- コメント文化が特異的に良い。「なぜ fail-closed か」「何を信用しないか」を
  境界ごとに書いており、セキュリティレビューの再現性が高い。

---

## 3. セキュリティ(検証結果を含む)

### 3.1 実測で確認した強み

| 領域 | 確認内容 |
|---|---|
| OAuth 2.1 | PKCE S256 必須・plain 拒否、redirect 完全一致(登録時+token 時の再検査)、public client 限定(client_secret 系を拒否)、refresh rotation + 再利用検知、RFC 8628 の slow_down/expired/denied、承認済み device code の原子的消費 |
| DCR | ChatGPT 既知 callback のみ無状態許可、他は `ownmesh.device` トークン必須。redirect は https または loopback http のみ |
| Passkey | `__Host-` cookie、同一オリジン POST 検査(origin/sec-fetch-site/referer)、操作 ID に束縛された 5 分 presence、@simplewebauthn/server 13.x |
| DO 内部呼び出し | SESSION_SECRET 署名 + body SHA-256 + correlation 束縛。DEVICE_ROOM/SESSION_SECRET 不在は fail-closed。送信後タイムアウトを「不確定」として扱い二重実行を防ぐ(dispatch_uncertain) |
| デバイス協定 | Ed25519 challenge-response、seq 単調、seen message id の TTL+上限、pending TTL+上限 |
| パス防御 | ハンドル保持 + final-path 再検証、no-follow、cross-mount/hardlink 拒否、リネーム競合 fail-closed。`security_path.rs` は置換シンボリックリンク競合まで検査 |
| 実行分類 | シェル・インタープリタ(python/node/…)・shebang スクリプトをサーバー側で raw_shell に再分類。`env` 間接も追跡。構造化コマンドは pin(SHA-256+dev/ino)を承認~実行間で再検証 |
| 一時 grant | ADR-0006 適用済み: workspace 束縛+ネイティブパス成分比較、command.\* grant は発行も照合も全面拒否(インタープリタ argv 差し替え攻撃への正答)。偽造/レガシー行の fail-closed をテストで確認 |
| ローカル IPC | 共有 daemon.token 全廃(起動時削除+非空 token 拒否)、OS peer 資格情報主体、per-client credential、失効の principal キー化。in-repo 監査文書(AUDIT-1)付き |
| ブローカー | 非 loopback bind 拒否、MAC+nonce+expiry+replay ledger、Linux は SO_PEERCRED+/proc 誕生時刻+実行体同一性まで検証。Windows/macOS 本番サーブは fail-closed 未対応と明示 |
| レート制限 | 資格情報ハッシュ鍵の厳格枠+IP の粗い天井の二層(v1.2.1 の共有 NAT 対策)。可用性優先で counter 障害時は素通し(認可境界ではない旨コメントあり) |
| サプライチェーン | 全 Action SHA ピン(検査スクリプト付き)、cargo audit / pnpm audit ブロッキング、gitleaks、SBOM 非空検査、minisign 署名→即時検証、GitHub provenance、公開ジョブは CI+Security 再利用ワークフローの成功が前提 |

### 3.2 指摘(重大度順)

1. **[中] 一時 grant が明示 deny に優先する**(§1.2-3 再掲)。期限上限 24h と
   lockdown 先行で緩和されているが、§7.7 と不整合。deny 評価を grant より先に。

2. **[中] Recommended で機微ファイルの読み取りが無確認 Allow。**
   仕様 §7.1 は「認証情報は確認」を約束するが、出荷 preset は
   `filesystem.read` を全面 Allow(workspace 内)。`ownmesh-fs` の
   `looks_sensitive()` は実装済みなのに**どこからも呼ばれていない**(自クレートの
   テストのみ)。workspace 内の `.env` / 秘密鍵が ChatGPT に無確認で渡り得る。
   facts に `reads_sensitive_location` タグを立てて Recommended に ask ルールを
   1 本足すだけで仕様との整合が取れる(実装コストは小さい)。

3. **[小] Windows IPC の peer user_id が daemon プロセスのユーザー名。**
   AUDIT-1 の残課題として文書化済み(判別は PID+exe パス+パイプ ACL に依存)。
   クロスユーザー防御はパイプ ACL が主防壁である旨を THREAT_MODEL にも一行
   反映しておくとよい。

4. **[小] `delegate_remote_mcp`(Ask→Allow 変換)の可視性。**
   実装は慎重(Deny/lockdown/バインディング検証は不変、操作束縛+期限内のみ)だが、
   この「リモート MCP 呼び出し自体を確認 UI とみなす」設定はセキュリティ意味論が
   大きい。onboarding/chatgpt-connection に記述はあるが、ADR として決定記録する
   価値がある。

5. **[情報] W-\* 免責は誠実。** 外部監査未実施(W-EXT-SEC)、ネイティブ署名
   (W-SIGN)、E8/E10 受領証の未完は、すべて「実装済みだが証拠が無い」と正確に
   区別して開示されており、この規律は維持すべき。

---

## 4. UX レビュー

### 4.1 オンボーディング(良い)

`deploy:guided` → 印字された `ownmesh setup --quickstart` を貼る → `doctor --json`
という 3 手の導線は、セルフホスト系 OSS として最高水準。特に:

- guided deploy が「次に実行すべきコマンドそのもの」を印字する設計。
- デスクトップ(ブラウザ)と headless(device code)の両導線が README 冒頭にある。
- `doctor` の完全 read-only 化と `--check-network` の意味の修正(v1.2.1)は、
  変更理由まで onboarding.md に書かれており、UX 判断の透明性が高い。
- setup の preset 選択時に「どの preset がコマンド実行を許すか」を明示する
  ガイダンス(`write_preset_guidance`)は誠実。

### 4.2 製品形状の問題(要改善)

1. **プリセットの梯子が二段しかない(§1.2-1 再掲)。**
   実効的には `workspace_only ≈ recommended`(読み allow・書き ask・実行 deny)と
   `full_user_access / full_access`(ほぼ全許可)の二択。仕様 §7.1 の 5 段設計が
   目指した「安全側の既定で日常が回る」体験は未達。ChatGPT 連携の実用は事実上
   full_user_access 前提であり、これは docs(chatgpt-connection.md 前提 5)にも
   明記されているが、「推奨設定では看板シナリオが動かない」という構造は早期に
   解消すべき。中間段の候補: 実行体 allowlist + workspace cwd + 全実行 ask、
   もしくは OS サンドボックス(spec が非目標とした完全封じ込めでなく、最小の
   process confinement)。

2. **インタープリタ一律 raw_shell 分類の UX 帰結が文書化不足。**
   `npm`(shebang スクリプト)、`python`、`node` 等は構造化リクエストでも
   raw_shell に再分類される。安全側の判断として支持するが、「`ownmesh_command_run`
   で npm test が raw 扱いになる」ことは統合者にとって意外性が高い。
   mcp-clients.md / chatgpt-connection.md に分類規則の要約表を載せるべき。

3. **`docs/mcp-clients.md` のスコープ表が不完全(実害あり)。**
   表には `ownmesh.read / ownmesh.exec / ownmesh.device / offline_access` の
   4 行しかなく、**`ownmesh.write` と `ownmesh.session` が欠落**。しかも
   「`ownmesh.exec` = Command execution and interactive session tools」と
   session 系を exec に誤帰属している(実装ではセッションツールは
   `ownmesh.session`、fs 書き込みは `ownmesh.write`)。この文書に従って
   サードパーティクライアントを設定すると write/session ツールが 403 になる。
   即修正推奨。

4. **TUI:** 4 画面ウィザード+4 言語+幅/スナップショットテストは堅実。仕様 §17 の
   12 段ウィザードや Command palette の fuzzy 検索等はまだ目標(§17.7 の実装状況
   注記で開示済み)。`t()` の `"[missing]"` フォールバックは CI で実質死文だが、
   ADR の記述との齟齬は §2.2-5 のとおり。

5. **CLI:** exit code 体系(§16.3 完全一致)、`--json` 単一エンベロープ、
   読み取り系コマンドが config を書かない(v1.2.1 修正)など、機械利用者向けの
   一貫性は高い。`--lang` が TUI 言語選択のみに効くことも help に明記されている。

---

## 5. OSS としての完成度

### 5.1 揃っているもの

ガバナンス一式(Apache-2.0 / NOTICE / CoC(Contributor Covenant 2.1)/
CONTRIBUTING / SECURITY(私的報告経路+鍵ローテーション手順)/ CODEOWNERS
(セキュリティ境界別)/ issue・PR テンプレート / dependabot 3 エコシステム)、
ADR 制度(6 本、いずれも高品質)、脅威モデル、セキュリティレビューチェックリスト
(チェックボックス→テストファイルへの対応付け)、リリース鍵の帯域外検証手順、
Homebrew formula テンプレート、インストーラの敵対的テスト。

**CI/リリースは最上位水準:** 全 Action SHA ピン+ピン検査テスト、3 OS マトリクス、
Linux stateful 分離、TUI i18n ゲート、リリース公開グラフの fail-closed 性を
変異テスト付きスクリプトで検査、SBOM 非空強制、署名必須(劣化リリース禁止)。
ローカル再現も `README` の Development gates がそのまま通る(実測)。

### 5.2 弱点

1. **バス係数 1。** CODEOWNERS は全行 @Aero123421。個人プロジェクトとして自然だが、
   SECURITY.md の応答目標(7 日)や「セキュリティ境界の変更は明示レビュー」が
   単独者運用であることは、利用者のリスク評価材料として README に一言あってよい。

2. **コミット履歴の 8 割が placeholder identity**(`OwnMesh Test
   <ownmesh@test.local>` 99 件 / 123 件)。CONTRIBUTING が事情と将来ルールを誠実に
   開示している(履歴書き換えはタグ/署名資産を壊すため行わない、という判断も正しい)
   が、「署名付きバイナリを配る以上、履歴が誰の手か言えるべき」という同文書の理念と
   の緊張は残る。今後のタグ署名(ADR-0001 に記載あり)の実施で補強を。

3. **仕様書が日本語のみ。** §0.2 で「日本語が設計意図の正本」と宣言済みで一貫は
   しているが、国際的なコントリビューター獲得の上限になる。README(英)→仕様(日)
   の落差が大きいので、せめて仕様の章立て+規範要件の英語サマリーがあるとよい。

4. **細部:**
   - `lint` スクリプトが `tsc --noEmit` の別名で、typecheck と完全重複。ESLint 等を
     入れるか、CI のステップ名を実態に合わせる。
   - installer 信頼テストが minisign 不在環境で fail(Windows 側テストは skip)。
     ローカル開発者の `run_release_quality_tests.py` 体験のため Unix 側も
     「minisign 不在なら明示 skip + CI では必ず存在」に揃えるとよい(実測で遭遇)。
   - workerd E2E ループバック群(`scripts/tests/test_*_workerd_*.py`)が CI グラフに
     入っていない。docs は「ローカルで再現可能」と正確に述べているが、nightly 等で
     自動化する価値がある。
   - spec §31.3 の「public roadmap」に相当する文書が無い(SUPPORTED_SURFACES と
     W-\* が事実上代替しているが、次に何をやるかは読み取れない)。

---

## 6. 検証ログ(このレビューで実行したもの)

```text
cargo fmt --all --check                                     → PASS
cargo test --workspace --all-targets --locked
  --exclude ownmesh-session-host --exclude ownmeshd         → 46 suites / 602 passed / 0 failed
cargo test -p ownmeshd --bin ownmeshd                       → 100 passed
cargo test -p ownmeshd --test adversarial_security 他 4     → 70 passed
cargo test -p ownmesh-session-host --all-targets -j1        → 33 passed
pnpm install --frozen-lockfile && pnpm -r test              → 384 passed(control-plane)+ schema
pnpm -r typecheck                                           → PASS
python scripts/check_release_quality.py                     → PASS(0 unsupported)
python scripts/tests/test_action_pins.py                    → PASS
python scripts/tests/run_release_quality_tests.py           → 38/39 PASS
  (1 fail は環境起因: minisign バイナリ不在。CI では事前導入される)
```

---

## 7. 指摘一覧(優先度順)

> **対応状況(2026-08-12 追記)**
> 本レビューで挙げた P1〜P3 は、同じ PR 内で以下のとおり対応済み。
> 対応内容の詳細は §9 を参照。唯一 P1-4(プリセット中間段)は製品判断のため
> 実装せず、ADR 0007 に決定と候補を記録した。

### P1 — 製品形状・実害あり

| # | 指摘 | 場所 | 提案 |
|---|---|---|---|
| 1 | mcp-clients.md のスコープ表に `ownmesh.write` / `ownmesh.session` が欠落、session 系を exec に誤帰属 | `docs/mcp-clients.md` | 6 スコープ全行の表に修正 |
| 2 | 一時 grant が明示 deny ルールに優先(§7.7 不整合) | `ownmesh-policy::evaluate_with_grants` | deny 評価を grant より先に/deny 追加時に該当 grant 失効 |
| 3 | Recommended が機微ファイル読み取りを無確認 Allow(§7.1 不履行)、`looks_sensitive` が死にコード | `ownmesh-policy` preset / `ownmeshd` facts | facts に sensitive タグを配線し Recommended に ask ルール追加 |
| 4 | プリセット梯子の中間段欠落(recommended ≒ workspace_only、実用は full_user_access 一択) | 製品全体 | 中間段の設計(実行体 allowlist + ask 等)を v1.3 最優先に。当面は命名/文書で誤誘導を解消 |

### P2 — 整合性負債(ADR/仕様更新で解消可能)

| # | 指摘 | 提案 |
|---|---|---|
| 5 | OAuth スコープ 14→6 の乖離に決定記録なし | ADR 化+仕様 §6.6 に実装状況注記 |
| 6 | 同名二重 `PolicyRule`(domain の豊富なモデルは本番未使用)、spec-bundle の policy/config/profile スキーマ・例 TOML が出荷実装と乖離し未検証 | spec-bundle README の宣言を実態に合わせる/aspirational 隔離/出荷形式スキーマの CI 検証追加 |
| 7 | `evaluate_combined`(§7.2 クラウド+ローカル合成)未使用 | アーキテクチャ決定として ADR 化(または削除) |
| 8 | 仕様 §4.1 edition 2024 vs 実装 2021、§24.1 update 既定 notify vs off | 仕様に実装状況注記(off は正当なプライバシー強化) |
| 9 | ADR-0005「翻訳漏れはコンパイルエラー」が実態(CI ゲート+実行時 [missing])と不一致 | 網羅 match 化で文字どおりにする、または ADR の記述修正 |
| 10 | 仕様 §28 のクレート構成が実リポジトリと大幅乖離 | §14.3 と同様の実装状況注記 |

### P3 — 磨き込み

| # | 指摘 |
|---|---|
| 11 | installer 信頼テストの Unix 側を minisign 不在時 skip に(Windows 側と対称に) |
| 12 | `lint` = typecheck 重複の解消(ESLint 導入 or 名称整理) |
| 13 | `runtime.rs`(7.8k 行)の追加分割(fs 系・admin/approval 系) |
| 14 | workerd E2E ループバック群の CI(nightly)組み込み |
| 15 | 今後のリリースタグ署名の実施(ADR-0001 記載事項) |
| 16 | 公開ロードマップ(次版の優先事項)の明文化 |

---

## 8. 結び

このリポジトリの本質的な強みは、個々の機能ではなく**「主張と証拠を分離し、証拠の
無い主張をしない」というエンジニアリング文化がコード・テスト・CI・文書の全てに
実装されている**ことにある。W-\* 免責、SUPPORTED_SURFACES、receipt の区別、
ADR 0004–0006 の「乖離を決定に変える」実践は、そのまま OSS 運営の教科書になる。

残る仕事は二種類に整理できる。ひとつは **P1 群 = 製品の約束と実装の一致**
(Recommended の意味、機微読み取り、grant 優先順位、統合者向け文書)。もうひとつは
**P2 群 = 意欲的仕様アーティファクトの棚卸し**であり、これは既に確立した ADR 規律を
残りの乖離に適用するだけである。どちらも本レビューで示した範囲で対応可能であり、
プロジェクトの基礎体力(テスト・リリース工学・脅威モデル)は、それを安全に行うのに
十分すぎるほど整っている。

---

## 9. 対応内容(同 PR で実施)

### 挙動変更(3 件)

| 指摘 | 変更 | 回帰テスト |
|---|---|---|
| #2 grant が deny に優先 | `evaluate_with_grants` が policy を先に評価し、`Deny` なら grant を見ずに返す。grant が持ち上げるのは `Ask` のみ | `explicit_deny_outranks_a_matching_temporary_grant` |
| #3 機微読み取りが無確認 | daemon が解決済みパスから `reads_sensitive_location` / `writes_sensitive_location` タグを生成し、`workspace_only` / `recommended` に条件付き ask ルールを追加。full access 系は不変 | `restricted_presets_ask_before_reading_sensitive_paths`、`recommended_asks_before_reading_a_workspace_credential_file` |
| — | `PolicyRule` に `when_tag` 条件を追加(サーバー計算 facts のみを参照) | `tag_conditioned_rules_require_the_exact_tag` |

`looks_sensitive` は `.env.*` 系、`id_ecdsa`/`id_dsa`、`.netrc`/`.npmrc`/
`.git-credentials`、`p12`/`pfx`/`jks` 等へ拡張し、`.environment` のような
非機微名を巻き込まないことをテストで固定した。タグはクライアントが渡す経路を
持たないため、モデルによる抑止も捏造もできない。

### 決定記録・仕様更新

- **ADR 0007**: 制限プリセットが exec/session を deny する理由、機微読み取り
  ask の復旧、プリセット改名を避ける判断、中間段の候補 4 案(未決として明記)。
- **ADR 0008**: control plane は「誰が要求してよいか」だけを判定し device が
  唯一の policy engine であること、6 scope の設計理由、`evaluate_combined` が
  参照実装であること。
- **仕様更新**: §7.1(プリセット実態)、§7.2(クラウド合成)、§7.7(grant の
  位置づけ)、§6.6(出荷 scope 一覧)、§4.1(edition)、§18.3(i18n 強制の
  実態)、§24.1(update 既定 off)、§28(実リポジトリ構成と対応表)。
- **ADR 0005 修正**: 「コンパイルエラー」→ 実態(`cargo test` の assert +
  `--check-i18n` + CI job の 3 段、`[missing]` は明示プレースホルダ)。
- **spec-bundle/README.md**: 「検証済み契約」と「仕様目標(出荷実装と異なる)」
  を表で分離。目標側の例 TOML 4 本に先頭バナーを追加。
- **`ownmesh_domain::PolicyRule`** に、エンジンが評価する型ではない旨を明記。

### 文書・基盤

- `docs/mcp-clients.md`: 6 scope 全件とツール所属を修正(#1)。二層認可
  (scope + device policy)と alias の扱いを明示。
- `docs/ROADMAP.md` 新規(#16)。両 README から参照。
- `docs/DOD_1.0.md`: リリースタグ署名の手順と、CI 未強制である旨(#15)。
- `scripts/lint-ts.mjs` 新規(#12): typecheck と重複しない 2 規則
  (相対 import の `.ts` 明示、非テスト source の `console.*` 禁止 = §26.6)。
  依存追加なし。
- `test_installers.py`: minisign 不在時は skip、`OWNMESH_REQUIRE_MINISIGN=1`
  で必須化。CI の該当ジョブに同変数を設定(#11)。
- `crates/ownmeshd/src/runtime_fs.rs` 新規(#13): fs ハンドラ 10 メソッドを
  既存の `runtime_session` / `runtime_transfer` / `runtime_workspace` と同じ
  パターンで分離。挙動不変。
- `.github/workflows/e2e-loopback.yml` 新規(#14): workerd ループバック群を
  nightly + 手動実行に。PR/リリースの gate には**しない**。

### 未対応として残したもの

- **#4 プリセット中間段**: 出荷済みプリセットのセキュリティ姿勢を変える製品判断
  のため実装せず、ADR 0007 に候補と各案のコストを記録した。
- **#5〜#10 の一部**: 仕様側の注記で解消。実装の統一(二重 `PolicyRule` の
  片方削除等)は互換性影響があるため別 PR 向け。
