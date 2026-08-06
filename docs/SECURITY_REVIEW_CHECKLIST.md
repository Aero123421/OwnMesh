# OwnMesh Security Review Checklist

OwnMesh は Full Access を正式に提供するため、「操作を禁止すること」ではなく、認証された意思が改ざんされず、別主体へ横取りされず、意図した端末と権限で一度だけ実行されることを中心にレビューする。

## 1. Identity と Token

- [ ] Human、ChatGPT/OAuth client、Device、local IPC principal を別 identity として扱う
- [ ] access token は短時間で audience/scope/tenant/client に binding される
- [ ] refresh token rotation と reuse detection がある
- [ ] redirect URI exact match、PKCE、state、nonce を検証する
- [ ] device key は extract されにくい OS keystore に保存する
- [ ] device revoke と client token revoke が即時反映される
- [ ] token、cookie、secret がログ、MCP result、panic dump に出ない

## 2. Device Protocol

- [ ] handshake transcript を device key で証明する
- [ ] message id、sequence、expiry、nonce を検証する
- [ ] at-least-once delivery で write operation を重複実行しない
- [ ] frame/message/payload/output の上限がある
- [ ] parser と state machine を fuzz test する
- [ ] version downgrade と unsupported feature を安全に扱う
- [ ] reconnection が別 device/session の状態を混同しない

## 3. Local IPC

- [ ] Windows Named Pipe ACL、Unix socket permission/peer credentials を検証する
- [ ] local user A が local user B の daemon を操作できない
- [ ] symlink/socket replacement と TOCTOU を考慮する
- [ ] TUI/CLI と daemon の protocol version を交渉する
- [ ] malformed request で daemon が panic しない

## 4. Privileged Broker

- [ ] broker は外部 network listener/client を持たない
- [ ] broker API は opaque raw bytes を無検証で shell へ渡さない
- [ ] caller identity、request MAC/signature、operation id、nonce、expiry を検証する
- [ ] unprivileged daemon compromise だけで forged elevated request を作れない設計を確認する
- [ ] broker service/socket/pipe の ACL と ownership を test する
- [ ] executable/args/env/cwd の length と encoding を検証する
- [ ] elevated child process tree を追跡・停止できる
- [ ] Full Access でも integrity/replay checks を無効化しない

## 5. Command と Process

- [ ] structured command は shell を経由しない
- [ ] raw shell は別 capability/tool として記録される
- [ ] OS ごとの quoting を自前で文字列連結しない
- [ ] cwd、environment、stdin、timeout、kill semantics を明示する
- [ ] process tree escape と orphan を test する
- [ ] output bomb、binary output、invalid UTF-8、ANSI escape injection を扱う
- [ ] TUI が terminal escape sequence を安全に表示する
- [ ] operation cancellation と timeout の race を test する

## 6. Filesystem

- [ ] path normalization の前後で authorization boundary を検証する
- [ ] symlink、junction、mount、reparse point、case folding を OS ごとに test する
- [ ] patch は expected hash/version を検証する
- [ ] temp file + fsync + atomic rename を使うべき書込を識別する
- [ ] delete、recursive delete、overwrite の事実分類が正しい
- [ ] file size、range、directory entry count を制限する
- [ ] secret path detection は UX 補助であり、Full Access の hidden deny にしない

## 7. Policy と Approval

- [ ] deny > ask > allow と priority が決定的である
- [ ] cloud/local policy 合成が常に最も制限的になる
- [ ] Full Access preset に隠れた deny/ask がない
- [ ] temporary grant は対象、principal、expiry を持つ
- [ ] broad grant 作成時に影響範囲を明示する
- [ ] approval race、double approval、stale approval を test する
- [ ] AI の risk note と機械的 operation facts を混同しない
- [ ] ChatGPT 側 approval を OwnMesh authorization の代替にしない

## 8. Session と Handoff

- [ ] controller lease は一意で期限を持つ
- [ ] observer は stdin を送れない
- [ ] claim/give/release の race を test する
- [ ] stale controller 回収と force-claim の権限を検証する
- [ ] replay buffer に secret が残る期間と削除を管理する
- [ ] disconnected client の古い input を再送しない
- [ ] native CLI session id を別 tenant/device へ漏らさない

## 9. MCP / ChatGPT

- [ ] tool annotations と実際の effect が一致する
- [ ] read/write/elevated/raw-shell/transfer を巨大な一つの tool に統合しない
- [ ] tool arguments を device-side policy でも再検証する
- [ ] untrusted repository/log content による prompt injection を想定する
- [ ] MCP result に token、内部 stack trace、local absolute secret path を不用意に含めない
- [ ] pagination/truncation で access boundary を越えない
- [ ] OAuth scope と tool capability mapping を automated test する

## 10. Profiles と External Adapters

- [ ] Profile なしでも generic exec/PTY が機能する
- [ ] external adapter は別 process で、本体へ dynamic library load しない
- [ ] adapter executable の trust policy/allowlist を設定できる
- [ ] adapter crash、hang、malformed JSON-RPC を隔離する
- [ ] CLI version drift で structured parser が誤操作しない
- [ ] structured interface failure 時の PTY fallback を明示する
- [ ] CLI credential を Cloudflare へコピーしない

## 11. File Transfer

- [ ] relay は標準オフである
- [ ] direct transfer は peer identity と ephemeral key を認証する
- [ ] chunk hash、final hash、resume offset を検証する
- [ ] destination path policy を再評価する
- [ ] relay addon 有効化時に課金先・保存先・retention を表示する
- [ ] 未設定 relay へ自動 fallback しない

## 12. Update と Supply Chain

- [ ] release artifact、manifest、update metadata を署名する
- [ ] rollback/freeze/expired metadata を扱う
- [ ] update channel switching を認証・監査する
- [ ] dependency audit、license review、SBOM を自動化する
- [ ] CI provenance と release signing key 管理を文書化する
- [ ] profile definitions/translation packs の update trust を定義する

## 13. Privacy と Diagnostics

- [ ] central telemetry が標準オフ
- [ ] crash report は明示 opt-in
- [ ] support bundle は送信前に preview/redaction 可能
- [ ] complete stdout/stderr と file body は標準で device のみに保存
- [ ] audit metadata retention/pruning が設定可能
- [ ] Cloudflare logs に request body、command text、file content を出さない

## 14. Release Gate

- [ ] Windows、macOS、Linux で threat-driven integration tests が通る
- [ ] protocol、path、broker、adapter fuzzing の重大 crash がない
- [ ] critical/high vulnerability が解消または公開された受容判断を持つ
- [ ] external security review の指摘を triage した
- [ ] SECURITY.md に報告方法と support policy を記載した
- [ ] emergency revoke/lockdown/rollback をリハーサルした
