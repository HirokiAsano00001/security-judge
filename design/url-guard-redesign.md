# url_guard 再設計 — 脅威モデル確定版

- 作成: 2026-07-07
- 対象欠陥: [security-judge監査] #1 (url_guard private-IP無条件ブロック) / #b (startsWith前方一致SSRFバイパス)
- 前提: 監査メモリ `security-judge-audit` / 判断メモリ `security-judge-urlguard-decision`

---

## 1. 確定した脅威モデル

**ローカルCLI（オペレーター＝標的所有者）** に確定（CTO判断 2026-07-07）。

根拠（RDD＋コード）:
- 配布形態は `npx security-judge@1.x` のClaude Code MCPツール。サーバ/共有サービスのデプロイ記述なし（RDD:9,299,330）。
- `ctx.allowedUrls` は `ask_target_persona.ts:44` で **唯一** `[baseUrl]` にセットされ、他のどこからも追記されない。
  → 「許可対象」は常にオペレーターが明示指定したただ1つの標的ベースURLと一致する。
- したがって「自分の127.0.0.1を自分のツールでテスト」は踏み台ではなく正当なペンテスト（nmap/Burpと同じ信頼境界）。

共有サービス方針は**不採用**（DNS rebinding対策・リダイレクト追従禁止・標的所有権検証が必須になり設計規模が変わるが、現アーキテクチャと不整合）。

---

## 2. 中心的な設計判断: 2つの概念を分離する

現行 `url_guard` は「private IP」と「metadata IP」を一括で無条件ブロックしている（`url_guard.ts:88`）。これが主用途（ローカルアプリ評価）を原理的に不能にしている。

再設計では **security-judge 自身が直接fetchするURL** に対し、2概念を分離:

| 概念 | 例 | 扱い |
|------|-----|------|
| **クラウドメタデータIP** | 169.254.169.254 / 100.100.100.200 / metadata.google.internal / fd00:ec2::254 | **恒久ブロック**。allowedUrlsに入っていても絶対fetchしない（決定a） |
| **その他のprivate/loopback** | 127.0.0.1 / 192.168.x / 10.x / 172.16-31.x / ::1 | **allowedUrlsに完全一致すれば許可**。それ以外はブロック |

重要な非対象:
- **SSRFペイロード**（`test_ssrf.ts` がボディの値として送るメタデータIP）は `assertAllowedUrl` を通らない。security-judge自身がfetchするのは `targetUrl` のみ。→ メタデータ恒久ブロックはSSRF検査を壊さない。
- **crawler派生リンク**は `crawler.ts:34` で `base.origin` フィルタ済み＋ `assertAllowedUrl` 再チェック。標的host外へ飛ばない（決定d：現状で既に満たす。回帰テストで固定する）。

---

## 3. `assertAllowedUrl` の新しい判定ロジック

判定順序（現行の「private先行ブロック→startsWith」を全面置換）:

```
assertAllowedUrl(urlStr, allowedUrls):
  1. u = parseUrl(urlStr)            // 失敗 → block（不正URL）
  2. host = expandIp(u.hostname)     // 難読化IP展開は現行 expandIp を流用
  3. if isCloudMetadata(host, u.hostname):  → block（恒久。allowedUrls無視）  … 決定a
  4. if matchesAllowed(u, allowedUrls):     → allow                          … 決定b
  5. else:                                   → block
```

### 3.1 `matchesAllowed` — startsWith を host:port 完全一致へ（決定b）

現行 `allowedUrls.some(base => urlStr.startsWith(base))` を廃止し、パース済み `host:port`（＋protocol）の完全一致にする。

```ts
function matchesAllowed(u: URL, allowedUrls: string[]): boolean {
  return allowedUrls.some(base => {
    let b: URL
    try { b = new URL(base) } catch { return false }
    return (
      u.protocol === b.protocol &&
      expandIp(u.hostname.toLowerCase()) === expandIp(b.hostname.toLowerCase()) &&
      effectivePort(u) === effectivePort(b)
    )
  })
}
// effectivePort: 明示ポート優先、無ければ protocol 既定 (http=80 / https=443)
```

これで下記のバイパスが同時に閉じる:
- `http://127.0.0.1:3737@169.254.169.254/` → `hostname` は `169.254.169.254`（userinfoは剥がれる）→ step3 でブロック。
- `http://127.0.0.1.evil.com/` → `hostname` ≠ 標的host → step4 不一致でブロック。
- `http://127.0.0.1:3737.evil.com` 等の前方一致トリック → 完全一致で不成立。

### 3.2 opt-inフラグは追加しない（決定cの解釈）

判断メモリ(c)は「private標的許可を明示オプトインフラグ（デフォルト閉）」を挙げたが、本アーキテクチャでは:
- `allowedUrls` は `ask_target_persona` で標的を指定した瞬間にのみ設定され、他経路の追記が存在しない。
- つまり **「allowedUrlsに載っていること」自体が明示的オプトイン** に等しい（オペレーターが `targetBaseUrl` にprivate IPを打った＝意図した許可）。
- 追加フラグはローカルCLIモデルでは摩擦のみで防御利得がない。

→ **フラグ不採用**。ただしメタデータIPだけは allowedUrls 指定でも恒久ブロック（step3が常に勝つ）することで「うっかりメタデータIPを標的指定」の事故も塞ぐ。

（将来共有サービス化する場合はこの判断を再検討。設計を`SHARED-SERVICE`分岐として別ドキュメント化する。）

---

## 4. `isPrivateOrMetadataUrl` の分割

現行の単一関数を用途別に分割:

```ts
export function isCloudMetadataUrl(urlStr: string): boolean   // step3用（恒久ブロック判定）
export function isPrivateUrl(urlStr: string): boolean         // 情報用（レポート表示等）— ブロック判定には使わない
export function assertAllowedUrl(urlStr, allowedUrls): void   // 上記ロジック
export function extractBaseUrl(urlStr): string                // 現行維持
```

- `PRIVATE_IP_PATTERNS` からメタデータレンジ（169.254系）は `CLOUD_METADATA_IPS`/専用判定へ寄せる。
  - 注意: 169.254.0.0/16 はリンクローカル全域。メタデータIPは169.254.169.254等の特定アドレス。**リンクローカル全体を恒久ブロックにするか、特定メタデータIPのみか**を実装時に確定（推奨: 既知メタデータIP列挙＋169.254.169.254固定を恒久、その他169.254系は「private扱い＝標的一致なら許可」）。

---

## 5. 実標的E2Eテスト（監査「1+2セット」の+2）

url_guard修正だけでは、262件モックテストが緑のまま実標的で壊れる現状に戻る。**実標的E2Eを土台として同時に入れる**。

設計:
- `test/target-app/server.js`（既存の意図的脆弱Express、脆弱性7件）を `127.0.0.1:<ランダム空きポート>` で起動。
- vitest から child_process で spawn → readiness待ち → 全ツールを実際のHTTPで実行 → teardown。
- **アサーション**:
  1. url_guardが127.0.0.1標的をブロックしない（回帰の主目的）。
  2. 7脆弱性のうち検出可能なものを検出しスコアが10未満に低下する（監査時は検出0・満点だった）。
  3. `http://127.0.0.1:<port>@169.254.169.254/` 型URLがブロックされる（SSRFバイパス回帰）。
  4. crawler/SSRFが標的host外へリクエストしない。
- CI: モックのユニットテストとは別 job（`test:e2e`）として `npm test` パイプラインに追加。カバレッジ80%要件は維持。

これがないと「グリーンなのに壊れている」が再発する（監査の中核指摘）。

---

## 6. 実装タスク分解（TDD順）

1. **RED**: `__tests__/safety/url_guard.spec.ts` を新ロジック仕様で書き換え/追加
   - 127.0.0.1標的許可 / メタデータ恒久ブロック / userinfoバイパス / 前方一致トリック / host:portミスマッチ。
2. **GREEN**: `src/safety/url_guard.ts` を §3–§4 に沿って実装。
3. 全 `assertAllowedUrl` 呼び出し元（fuzz/bola/ssrf/ssti/cors/path/headers/jwt/privesc/scan/crawler/login/jailbreak）が新シグネチャで壊れないことを型＆テストで確認（シグネチャは不変なので呼び出し側改修は原則不要）。
4. **E2E土台**: `__tests__/e2e/target-app.e2e.spec.ts` ＋ spawnヘルパ。§5 のアサーション。
5. `npm run build` / `npm test` / `test:e2e` グリーン確認。
6. `/adversary` で本設計と実装をゲートレビュー（重要変更のため）。

---

## 7. 本設計のスコープ外（別欠陥・別タスク）

監査で指摘された他欠陥（#2 run_adaptive虚偽記載、#3 BOLA正規表現空振り、#4 jailbreak緩い部分文字列、#5 JWT no-token誤検知、#6 confidence欠落、#7 SAST正規表現、#8-11）は url_guard とは独立。E2E土台が入った後、実標的で1件ずつ再現→修正する（E2Eが再発検出器になる）。本ドキュメントは #1/#b と E2E土台に限定。

---

## 8. 実装結果（2026-07-07 完了）

url_guard 再設計＋E2E土台に加え、E2Eを再発検出器として実標的で複数の検出欠陥を修正。`/adversary` ゲート **PASS**（2イテレーション）。

### 測定設計（感度＋特異度）
- **脆弱標的** `test/target-app/server.js`（8脆弱性）→ 検出スコアカード（`__tests__/e2e/helpers/scorecard.ts`、各GTを toolName＋固有cweId/pathに束縛）で **感度100/100**。
- **堅牢標的** `test/secure-app/server.js`（8クラス全て remediation）→ **特異度0/100**（誤検知ゼロ）。負の標的が「全部フラグ」型ツールを落とす。これが「グリーンなのに壊れている」の再発防止の核心。
- ハーネス: `startTarget('vulnerable'|'secure')`、`vitest.e2e.config.ts`、`npm run test:e2e`。

### 検出ロジック修正（実標的で発見→修正→FP/FN固定テスト）
| 欠陥 | 修正 | 固定テスト |
|------|------|-----------|
| #7 SAST: ハードコード秘密/マスアサイン未検出 | `analyze_sast_deep.ts` に CWE-798（min12字＋プレースホルダ除外）/CWE-915（`Object.assign(x,req.body)`）パターン追加 | fixture vuln/safe で検出・非検出 |
| SSRF: 非クラウド環境で検出不能 | `test_ssrf.ts` に「接続失敗署名＝egressフィルタ欠如」オラクル追加。bare 5xxは不採用。1脆弱性=1finding にデデュープ | 400拒否→0/ bare500→0/ ECONNREFUSED→検出 |
| #4 jailbreak: エコー反射で誤検知 | `inject_llm_jailbreak.ts` を自ペイロード除去（stripEcho）＋開示マーカー照合に | benign "You are welcome"→0/ echo→0 |
| privesc: 同語反復・no-op計上 | `test_privilege_escalation.ts` をベースライン差分＋1件デデュープに | hardened→0/ already-admin→inconclusive/ 1件のみ |
| stackトレース未検出 | `oracle.ts` に一般Node/JSスタック署名（`at <path>.js:line:col`、`"stack":"Error:`）追加 | Node arrow-frame stack 検出 |
| 踏み台化経路 | `js_bundle_scanner.ts` の script URL fetch に同一オリジンガード | — |

### 最終ゲート
`npm run build` 成功 / `npm test` 278件緑 / `npm run test:coverage` exit0・91.5%（test_ssrf 100%）/ `npm run test:e2e` vuln=100・secure=0。

### 残（LOW、非ブロッカー）
url_guard.ts のファイル単体分岐カバレッジ78%（防御的catch未到達、グローバルは通過）。SSRF `\btimeout\b` 署名の理論的FP経路（主要FP経路は secure=0 で実証的に閉）。
