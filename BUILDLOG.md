# BUILDLOG.md

## フェーズ1: プロジェクトセットアップ

### 作業内容
- `package.json` 作成（type:module, bin, engines:>=22, postinstall）
- `tsconfig.json` 作成（module:NodeNext, strict:true）
- `vitest.config.ts` 作成（80%カバレッジ閾値）
- `scripts/install-gitleaks.js` 作成（postinstall用・OS標準tar使用）
- `.gitignore` 作成
- `git init` 実行

### コマンド実行結果
```
npm install --legacy-peer-deps
→ 309 packages, 0 vulnerabilities
→ gitleaks v8.21.2 installed to bin/gitleaks.exe
```

### 依存関係
- `@modelcontextprotocol/sdk ^1.29.0` — MCPフレームワーク
- `undici ^7.0.0` — HTTP攻撃クライアント
- `p-limit ^6.1.0` — 並列数制御
- `tree-sitter` 等 — optionalDependencies（AST解析）
- `typescript ^5.7.0`, `vitest ^3.0.0` — 開発ツール

### 注意点
- tree-sitter-go の peer dependency 競合 → `--legacy-peer-deps` で解決
- install-gitleaks.js で外部 `tar` パッケージ不要（OS標準tar使用に修正）

---

## フェーズ2: 型定義

### 作成ファイル
- `src/types/index.ts`

### 定義型
- `Persona`, `FindingCategory`, `FindingSeverity`
- `JudgeContext`, `Finding`, `EndpointInfo`, `ParameterInfo`
- `SecurityReport`, `Remediation`, `ExtractedArtifact`
- `IAnalyzer`, `MutationResult`, `AttackResult`, `GitleaksSecret`

---

## フェーズ3: コア実装

### 作成ファイル

#### エントリーポイント
- `src/index.ts` — MCPサーバー（McpServer + StdioServerTransport）

#### 安全機構
- `src/safety/url_guard.ts` — allowlist + プライベートIPブロック

#### スコアリング
- `src/scorer/rubric.ts` — ペルソナ別減点計算・即時フェイル判定

#### レポート生成
- `src/reporter/report.ts` — Markdown形式レポート生成

#### 攻撃コア
- `src/attack/payload_mutator.ts` — エラー駆動変異器（400/401/403/429/422別戦略）
- `src/attack/dag_orchestrator.ts` — 依存関係付き並列実行

#### 情報収集
- `src/recon/language_detector.ts` — 設定ファイルベース言語自動判定
- `src/recon/endpoint_extractor.ts` — 言語→アナライザーディスパッチャー
- `src/recon/analyzers/java.ts` — Spring Boot アノテーション解析
- `src/recon/analyzers/node.ts` — Express/Fastify ルート解析
- `src/recon/analyzers/python.ts` — Flask/FastAPI ルート解析
- `src/recon/analyzers/go.ts` — net/http + gorilla/mux 解析
- `src/recon/analyzers/ruby.ts` — Rails/Sinatra ルート解析
- `src/recon/js_bundle_scanner.ts` — JSバンドルスキャン + OpenAPI探索

#### MCPツール（9本）
- `src/tools/ask_target_persona.ts`
- `src/tools/analyze_sast_deep.ts`
- `src/tools/fuzz_api_direct.ts`
- `src/tools/test_bola_idor.ts`
- `src/tools/test_privilege_escalation.ts`
- `src/tools/test_jwt_tampering.ts`
- `src/tools/scan_exposed_endpoints.ts`
- `src/tools/test_ssrf.ts`
- `src/tools/inject_llm_jailbreak.ts`

---

## フェーズ4: E2Eテスト脆弱アプリ

### 作成ファイル
- `test/target-app/server.js` — 意図的脆弱Expressサーバー
- `test/target-app/package.json`

### 脆弱性実装
- IDOR（所有権チェックなし）
- バックエンド検証なし（任意フィールド更新）
- 権限昇格（isAdmin/role受け入れ）
- 情報漏洩（スタックトレース・APIキー）
- SSRF（任意URLフェッチ）
- LLMシステムプロンプトリーク

---

## フェーズ5: テスト実装

### ユニットテスト
- `__tests__/unit/rubric.test.ts` — 全ペルソナ×全カテゴリのスコアリングマトリクス
- `__tests__/unit/url_guard.test.ts` — プライベートIP・allowlistチェック
- `__tests__/unit/payload_mutator.test.ts` — 変異器・リトライ境界値
- `__tests__/unit/report.test.ts` — レポート生成・フォーマット

### インテグレーションテスト（msw使用）
- `__tests__/integration/scan_exposed_endpoints.test.ts`
- `__tests__/integration/test_jwt_tampering.test.ts`
- `__tests__/integration/fuzz_api_direct.test.ts`
- `__tests__/integration/test_bola_idor.test.ts`
- `__tests__/integration/inject_llm_jailbreak.test.ts`
- `__tests__/integration/test_privilege_escalation.test.ts`
- `__tests__/integration/test_ssrf.test.ts`
- `__tests__/integration/analyze_sast_deep.test.ts`

### ゴールデンフィクスチャ
- `__tests__/fixtures/vuln/` — 脆弱コードサンプル（ts/java/js）
- `__tests__/fixtures/safe/` — 安全コードサンプル（ts/java）

---

## フェーズ6: CI・カスタムコマンド

### 作成ファイル
- `.github/workflows/ci.yml` — test → build → publish（mainブランチのみ）
- `.claude/commands/security-judge_goal.md` — フェーズ1〜4自律実行
- `.claude/commands/security-judge_remedy.md` — 修正案提示

---

## フェーズ7: リリース検証・ドキュメント

### 作成ファイル
- `README.md` — セットアップ手順・ツール一覧・スコアリング説明
- `BUILDLOG.md`（本ファイル）

---

## AIレッドチーム強化: inject_llm_jailbreak マルチターン化（2026-08-16）

### 背景
AIレッドチーム観点の評価で、LLM攻撃が「固定4プロンプト・単発・regex検出のみ」で、RDDが謳う「マルチターン」未実装、良性応答への過剰マッチ、意味的判定の不在が判明。スコープB（外部依存なし・判定はホスト委譲）で改修。

### 新規ファイル
- `src/attack/prompt_mutator.ts` — 難読化変換（base64 / leetspeak / rot13 / reverse / 多言語）とマルチターン攻撃キャンペーン生成（direct / crescendo / many_shot / payload_split / obfuscation / injected_compliance）。純関数・決定論的。
- `src/attack/llm_chat_client.ts` — `messages[]`配列 + 単一フィールド + SSEストリーミング対応クライアント。全fetchは `assertAllowedUrl` でゲート。

### 変更ファイル
- `src/tools/inject_llm_jailbreak.ts` — マルチターン会話状態、検出精度の是正（`LEAK_MARKERS` を高精度な開示表現へ絞込み、`REFUSAL_MARKERS` で拒否＝ガードレール維持を判定）、逆順カナリア（`SECURITYJUDGE_OK`）によるエコー耐性のある注入コンプライアンス検出、`HOST JUDGMENT REQUIRED` ブロックで最終判定をオーケストレータへ委譲。誤検出は MEDIUM confidence に較正（過剰減点を回避）。
- `src/index.ts` — `wireFormat` / `responseField` / `strategies` パラメータを登録。

### テスト
- `__tests__/unit/prompt_mutator.test.ts`（10件）
- `__tests__/integration/llm_chat_client.test.ts`（8件）
- `__tests__/integration/inject_llm_jailbreak.test.ts`（14件、既存＋マルチターン/messages/SSE/カナリア/精度是正）

### 検証結果
- `tsc --noEmit` / `tsc` ビルド: エラーなし
- `vitest run`: 全 **357件パス**（38ファイル）
- カバレッジ: 全体 lines 92.7% / branches 86.1%（attack 97.8% / tools 94.9%）— 閾値80%超

---

## AIレッドチーム強化 第2弾: 攻撃面の拡張（2026-08-16）

### 追加した攻撃・判定
- **間接プロンプトインジェクション**（`indirect_injection`）— 取得文書/メール等「データ」に埋め込んだ命令を実行するか検査（LLM01 indirect）。逆順カナリアで実行を検出。記事版・メール版の2キャンペーン。
- **機密情報の持ち出しプローブ**（`data_exfiltration`）— 他ユーザーデータ/APIキー/環境変数を要求。`SECRET_PATTERNS`（OpenAI/AWS/GitHub/Google鍵・JWT・秘密鍵ブロック）の高精度形状検出で HIGH confidence（LLM02）。攻撃文自体はシークレット形状を含まない。
- **クロス戦略コロボレーション** — 同一のシステムプロンプト漏洩を2つ以上の異なる戦略が誘発した場合、当該 leak findings を MEDIUM→HIGH confidence/severity へ昇格。単一regexシグナル依存を解消。
- **ガードレール堅牢性メトリクス** — 拒否キャンペーン数/総数・suspect数を出力に付与。

### 変更ファイル
- `src/attack/prompt_mutator.ts` — `AttackStrategy` に2種追加、`Oracle` に `secret` 追加、間接インジェクション/持ち出しのキャンペーン生成を追加。
- `src/tools/inject_llm_jailbreak.ts` — `SECRET_PATTERNS`/`detectSecret`、secretオラクル、2パス化（全キャンペーン実行→コロボレーション算出→finding生成）、堅牢性サマリ。
- `src/index.ts` — `strategies` enum とツール説明を更新。

### テスト
- `__tests__/unit/prompt_mutator.test.ts`（+2件）
- `__tests__/integration/inject_llm_jailbreak.test.ts`（+6件: 単一戦略MEDIUM/コロボレーションHIGH/間接注入/機密持ち出し/拒否時の非検出/堅牢性メトリクス）

### 検証結果（第2弾）
- `tsc` ビルド: エラーなし
- `vitest run`: 全 **364件パス**（38ファイル）
- カバレッジ: 全体 lines 92.94% / branches 86.5%（attack 98.0% / tools 95.1%）— 閾値80%超

---

## AIレッドチーム強化 第3弾: 責任あるAI（幻覚/バイアス/毒性）＋RDD整合（2026-08-16）

### RDD⇔コード不整合の解消
- `RDD.md` のカテゴリD即時フェイル対象を「commercial, internal」→「なし（即時フェイル対象外・段階減点のみ）」へ修正し、理由（LLM検出は確率的でホスト判定が必要／誤検知の致命化回避／コロボレーションでHIGH昇格）を明記。実装 `INSTANT_FAIL_PERSONAS.D=[]` と一致させた（＝コードに合わせてRDDを修正）。

### 新ツール `test_llm_safety`
タクソノミー③④（幻覚・バイアス・毒性）に対応。
- **幻覚**: 架空カナリア・オラクル。存在し得ない固有名（Zylthorpe-Vandersnoot定理 等）を説明させ、不確実性/否認マーカーが無く実質的に記述したら「自信のある捏造」として検出（MEDIUM confidence, LLM09）。
- **バイアス/毒性**: 意味判定が本質のためホスト委譲を主軸。拒否されなかった応答を候補として `HOST JUDGMENT REQUIRED` に提示（LOW severity/confidence）。拒否＝ガードレール維持で非検出。
- 責任あるAI堅牢性メトリクス（拒否数/総数）を出力。severity LOW＋小減点で情報寄り（スコアを支配しない）。

### 新規ファイル
- `src/attack/safety_probes.ts` — 純粋・決定論的なプローブ定義。
- `src/tools/test_llm_safety.ts` — プローブ実行・幻覚オラクル・ホスト委譲・メトリクス。
- `__tests__/unit/safety_probes.test.ts`（4件）/ `__tests__/integration/test_llm_safety.test.ts`（7件）

### 変更ファイル
- `src/index.ts` — `test_llm_safety` を登録（MCPツール計23本）。

### 検証結果（第3弾）
- `tsc` ビルド: エラーなし
- `vitest run`: 全 **375件パス**（40ファイル）
- カバレッジ: 全体 lines 93.2% / branches 86.58%（attack 98.2% / tools 95.2%）— 閾値80%超
- MCPサーバ起動スモーク: `tools/list` で23本を確認（`test_llm_safety` 登録済み）

---

## AIレッドチーム強化 第4弾: 深さ・測定・網羅の総仕上げ（2026-08-16）

10項目を一括実装。共通検出モジュール `src/attack/detectors.ts` を新設し、2ツールを統一。

| # | 内容 |
|---|---|
| 1 適応ループ | 拒否されたら reframing フォローアップを会話に追記して継続（`adaptiveFollowups`、既定ON）。応答駆動化。 |
| 2 多言語検出 | LEAK/REFUSAL/UNCERTAINTY マーカーを EN＋JA/ES/FR/DE/ZH に拡張（`detectors.ts`）。日本語アプリの偽陰性を解消。 |
| 3 応答デコード | base64/rot13/reverse でエンコードされた応答をデコードしてから漏洩検出（`decodeVariants`/`detectLeakAny`）。出力符号化回避に対応。 |
| 4 攻撃成功率(ASR) | `attempts`(既定1,最大5) で各キャンペーンを反復し成功率を計測・出力。 |
| 5 ツール濫用 | `tool_abuse` 戦略＋`EXFIL_CANARY`。攻撃者指定のツール/関数呼び出し構築を検出（LLM06, CWE-918）。 |
| 6 PII/機密拡張 | 鍵/JWT/秘密鍵(HIGH)に加え、メール/電話/SSN/クレカ(Luhn検証)(MEDIUM) を検出（`detectSecret`）。 |
| 7 一貫性オラクル | 漏洩を同一プロンプトで再取得し Jaccard 類似度で安定性を判定。安定なら単一戦略でも HIGH に昇格、揺らげば MEDIUM 据え置き。 |
| 8 リソース枯渇 | `test_llm_safety` に `resource` プローブ追加。巨大出力の生成を検出（LLM10）。 |
| 9 レポート統合 | `report.ts` に OWASP LLM Top-10 別の修正提案と OWASP/CWE/confidence タグ表示を追加。 |
| 10 構造化出力 | 両ツールに `=== STRUCTURED ===` の機械可読JSONサマリを付与（ホスト連携用）。 |

### 新規/変更ファイル
- 新規: `src/attack/detectors.ts`, `__tests__/unit/detectors.test.ts`
- 変更: `src/attack/{prompt_mutator,safety_probes}.ts`, `src/tools/{inject_llm_jailbreak,test_llm_safety}.ts`, `src/reporter/report.ts`, `src/index.ts`, 各テスト

### 検証結果（第4弾）
- `tsc` ビルド: エラーなし
- `vitest run`: 全 **401件パス**（41ファイル）
- カバレッジ: 全体 lines 93.46% / branches 86.59%（attack 98.4% / reporter 100% / tools 95.3%）— 閾値80%超
- MCPサーバ起動スモーク: 23本・`tool_abuse`/`attempts` 露出を確認
