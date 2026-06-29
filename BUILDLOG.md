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
