# RDD.md - security-judge

## プロジェクト概要

| 項目 | 内容 |
|------|------|
| **プロジェクト名** | security-judge |
| **生成先ディレクトリ名** | `security-judge` |
| **種別** | Claude Code MCP ツール（npmパッケージ） |
| **目的** | 制作したアプリに対して自律型サイバー攻撃（Agentic Hacking）を実行し、脆弱性を検出・スコアリングする |

### 一言説明
Claude Code の MCP（Model Context Protocol）ツールとして動作するセキュリティ評価エージェント。  
フロントエンドのUI制限を無視したAPIへの直接攻撃・静的解析・LLMジェイルブレイクを組み合わせ、最も厳格な基準でセキュリティ耐性を 0〜10点で評価する。

---

## 実装範囲（MVP）

### 評価実行フロー

| フェーズ | 内容 |
|---------|------|
| フェーズ1 | **ペルソナ定義**: ターゲット層をヒアリングし、減点係数を決定 |
| フェーズ2 | **情報収集**: ソースコードスキャン・エンドポイント特定（Java/TS/JS対応）・クライアント側バリデーションの抽出・JSバンドルからの隠しエンドポイント抽出 |
| フェーズ3 | **自律攻撃実行**: HTTPクライアント経由のAPI直接攻撃。エラー駆動変異器（`payload_mutator.ts`）により最大3回の知性的な再攻撃を実行。発見情報を次の攻撃コンテキストに引き継ぐ攻撃チェーンをサポート |
| フェーズ4 | **採点・レポーティング**: ペルソナ基準の減点方式で 0〜10点評価。再現可能な curl コマンド付きレポートを出力 |

### フェーズ2: 情報収集の詳細

#### 言語自動判定（`language_detector.ts`）

ソースコードパスが指定された場合、ファイル拡張子・設定ファイルの存在から言語を自動判定し、対応アナライザーを動的に実行する：

```
.java + pom.xml / build.gradle  → JavaAnalyzer
.py + requirements.txt / pyproject.toml → PythonAnalyzer
go.mod + .go                    → GoAnalyzer
Gemfile + .rb                   → RubyAnalyzer
package.json + .ts              → NodeAnalyzer
package.json + .js              → NodeAnalyzer
```

ソースコードパスが指定されない（URLのみ）場合 → HTTPフォールバックへ

#### ソースコードあり: 言語別アナライザー（`recon/analyzers/`）

判定された言語のアナライザーを実行し、エンドポイントとクライアント側バリデーションを抽出する。アナライザーは `IAnalyzer` インターフェースを実装し、言語が追加された場合は新しいファイルを追加するだけで対応できる設計とする。

**各アナライザーの共通責務**:
1. 対象ファイルをtree-sitterでAST解析（対応grammarsを動的ロード）
2. エンドポイント（HTTPメソッド・パス・パラメータ）を抽出
3. クライアント側バリデーションの有無を特定

#### ソースコードなし: HTTPフォールバック

- レスポンスヘッダー（`X-Powered-By`・`Server`）から言語/FW推定
- `robots.txt`・`sitemap.xml`・OpenAPI定義ファイル（`/openapi.json`・`/swagger.json`・`/v3/api-docs`）の自動探索
- フロントエンドJSバンドルの正規表現スキャン（`/api/`・`fetch(`・`axios.`パターンで隠しエンドポイントURL抽出）

#### 共通処理（言語問わず実施）

- gitleaks によるシークレット検知（ソースコードがある場合）

### フェーズ3: 自律攻撃の詳細

#### エラー駆動変異器（`payload_mutator.ts`）

単純リトライではなく、エラーレスポンスを分析して変異戦略を決定する：

| エラー種別 | 変異戦略 |
|-----------|---------|
| 400 "field required" | 必須フィールドを補完して再試行 |
| 400 "invalid type" | 型変換（string→number等）して再試行 |
| 400 "max length" | ペイロードを短縮して再試行 |
| 401 Unauthorized | トークンリフレッシュして再試行 |
| 403 Forbidden | 別ユーザートークンで再試行 |
| 422 Unprocessable | エラーメッセージからフィールド名を抽出して修正 |
| 429 Too Many Requests | バックオフ延長後に別ヘッダー（`X-Forwarded-For`偽装）で再試行 |
| 500 Internal Server Error | Finding確定（情報漏洩C判定）、次のターゲットへ |

変異ラウンド:
- 1回目: オリジナルペイロード
- 2回目: 境界値（空文字・null・-1・2^31-1・空配列）
- 3回目: エンコーディング変換（URLエンコード・Unicodeエスケープ・Base64）

#### 並列攻撃戦略

| レベル | 内容 |
|-------|------|
| **レベル1: ツール間並列** | 独立ツールを同時実行（例: `scan_exposed_endpoints` + `test_jwt_tampering` + `fuzz_api_direct`） |
| **レベル2: エンドポイント間並列** | 複数エンドポイントをN並列バッチ処理。同時実行上限はペルソナで制御（personal=1、commercial=5） |
| **レベル3: ペイロード並列** | 1エンドポイントに対してSQLi系・型破壊系・XSS系を同時投射 |

#### 攻撃DAG（依存関係付き実行順序）

```
フェーズ2: 情報収集（直列・必須完了待ち）
├── SASTスキャン + gitleaks
├── エンドポイント抽出（Spring Boot / Express / JSバンドル）
└── クライアントバリデーション特定
         ↓
フェーズ3: 攻撃実行
├── [並列グループA] 独立攻撃
│   ├── fuzz_api_direct（エンドポイントごとにレベル2並列）
│   ├── scan_exposed_endpoints
│   └── test_jwt_tampering
└── [直列グループB] 情報依存攻撃
    ├── test_bola_idor
    ├── test_privilege_escalation
    └── test_ssrf（社内/商用ペルソナのみ）
    ※ グループAで発見した情報をグループBのコンテキストに引き継ぐ
```

### 実装するMCPツール（9本）

#### コアツール（5本）

| ツール名 | 機能 | OWASP対応 |
|---------|------|-----------|
| `ask_target_persona` | アプリ用途（自分用/チーム用/社内用/商用）・ターゲットURL・ソースコードパスをヒアリングし、評価基準のベースラインを決定 | — |
| `analyze_sast_deep` | tree-sitter でAST解析。危険な関数呼び出しの検知 + gitleaks によるシークレット検知 | A01, A02, C |
| `fuzz_api_direct` | 指定エンドポイントへUI制限を無視した異常値・長文・改ざんパラメータを送信。エラー駆動変異器で最大3回再攻撃 | A01, A03, A |
| `test_bola_idor` | 取得トークンを保持したまま他ユーザーIDやリソースURLへのアクセスを試みる（横方向権限昇格） | A01, B |
| `inject_llm_jailbreak` | AIチャット入力欄にシステムプロンプト抽出・制限解除を狙うマルチターンプロンプトを送信 | D |

#### 追加ツール（4本）

| ツール名 | 機能 | OWASP対応 | 対象ペルソナ |
|---------|------|-----------|------------|
| `test_privilege_escalation` | `isAdmin=true`・`role=admin`・JWTペイロードの`role`フィールド書き換えによる縦方向権限昇格を試みる | A01, B | 全ペルソナ |
| `test_jwt_tampering` | `alg: none`攻撃・RS256→HS256アルゴリズム混乱・署名スキップ・有効期限改ざんを試みる | A02 | 全ペルソナ |
| `scan_exposed_endpoints` | Actuator（`/actuator/env`等）・Swagger（`/v3/api-docs`）・`/.env`・`/debug`等をwordlistで自動探索 | A05, C | 全ペルソナ |
| `test_ssrf` | URLパラメータ（`redirect_url`・`webhook`・`imageUrl`等）にクラウドメタデータIP（169.254.169.254）・内部IPを注入 | A10 | 社内用・商用 |

> **`test_ssrf` と安全機構の区別**: `url_guard.ts`はsecurity-judge自身がプライベートIPへ送信することを禁止するが、`test_ssrf`は「ターゲットアプリ自身がSSRFを実行するか」を検証するものであり、ペイロードにプライベートIPを含めることは問題ない。

### フェーズ1: ヒアリング詳細（`ask_target_persona`）

以下を順番にヒアリングし、`JudgeContext`へセットする：

| # | 質問 | 全ペルソナ | 補足 |
|---|------|-----------|------|
| 1 | ペルソナ選択（自分用 / チーム用 / 社内用 / 商用） | ✓ | `penaltyMultiplier`を確定 |
| 2 | ターゲットベースURL（例: `http://localhost:8080`, `https://app.example.com`） | ✓ | allowlistに登録 |
| 3 | ソースコードのルートパス（例: `/home/user/myapp`）。ない場合はスキップ | ✓ | フェーズ2のSAST対象 |
| 4 | LLMチャット機能の有無（`inject_llm_jailbreak`を実行するか） | ✓ | NOなら対象ツールをスキップ |

> **所有権確認は行わない。** セキュリティテストツールの標準的な設計（Burp Suite / ZAP と同様）に従い、ツール側での確認は不要。代わりに README に免責事項（authorized testing only / unauthorized use is illegal）を明記する。

### カスタムコマンド（2本）

| コマンド | 機能 |
|---------|------|
| `/security-judge_goal` | フェーズ1〜4の自律実行を開始するメインコマンド |
| `/security-judge_remedy` | 検出された脆弱性に対する修正案（Before/After）を提示するコマンド |

### スコアリング・ルーブリック

| ペルソナ | `penaltyMultiplier` | 減点方針 |
|---------|---------------------|---------|
| 自分用 (`personal`) | 0.3 | 致命的な情報漏洩（環境変数・クラウド認証情報のハードコード）のみ厳格減点 |
| チーム用 (`team`) | 0.5 | BOLA/IDOR（他人のデータへのアクセス）を中程度の減点対象 |
| 社内用 (`internal`) | 0.8 | 権限昇格・内部ネットワーク情報漏洩（SSRF等）を厳格減点 |
| 商用 (`commercial`) | 1.0 | 最高難易度（Zero Trust前提）。以下の即時フェイル条件を適用 |

**スコア計算式**: `score = max(0, 10 - Σ(各Findingの基礎減点 × penaltyMultiplier))`

#### 各カテゴリの基礎減点（上限10点）

| カテゴリ | 基礎減点 | 即時フェイル対象ペルソナ |
|---------|---------|----------------------|
| A. バックエンド検証欠落 | 10点 | commercial |
| B. 認可制御欠落（BOLA/IDOR・権限昇格） | 10点 | commercial, internal |
| C. 情報漏洩（スタックトレース・APIキー等） | 10点 | commercial, internal |
| D. LLMガードレール突破 | 5点（段階的） | commercial, internal |

#### 商用ペルソナの即時フェイル条件（スコア0点）

| 分類 | 検知条件 | 観測方法 |
|------|---------|---------|
| A. バックエンド検証欠落 | フロントエンドで入力制限しているが、API直接攻撃で異常値がDBに保存または200/201が返った場合 | レスポンスステータスコード + レスポンスボディで判定 |
| B. 認可制御欠落（BOLA/IDOR） | `isAdmin=true` 等のパラメータ改ざんリクエストが成功した場合 | レスポンスコード + 返却データで判定 |
| C. 情報漏洩 | スタックトレース・SQL構文・フレームワークバージョンがHTTPレスポンスに含まれた場合、またはコード内にAPIキーが存在する場合 | gitleaks スキャン結果 + レスポンスボディの正規表現マッチ |
| D. LLMガードレール突破 | AIがシステムプロンプトの一部を漏洩、または意図しないタスクを実行した場合 | レスポンスに事前定義のシステムプロンプトキーワードが含まれるか判定 |

### 安全機構（必須）

本ツールは任意URLへ異常値リクエストを送信するため、以下の安全機構を実装する：

- **対象URLの allowlist 方式**: ユーザーが明示指定したベースURL以外への送信を禁止
- **プライベートIPブロック（security-judge自身の送信先）**: RFC1918アドレス（10.x, 172.16-31.x, 192.168.x）およびクラウドメタデータIP（169.254.169.254等）への送信を禁止
- **リダイレクト先検証**: HTTPリダイレクト先がallowlist外の場合は追跡しない
- **concurrency上限**: ペルソナで制御（personal=1, team=2, internal=3, commercial=5）

---

## 除外機能（スコープ外）

- フロントエンドUI（Web画面・ダッシュボード等）
- データベース（評価結果はメモリ内で保持、レポートはファイル出力）
- ユーザー認証・アカウント管理
- 評価履歴の永続化・管理
- グローバルインストール（`npx` 経由での起動を前提とする）

---

## 将来の拡張（フェーズ2以降）

| 機能 | 内容 | 実装コスト | 検出価値 |
|------|------|-----------|---------|
| 攻撃チェーン | `Finding`の`extractedArtifacts`（取得APIキー・内部URL）を次ツールのコンテキストに引き渡す連鎖シナリオ | 高 | 高 |
| `test_sql_injection` | 検索系エンドポイントへのSQLi・time-based blind SQL（SLEEP計測）。偽陽性管理が前提 | 中 | 高 |
| JSソースマップ解析 | `{bundle}.js.map`から元コードを復元し`analyze_sast_deep`を適用 | 中 | 高 |
| `test_business_logic` | 数量マイナス値・ゼロ価格等。フェーズ1でアプリ種別（EC/決済有無）を追加ヒアリングして有効化 | 低 | 高 |
| `test_graphql_injection` | introspectionクエリ・Depth/Batch攻撃 | 中 | 中 |
| `test_rate_limit_bypass` | `X-Forwarded-For`偽装・IPローテーションでレート制限バイパス | 中 | 中 |
| `scan_dependency_cve` | `npm audit` / `mvn dependency-check` のラッパー | 低 | 中 |
| `test_xxe` | XML入力エンドポイントへのXXE注入 | 高 | 中 |

---

## データモデル（型定義のみ、DBなし）

```typescript
// ペルソナ
type Persona = 'personal' | 'team' | 'internal' | 'commercial';

// penaltyMultiplier の確定値
const PENALTY_MULTIPLIER: Record<Persona, number> = {
  personal:   0.3,
  team:       0.5,
  internal:   0.8,
  commercial: 1.0,
};

// 攻撃チェーン用: 攻撃で取得した情報（将来拡張）
interface ExtractedArtifact {
  type: 'token' | 'apiKey' | 'internalUrl' | 'stackTrace';
  value: string;
  source: string;  // 取得元ツール名
}

// 評価コンテキスト（メモリ内保持）
interface JudgeContext {
  persona: Persona;
  penaltyMultiplier: number;
  targetBaseUrl: string;
  allowedUrls: string[];            // 安全機構: 送信許可URLのリスト
  endpoints: EndpointInfo[];
  findings: Finding[];
  extractedArtifacts: ExtractedArtifact[];  // 攻撃チェーン用
  score: number;                    // 0〜10
}

// エンドポイント情報
interface EndpointInfo {
  method: string;
  path: string;
  parameters: ParameterInfo[];
  authRequired: boolean;
  sourceLanguage: 'java' | 'typescript' | 'javascript';
}

// 検知結果
interface Finding {
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  category: 'A' | 'B' | 'C' | 'D';
  description: string;
  evidence: string;                 // 再現curlコマンド等
  isFail: boolean;                  // 即時フェイルか
  baseDeduction: number;            // 基礎減点（penaltyMultiplier適用前）
}

// レポート
interface SecurityReport {
  timestamp: string;
  persona: Persona;
  score: number;
  findings: Finding[];
  remediations: Remediation[];
}

// 修正案
interface Remediation {
  findingCategory: string;
  filePath?: string;
  lineNumber?: number;
  before: string;
  after: string;
  description: string;
}
```

---

## 画面構成

**なし**（MCPツール・CLIツールのためUI不要）

出力はすべて Claude Code のターミナル・チャット画面に表示する。

---

## 認証の有無と方式

**なし**（Claude Code の MCP 接続セキュリティに委譲）

---

## ユーザー権限・ロール

**なし**（単一ユーザー・単一コンテキスト）

---

## 技術スタック

| レイヤー | 技術 | 選定理由 |
|---------|------|---------|
| **ランタイム** | Node.js 24 LTS（`engines: ">=22"`） | 20はEOL済み（2026-04-30）、24が現行Active LTS |
| **言語** | TypeScript 5.x（`module: NodeNext`, `strict: true`） | MCP SDK がESM前提のため NodeNext 必須 |
| **MCPフレームワーク** | `@modelcontextprotocol/sdk ^1.29` | バージョンpin必須（v2 alpha進行中・破壊的変更継続） |
| **HTTPクライアント** | `undici`（Node.js 標準モジュール） | 生HTTP制御・malformedリクエスト送信に対応。axiosは攻撃用途に不向き |
| **AST解析** | `tree-sitter` + 言語別grammars（動的ロード） | 判定された言語のgrammarsのみをロード。対応: java / python / go / ruby / javascript / typescript |
| **シークレット検知** | `gitleaks`（CLIサブプロセス実行） | 成熟したルールセット・エントロピー検知・自前regex実装は不要 |
| **concurrency制御** | `p-limit` | ペルソナ別並列数上限の制御 |
| **テストFW** | `vitest` | ユニット・インテグレーションテスト |
| **HTTPモック** | `msw`（またはnock） | 外部I/Oを決定論的にモック化 |
| **配布** | `npm publish`（`npx security-judge@1.x` で起動） | バージョン指定付きnpxでサプライチェーンリスク低減 |

> AGENT.md のデフォルト構成（React + MUI + Express + PostgreSQL）は**適用しない**。  
> MCPツール単体（バックエンドのみ相当）として構成する。

---

## テスト戦略

### 方針

- カバレッジ目標: **80%以上**（vitest coverage）
- ユニット・インテグレーション・E2E の3層必須

### テストカテゴリと設計

| テスト種別 | 対象 | 手法 |
|-----------|------|------|
| **ユニット** | スコアリングロジック（rubric.ts）・エラー駆動変異器（payload_mutator.ts）・レポート生成（report.ts）・URL検証（url_guard.ts） | vitest、外部I/Oなし |
| **インテグレーション** | 各MCPツール（9本）の入出力検証 | vitest + msw でHTTP/LLMをモック |
| **E2E** | フェーズ2〜4の自律実行フロー | テスト用脆弱アプリ（`test/target-app/`）を実対象として使用 |

### スコアリングテストマトリクス（必須）

ペルソナ × カテゴリの全組み合わせで期待スコアを定義し、パラメタライズドテストとして実装する：

| ペルソナ | カテゴリA発火 | カテゴリB発火 | カテゴリC発火 | カテゴリD発火 | 期待スコア |
|---------|-------------|-------------|-------------|-------------|-----------|
| personal | - | - | - | - | 10 |
| personal | ✓ | - | - | - | 7.0（10 - 10×0.3） |
| commercial | ✓ | - | - | - | 0（即時フェイル） |
| commercial | - | ✓ | - | - | 0（即時フェイル） |
| commercial | - | - | - | ✓ | 5.0（10 - 5×1.0） |
| internal | - | ✓ | - | - | 0（即時フェイル） |
| （全ペルソナ×全カテゴリの網羅はコードに記述） | | | | | |

### エラー駆動変異器のリトライテスト（境界値）

- 0回目で成功 → 再攻撃なし
- 3回目で成功 → 正常終了
- 3回すべて失敗 → Finding として記録、4回目の実行がないことを確認

### ゴールデンフィクスチャ（SAST精度検証）

```
__tests__/fixtures/
├── vuln/
│   ├── hardcoded_secret.ts    # ハードコードAPIキー
│   ├── hardcoded_secret.java  # ハードコードパスワード（Spring Boot）
│   └── dangerous_eval.js
└── safe/
    ├── env_var_usage.ts        # 環境変数経由でのシークレット取得
    └── safe_query.java         # パラメタライズドクエリ
```

### テスト用脆弱アプリ（E2E用）

`test/target-app/` に最小の脆弱Expressサーバーを同梱：IDOR・verbose error・ハードコードAPIキー・バックエンド検証なし・SSRF可能なURLパラメータ

### 外部I/Oのモック化方針

- `fuzz_api_direct` / `test_bola_idor` 等: msw でHTTPレスポンスをスタブ化
- `inject_llm_jailbreak`: LLMレスポンスをJSONフィクスチャで固定
- ユニットテストでは実ネットワーク・実LLMへの通信を完全遮断

### CI（GitHub Actions）

```
.github/workflows/ci.yml
  ↓
  npm test（vitest + カバレッジ80%チェック）
  ↓ パスしたら
  npm run build（tsc）
  ↓ パスしたら
  npm publish（mainブランチのみ）
```

---

## 外部サービス連携

| 連携先 | 内容 |
|-------|------|
| **評価対象アプリ** | ユーザーが指定したベースURL（allowlist検証済み）にHTTPリクエストを送信 |
| **Claude Code** | MCPプロトコル経由でツール呼び出しを受け付ける |
| **gitleaks** | CLIサブプロセスとして実行（オフライン、ネットワーク不要） |

---

## プロジェクト構成

```
security-judge/
├── src/
│   ├── index.ts                      # MCPサーバー エントリーポイント
│   ├── tools/                        # MCPツール実装（9本）
│   │   ├── ask_target_persona.ts
│   │   ├── analyze_sast_deep.ts
│   │   ├── fuzz_api_direct.ts
│   │   ├── test_bola_idor.ts
│   │   ├── inject_llm_jailbreak.ts
│   │   ├── test_privilege_escalation.ts
│   │   ├── test_jwt_tampering.ts
│   │   ├── scan_exposed_endpoints.ts
│   │   └── test_ssrf.ts
│   ├── attack/                       # 攻撃コアロジック
│   │   ├── payload_mutator.ts        # エラー駆動変異器
│   │   └── dag_orchestrator.ts       # 攻撃DAG実行制御
│   ├── recon/                        # フェーズ2: 情報収集
│   │   ├── language_detector.ts      # 言語自動判定（拡張子・設定ファイル）
│   │   ├── endpoint_extractor.ts     # ディスパッチャー（判定結果→アナライザー呼び出し）
│   │   ├── analyzers/                # 言語別プラグイン（IAnalyzer実装）
│   │   │   ├── java.ts
│   │   │   ├── python.ts
│   │   │   ├── go.ts
│   │   │   ├── ruby.ts
│   │   │   └── node.ts
│   │   └── js_bundle_scanner.ts      # HTTPフォールバック: JSバンドルからURL抽出
│   ├── scorer/                       # スコアリングロジック
│   │   └── rubric.ts
│   ├── reporter/                     # レポート生成
│   │   └── report.ts
│   ├── safety/                       # 安全機構
│   │   └── url_guard.ts
│   └── types/                        # 型定義
│       └── index.ts
├── __tests__/
│   ├── fixtures/
│   │   ├── vuln/                     # ゴールデンサンプル（脆弱コード）
│   │   └── safe/                     # ゴールデンサンプル（安全コード）
│   ├── unit/
│   │   ├── rubric.test.ts
│   │   ├── payload_mutator.test.ts
│   │   ├── report.test.ts
│   │   └── url_guard.test.ts
│   └── integration/
│       ├── analyze_sast_deep.test.ts
│       ├── fuzz_api_direct.test.ts
│       ├── test_bola_idor.test.ts
│       ├── test_privilege_escalation.test.ts
│       ├── test_jwt_tampering.test.ts
│       ├── scan_exposed_endpoints.test.ts
│       ├── test_ssrf.test.ts
│       └── inject_llm_jailbreak.test.ts
├── test/
│   └── target-app/                   # E2E用テスト脆弱アプリ
│       ├── server.ts
│       └── package.json
├── .claude/
│   └── commands/
│       ├── security-judge_goal.md
│       └── security-judge_remedy.md
├── .github/
│   └── workflows/
│       └── ci.yml
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── BUILDLOG.md
└── README.md
```

---

## 環境変数

```env
# なし（ユーザー環境の認証情報には依存しない）
# ターゲットURLはMCPツール呼び出し時に引数として受け取る
```

---

## 起動・配布方法

```bash
# ローカル開発
npm run dev

# テスト実行
npm test
npm run test:coverage   # カバレッジ確認（80%以上必須）

# ビルド
npm run build

# npm公開後の利用（バージョン指定でサプライチェーンリスク低減）
npx security-judge@1.x
```

### Claude Code への MCP 登録（利用者向け）

```json
// .claude/settings.json または settings.local.json
{
  "mcpServers": {
    "security-judge": {
      "command": "npx",
      "args": ["-y", "security-judge@1.x"]
    }
  }
}
```

---

## 期待される成果物

```
security-judge/
├── src/                  # MCPサーバー実装（起動可能）
├── __tests__/            # ユニット・インテグレーションテスト（カバレッジ80%以上）
├── test/target-app/      # E2E用テスト脆弱アプリ
├── .claude/commands/     # カスタムコマンド定義
├── .github/workflows/    # CI（test → build → publish）
├── package.json          # npm publishable な状態
├── tsconfig.json
├── vitest.config.ts
├── BUILDLOG.md
└── README.md             # セットアップ手順
```

---

**文書バージョン**: 3.0  
**対応仕様書**: security-judge.md  
**変更履歴**:
- v1.0: 初版
- v2.0: 技術スタック全面刷新・テスト戦略追加（adversaryレビュー対応）
- v3.0: MCPツール9本に拡充・エラー駆動変異器・攻撃DAG・並列戦略・将来拡張セクション追加
- v3.1: フェーズ1ヒアリング詳細追加（URL・ソースパス・LLM有無）・所有権確認なし方針を明記
- v3.2: 言語自動判定+動的アナライザー設計に変更（FW固定対応表廃止）・ソースコードなし時のHTTPフォールバック追加
