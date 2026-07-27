
# プロジェクト README（AI Agent 実行用）

このフォルダで **AI Agent** に本ドキュメントを読ませ、要件定義書（RDD.md）に基づいて、MCPツール（npmパッケージ）を0から自動生成します。

## 基本設定
- **プロジェクト名**: security-judge
- **フロントエンド**: なし（MCPツールのためUI不要）
- **バックエンド**: Node.js 24 LTS (TypeScript) + `@modelcontextprotocol/sdk ^1.29`（MCPサーバー）
- **データベース**: なし（評価結果はメモリ内保持、レポートはファイル出力）
- **配布方法**: `npm publish`（`npx security-judge@1.x` で起動）
- **生成先ディレクトリ名**: `security-judge`
- **グローバルインストールや sudo は使わないでください。ホーム配下の設定も変更しないでください。**
- **作業ログは BUILDLOG.md に残してください。**

> 重要方針: **ユーザ環境を汚さない**（グローバルインストール禁止・ホーム配下の設定ファイルに変更禁止・sudo 使用禁止）。すべて **現在のプロジェクト配下だけ** で完結させてください。
>
> **例外**: Node.js 等の **環境構築に必要なツールのインストールのみ**、グローバルインストール・sudo の使用を許可する。
>
> **gitleaks について**: グローバルインストール禁止の原則に従い、`package.json` の `postinstall` スクリプトでプロジェクト内の `bin/` ディレクトリにバイナリをダウンロードし、実行時は `bin/gitleaks` をフルパスで呼び出す。グローバルに `gitleaks` コマンドをインストールしない。

---

## フェーズ管理ルール（PGDD）— 絶対厳守

本プロジェクトは `.pgdd/` でフェーズ管理される。**作業の最初に必ず以下を実行すること。**

### 1. 現在フェーズの確認（作業開始前に必須）

```
1. .pgdd/state.json を読み、currentPhase を確認する
2. .pgdd/config.json を読み、currentPhase に対応する allow / block を確認する
3. 作業対象ファイルが block に含まれていないことを確認する
```

### 2. ファイル書き込み禁止ルール

| 条件 | 動作 |
|------|------|
| 書き込み先が `block` リストのプレフィックスに一致 | **書き込み禁止。即座に中断し、ユーザーに報告する** |
| 書き込み先が `allow` リスト外 | **書き込み禁止。即座に中断し、ユーザーに報告する** |
| 書き込み先が `allow` リスト内 かつ `block` 外 | 書き込み可 |

**ブロック時の報告フォーマット:**
```
⛔ PGDD フェーズ制約違反
対象ファイル: {ファイルパス}
現在フェーズ: {フェーズ名} ({id})
理由: blockルール "{マッチしたblock}") に該当 / allowリスト外
→ このフェーズでは変更できません。
```

### 3. フェーズ移行の禁止

- **Agent 自身が `.pgdd/state.json` を書き換えてはならない**
- 完了条件を満たしたらユーザーに以下を報告して**必ず止まる**:

```
✅ フェーズ完了条件を満たしました
フェーズ: {フェーズ名}
完了条件: {completionCondition}

次フェーズへ進む場合は /pgdd next を実行してください。
```

- ユーザーが `/pgdd next` を実行して state.json が更新されるまで、次フェーズのファイルには手を触れない

---

## 1. ゴール

RDD.md に定義された要件を実装し、**MCPサーバーとして起動可能な npm パッケージ**の状態で引き渡す。

具体的な完了条件:
- `npm run dev` でMCPサーバーが起動し、Claude Code から MCP ツール9本が呼び出せること
- `npx security-judge@1.x` で起動できるよう `package.json` が `npm publishable` な状態であること
- `npm test` がパスし、カバレッジが 80% 以上であること

### 実装範囲（MVP）
RDD.md の「実装範囲」「MVP」セクションに従う。

### 除外機能
RDD.md の「除外機能」「スコープ外」セクションに従う。フロントエンド・データベースは実装しない。

---

## 2. プロジェクト構成

RDD.md に記載のディレクトリ構造に従う:

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
│   │   ├── language_detector.ts      # 言語自動判定
│   │   ├── endpoint_extractor.ts     # ディスパッチャー
│   │   ├── analyzers/                # 言語別プラグイン（IAnalyzer実装）
│   │   │   ├── java.ts
│   │   │   ├── python.ts
│   │   │   ├── go.ts
│   │   │   ├── ruby.ts
│   │   │   └── node.ts
│   │   └── js_bundle_scanner.ts      # HTTPフォールバック
│   ├── scorer/
│   │   └── rubric.ts
│   ├── reporter/
│   │   └── report.ts
│   ├── safety/
│   │   └── url_guard.ts
│   └── types/
│       └── index.ts
├── __tests__/
│   ├── fixtures/
│   │   ├── vuln/
│   │   └── safe/
│   ├── unit/
│   └── integration/
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
├── bin/                              # gitleaks バイナリ配置先（postinstall で自動取得）
├── scripts/
│   └── install-gitleaks.js           # postinstall スクリプト
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── BUILDLOG.md
└── README.md
```

---

## 3. 実行前チェック（Agent のやること）

### 3.1. 環境チェック（必須）

以下のツールを **インストールコマンドで確認・インストールする**（既にインストール済みならスキップ）。

```bash
# Node.js 24 LTS（必須）
node --version   # v22以上であれば可（engines: ">=22" のため）
npm --version
```

> データベースのインストールは不要。gitleaks はプロジェクト内 `bin/` に配置するため、グローバルインストールしない。

> この環境チェックでのインストールのみ、グローバルインストール・sudo の使用を許可する。

### 3.2. プロジェクト準備

1. **RDD.md を読み込み、要件を把握する**
2. **作業ディレクトリを固定**: 現在のフォルダをルートとし、生成物はプロジェクトディレクトリ以下に作る。
3. **禁止事項を遵守**（環境構築を除く）:
   - `npm i -g ...` / `yarn global add ...` の禁止（gitleaks 含む）
   - `sudo` の禁止
   - `~/.zshrc`、`~/.bashrc`、`~/.npmrc` などホーム配下の編集禁止
   - OS やシェルのグローバル設定変更禁止
4. **ログ**: `BUILDLOG.md` を新規作成し、以降のコマンドと結果要約を逐次追記。

---

## 3.5. 開発前チェックリスト（Agent が必ず確認）

RDD.md を読んだ後、以下の項目がすべて揃っているか確認する。
**不足がある場合はユーザーに質問し、すべて埋まってから開発を開始すること。**

| # | チェック項目 | 確認内容 |
|---|---|---|
| 1 | プロジェクト名・ディレクトリ名 | 生成先のディレクトリ名が決まっているか |
| 2 | アプリの概要・目的 | 何をするMCPツールか明確か |
| 3 | MVP範囲（実装するツール一覧） | どのMCPツールを実装するか具体的に列挙されているか |
| 4 | 除外機能（やらないこと） | スコープ外が明示されているか |
| 5 | データモデル（型定義） | 型定義・インターフェースが定義されているか（DBなし） |
| 6 | MCPツール仕様 | 各ツールの inputSchema・処理内容が明確か |
| 7 | 安全機構の要件 | allowlist・プライベートIPブロック等が明示されているか |
| 8 | テスト戦略 | カバレッジ目標・テスト種別が定義されているか |
| 9 | 配布方法 | npm publish・npx 起動の要件が明確か |
| 10 | 外部ツール連携 | gitleaks 等の外部ツールの扱いが明確か |

### 運用フロー

1. Agent が RDD.md を読み込む
2. 上記チェックリストと照合し、不足項目を洗い出す
3. 不足がある場合 → ユーザーに質問して情報を収集する
4. すべて揃ったら → 開発を開始する

---

## 4. プロジェクト生成手順

### ステップ1: プロジェクトルート作成

```bash
mkdir security-judge
cd security-judge
```

### ステップ2: MCPサーバーセットアップ

```bash
# package.json 初期化
npm init -y

# MCPフレームワーク・コアライブラリ
npm i @modelcontextprotocol/sdk@^1.29 undici p-limit

# tree-sitter + 言語別grammars（動的ロード対象）
npm i tree-sitter tree-sitter-java tree-sitter-python tree-sitter-go tree-sitter-ruby tree-sitter-javascript tree-sitter-typescript

# 開発ツール
npm i -D typescript @types/node vitest @vitest/coverage-v8 msw ts-node nodemon
```

#### tsconfig.json（NodeNext 必須）

```json
{
  "compilerOptions": {
    "target": "ES2022",
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "outDir": "./dist",
    "rootDir": "./src",
    "strict": true,
    "esModuleInterop": true,
    "skipLibCheck": true
  },
  "include": ["src/**/*"],
  "exclude": ["node_modules", "dist", "__tests__"]
}
```

#### package.json スクリプト追加

```json
{
  "name": "security-judge",
  "version": "1.0.0",
  "type": "module",
  "engines": { "node": ">=22" },
  "bin": { "security-judge": "./dist/index.js" },
  "main": "./dist/index.js",
  "files": ["dist/", "bin/"],
  "scripts": {
    "dev": "nodemon --exec ts-node src/index.ts",
    "build": "tsc",
    "start": "node dist/index.js",
    "test": "vitest run",
    "test:coverage": "vitest run --coverage",
    "postinstall": "node scripts/install-gitleaks.js"
  }
}
```

#### vitest.config.ts

```typescript
import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      thresholds: { lines: 80, branches: 80, functions: 80, statements: 80 },
    },
  },
})
```

#### gitleaks バイナリ自動取得（scripts/install-gitleaks.js）

`postinstall` で `bin/gitleaks` にバイナリを配置する。呼び出し時は `bin/gitleaks` のフルパスを使用し、グローバルインストールは行わない。

---

## 5. MCPサーバー実装

### エントリーポイント（src/index.ts）

RDD.md の MCPツール9本を `@modelcontextprotocol/sdk` の `Server` クラスに登録する。

```
src/
├── index.ts          # Server インスタンス生成・ツール登録・StdioServerTransport で起動
└── tools/            # 各ツールを個別ファイルで実装し、index.ts からインポート
```

### 主要実装パターン

RDD.md の各MCPツール仕様・inputSchema・フェーズ定義に基づいてツールを実装する。

`JudgeContext`（評価コンテキスト）はモジュールスコープで単一インスタンスとして保持し、ツール間で共有する。型定義は RDD.md の「データモデル」セクションに従う。

---

## 6. テスト実装

### テスト構成

RDD.md の「テスト戦略」セクションに完全準拠:

```
__tests__/
├── fixtures/
│   ├── vuln/          # ゴールデンサンプル（脆弱コード）
│   └── safe/          # ゴールデンサンプル（安全コード）
├── unit/              # rubric・payload_mutator・report・url_guard
└── integration/       # 各MCPツール（msw でHTTPモック）
```

`test/target-app/` に E2E 用の最小脆弱 Express サーバーを実装する。

---

## 7. 環境変数設定

```env
# なし（ユーザー環境の認証情報には依存しない）
# ターゲットURLはMCPツール呼び出し時の引数として受け取る
```

---

## 8. 必須検証手順（完成前に必ず実行）

### MCPサーバー起動確認

```bash
npm run build
node dist/index.js
# MCPサーバーが起動し、stdioで通信待機状態になること
```

### テスト・カバレッジ確認

```bash
npm test
npm run test:coverage
# vitest がパスし、カバレッジ 80% 以上であること
```

### npx 動作確認

```bash
npm pack
npx ./security-judge-1.0.0.tgz
# エラーなく起動すること
```

### Claude Code への MCP 登録確認

```json
// .claude/settings.json または settings.local.json に追記して動作確認
{
  "mcpServers": {
    "security-judge": {
      "command": "node",
      "args": ["<プロジェクトの絶対パス>/dist/index.js"]
    }
  }
}
```

---

## 9. 期待される成果物

```
security-judge/
├── src/                  # MCPサーバー実装（起動可能）
├── __tests__/            # ユニット・インテグレーションテスト（カバレッジ80%以上）
├── test/target-app/      # E2E用テスト脆弱アプリ
├── .claude/commands/     # カスタムコマンド定義
├── .github/workflows/    # CI（test → build → publish）
├── bin/                  # gitleaks バイナリ
├── package.json          # npm publishable な状態
├── tsconfig.json
├── vitest.config.ts
├── BUILDLOG.md
└── README.md             # セットアップ手順
```

---

## 10. DO / DON'T

**DO**
- RDD.md を最初に読み、要件を正確に把握する
- ローカルのみで完結するコマンドを使用
- ロックファイル（`package-lock.json`）をコミット
- 依存追加・スクリプト変更は `BUILDLOG.md` に都度記録
- エラーハンドリングを適切に実装
- TypeScriptの型定義を厳密に（`strict: true`）
- `module: NodeNext`・ESM を維持する（`@modelcontextprotocol/sdk` が ESM 前提）
- gitleaks は `bin/` にローカル配置し、フルパスで呼び出す

**DON'T**
- グローバルインストール（`-g`）や `sudo` の使用
- gitleaks のグローバルインストール（`postinstall` で `bin/` に配置する）
- ホーム配下や他プロジェクトの設定変更
- 秘密情報のコミット（`.env` の直コミット禁止）
- RDD.md に記載のない機能の過剰実装（MVPに集中）
- フロントエンド（React等）の実装
- データベース（PostgreSQL等）のセットアップ
- `module: commonjs` の使用（`@modelcontextprotocol/sdk` との非互換が生じる）

---

## 11. README.md の雛形（自動生成して配置）

````md
# security-judge

Claude Code の MCP ツールとして動作するセキュリティ評価エージェント。  
フロントエンドのUI制限を無視したAPIへの直接攻撃・静的解析・LLMジェイルブレイクを組み合わせ、最も厳格な基準でセキュリティ耐性を 0〜10点 で評価する。

> **免責事項**: 本ツールは authorized testing のみを対象としています。無許可の対象への使用は違法です。

## インストール・登録

### npx（推奨）

```json
// .claude/settings.json
{
  "mcpServers": {
    "security-judge": {
      "command": "npx",
      "args": ["-y", "security-judge@1.x"]
    }
  }
}
```

### ローカル開発

```bash
git clone <repo>
cd security-judge
npm install       # gitleaks が bin/ に自動配置される
npm run build
```

```json
// .claude/settings.json
{
  "mcpServers": {
    "security-judge": {
      "command": "node",
      "args": ["<絶対パス>/security-judge/dist/index.js"]
    }
  }
}
```

## 使い方

Claude Code のチャット画面で:

```
/security-judge_goal
```

評価フロー（フェーズ1〜4）が自律的に実行されます。

## 技術スタック

- Node.js 24 LTS / TypeScript 5.x（module: NodeNext）
- @modelcontextprotocol/sdk ^1.29
- undici（HTTP攻撃クライアント）
- tree-sitter（AST解析）
- gitleaks（シークレット検知、bin/ にローカル配置）
- vitest + msw（テスト）
````

---

## 12. トラブルシュート

- **MCPサーバーが起動しない**: `npm run build` 後に `node dist/index.js` で手動確認。tscエラーを先に解消する
- **gitleaks が見つからない**: `npm install` を再実行し、`bin/gitleaks` が存在するか確認
- **ESM関連エラー**: `tsconfig.json` の `module: NodeNext`・`package.json` の `"type": "module"` を確認
- **MCP接続エラー**: Claude Code の `.claude/settings.json` の `command`/`args` パスを確認
- **テストが通らない**: msw のモック設定・fixtures のサンプルコードを確認

---

**文書バージョン**: 3.0
**対応要件定義**: security-judge RDD.md v3.2
