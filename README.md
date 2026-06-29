# security-judge

Claude Code の MCP ツールとして動作するセキュリティ評価エージェント。
フロントエンドのUI制限を無視したAPIへの直接攻撃・静的解析・LLMジェイルブレイクを組み合わせ、最も厳格な基準でセキュリティ耐性を **0〜10点** で評価する。

> **免責事項**: 本ツールは authorized testing（許可されたセキュリティテスト）のみを対象としています。無許可の対象への使用は違法です。Burp Suite / OWASP ZAP と同様のセキュリティ評価ツールです。

## 機能

- **9本のMCPツール**: SAST分析・ファジング・IDOR・JWT改ざん・SSRF・LLMジェイルブレイク等
- **エラー駆動変異器**: エラーレスポンスを分析して最大3回の知性的な再攻撃
- **ペルソナ別評価**: personal/team/internal/commercial の4段階
- **自動スコアリング**: 0〜10点評価（即時フェイル判定付き）
- **gitleaks統合**: シークレット検知（bin/ にローカル配置）

## インストール・登録

### npx（推奨）

```json
// ~/.claude/settings.json または .claude/settings.local.json
{
  "mcpServers": {
    "security-judge": {
      "command": "npx",
      "args": ["-y", "security-judge@1.x"]
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
修正案の提示には `/security-judge_remedy` を使います。

## MCPツール一覧

| ツール | 機能 | OWASP |
|-------|------|-------|
| `ask_target_persona` | ペルソナ・URL・ソースパス設定 | — |
| `analyze_sast_deep` | AST解析 + gitleaks シークレット検知 | A01, A02, C |
| `fuzz_api_direct` | API直接ファジング（エラー駆動変異器） | A01, A03, A |
| `test_bola_idor` | 横断的権限昇格（IDOR）テスト | A01, B |
| `inject_llm_jailbreak` | LLMガードレール突破テスト | D |
| `test_privilege_escalation` | 縦断的権限昇格テスト | A01, B |
| `test_jwt_tampering` | JWT改ざん攻撃（alg:none等） | A02 |
| `scan_exposed_endpoints` | 公開エンドポイントスキャン | A05, C |
| `test_ssrf` | SSRF脆弱性テスト | A10 |

## スコアリング

| ペルソナ | 減点係数 | 即時フェイル条件 |
|---------|---------|----------------|
| personal | 0.3 | なし |
| team | 0.5 | なし |
| internal | 0.8 | カテゴリB・C発火 |
| commercial | 1.0 | カテゴリA・B・C発火 |

スコア = `max(0, 10 - Σ(基礎減点 × 係数))`

## 技術スタック

- **Node.js 22+ / TypeScript 5.x** (`module: NodeNext`)
- **@modelcontextprotocol/sdk ^1.29**
- **undici** — HTTP攻撃クライアント
- **tree-sitter** — AST解析（動的ロード）
- **gitleaks** — シークレット検知（bin/ にローカル配置）
- **p-limit** — 並列数制御
- **vitest + msw** — テスト・HTTPモック

## 開発

```bash
npm install         # gitleaks 自動取得
npm test            # テスト実行
npm run test:coverage  # カバレッジ確認（80%以上必須）
npm run build       # TypeScriptビルド
npm run dev         # 開発モード
```

## トラブルシュート

- **MCPサーバーが起動しない**: `npm run build` 後に `node dist/index.js` で手動確認
- **gitleaks が見つからない**: `npm install` を再実行し `bin/gitleaks` の存在を確認
- **ESM関連エラー**: `tsconfig.json` の `module: NodeNext` と `package.json` の `"type": "module"` を確認
- **テストが失敗**: msw モック設定と fixtures のサンプルコードを確認
