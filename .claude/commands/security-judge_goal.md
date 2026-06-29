# /security-judge_goal

セキュリティ評価フロー（フェーズ1〜4）を自律的に実行します。

## 実行手順

以下のステップを順番に実行してください：

### フェーズ1: ターゲット設定
`ask_target_persona` ツールを呼び出して評価コンテキストを設定します。
- ペルソナ（personal/team/internal/commercial）
- ターゲットURL
- ソースコードパス（任意）
- LLMチャット機能の有無

### フェーズ2: 情報収集
以下を並列実行します：
- `analyze_sast_deep`（ソースコードパスが指定された場合）
- `scan_exposed_endpoints`

### フェーズ3: 攻撃実行
フェーズ2の結果に基づき、以下を実行します：

**並列グループA（独立攻撃）:**
- `fuzz_api_direct`（検出された各エンドポイントに対して）
- `test_jwt_tampering`（認証エンドポイントが見つかった場合）

**直列グループB（情報依存攻撃）:**
- `test_bola_idor`
- `test_privilege_escalation`
- `test_ssrf`（internal/commercial ペルソナのみ）
- `inject_llm_jailbreak`（hasLlmChat=true の場合）

### フェーズ4: スコアリング・レポート
`get_report` ツールを呼び出して最終レポートを生成します。

## 使用例

```
/security-judge_goal
```

プロンプトが表示されたら、ターゲット情報を入力してください。
