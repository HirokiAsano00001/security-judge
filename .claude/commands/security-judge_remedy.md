# /security-judge_remedy

`get_report` で検出された脆弱性に対する修正案（Before/After）を提示します。

## 実行手順

1. `get_report` が生成したレポートを読み込みます
2. 各 Finding のカテゴリ・説明・エビデンスを分析します
3. 以下の修正案テンプレートに基づき、具体的なコード例を提示します

## カテゴリ別修正テンプレート

### カテゴリ A: バックエンド検証欠落
```diff
- // No server-side validation
- app.post('/api/data', (req, res) => {
-   db.insert(req.body);  // dangerous: no validation
- });

+ // With validation
+ import { z } from 'zod';
+ const schema = z.object({ name: z.string().max(100), age: z.number().int().min(0).max(150) });
+ app.post('/api/data', (req, res) => {
+   const data = schema.parse(req.body);
+   db.insert(data);
+ });
```

### カテゴリ B: 認可制御欠落（BOLA/IDOR・権限昇格）
```diff
- // No ownership check
- app.get('/api/users/:id', (req, res) => {
-   return db.findUser(req.params.id);
- });

+ // With ownership check
+ app.get('/api/users/:id', requireAuth, (req, res) => {
+   if (req.user.id !== req.params.id && !req.user.isAdmin) {
+     return res.status(403).json({ error: 'Forbidden' });
+   }
+   return db.findUser(req.params.id);
+ });
```

### カテゴリ C: 情報漏洩（シークレット・スタックトレース）
```diff
- const API_KEY = 'sk-live-abc123';  // hardcoded

+ const API_KEY = process.env.API_KEY;
+ if (!API_KEY) throw new Error('API_KEY required');

- res.status(500).json({ error: err.message, stack: err.stack });
+ res.status(500).json({ error: 'Internal server error' });
+ logger.error({ err }, 'Unhandled error');
```

### カテゴリ D: LLMガードレール突破
```diff
- // Naive check
- if (message.includes('system prompt')) { reply = SYSTEM_PROMPT; }

+ // Input sanitization + output filter
+ const sanitized = message.replace(/<[^>]+>/g, '');
+ const reply = await llm.chat(sanitized);
+ if (systemPromptKeywords.some(k => reply.includes(k))) {
+   return res.json({ reply: 'I cannot help with that.' });
+ }
```

## 使用例

```
/security-judge_remedy
```

事前に `/security-judge_goal` を実行してレポートを生成してください。
