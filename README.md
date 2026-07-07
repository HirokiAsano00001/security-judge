# security-judge

Claude Code MCP server for autonomous security testing of web applications.

Runs SAST, fuzzing, BOLA/IDOR, JWT, SSRF, CORS, SSTI, path traversal, dependency auditing, and more against a target. Designed to work with Claude Code's native multi-agent orchestration — no separate API key required.

## Requirements

- Node.js >= 22
- Claude Code (claude.ai/code or CLI)

## Installation

```bash
# Run directly without installing
npx security-judge

# Or install globally
npm install -g security-judge
```

Then add to your Claude Code MCP config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "security-judge": {
      "command": "npx",
      "args": ["-y", "security-judge"]
    }
  }
}
```

## Tools

### Recon & Setup

| Tool | OWASP | Description |
|------|-------|-------------|
| `ask_target_persona` | — | Set target URL, persona, and options. **Run this first.** |
| `login_and_capture` | A07 | POST credentials, capture session cookies and CSRF tokens |
| `crawl_target` | — | BFS crawler: discover endpoints from HTML links and forms |

### Static Analysis

| Tool | OWASP | Description |
|------|-------|-------------|
| `analyze_sast_deep` | A02/A03/A08 | Regex SAST (30+ dangerous patterns) + hardcoded-secret and mass-assignment (`Object.assign(x, req.body)`) detection. gitleaks is used when present; a regex fallback still catches hardcoded secrets without it. |
| `scan_dependencies` | A06 | `npm audit` integration: find known vulnerable dependencies |

### Dynamic Testing

| Tool | OWASP | Description |
|------|-------|-------------|
| `scan_exposed_endpoints` | A05 | Wordlist scan for admin, Swagger, .env, Actuator paths |
| `check_security_headers` | A05 | Verify HSTS, CSP, CORS, X-Frame-Options, info-leak headers |
| `fuzz_api_direct` | A03 | Fuzz with SQL injection (oracle-confirmed) and XSS payloads |
| `test_cors` | A01 | CORS misconfiguration: evil origin, null origin, suffix bypass |
| `test_ssti` | A03 | Server-side template injection: probe + math evaluation |
| `test_path_traversal` | A01 | Path traversal with 11 payloads including double-encoding |
| `test_bola_idor` | A01 | BOLA/IDOR: cross-user resource access with attacker token |
| `test_privilege_escalation` | A01 | Vertical privilege escalation via parameter injection |
| `test_jwt_tampering` | A07 | JWT attacks: alg:none, RS256→HS256, role injection |
| `test_ssrf` | A10 | SSRF: inject cloud-metadata/internal IPs. Confirms via metadata leakage **or** a server-side connection attempt (missing egress filter). |
| `inject_llm_jailbreak` | LLM01 | LLM guardrail bypass: DAN prompts, XML injection, system-prompt extraction. Strips echoed payloads to avoid parroting false positives. |

### Orchestration

| Tool | Description |
|------|-------------|
| `run_adaptive_pentest` | Autonomous loop: discovers endpoints → selects attacks → repeats |
| `plan_pentest` | Multi-agent planning: discovery + mission generation |
| `investigate_area` | Scout: runs targeted attacks and returns danger score (0–10) |
| `get_report` | Final security report with score and all findings |

## Basic Usage

```
1. ask_target_persona      →  set target URL and persona
2. login_and_capture       →  authenticate and capture session (if login required)
3. crawl_target            →  discover endpoints from HTML
4. scan_exposed_endpoints  →  wordlist scan for exposed paths
5. analyze_sast_deep       →  SAST + secret detection from source
6. scan_dependencies       →  npm audit for vulnerable dependencies
7. check_security_headers  →  verify security response headers
8. test_cors               →  CORS misconfiguration check
9. fuzz_api_direct / test_bola_idor / test_ssti / test_path_traversal / ...
10. get_report             →  score and findings summary
```

### Persona types

| Persona | Severity multiplier | Use case |
|---------|---------------------|----------|
| `personal` | 0.3× | Personal project, low-stakes |
| `team` | 0.5× | Internal team service |
| `internal` | 0.8× | Company-internal system |
| `commercial` | 1.0× | Customer-facing product |

## Multi-Agent Pentest

Uses Claude Code's native Agent orchestration — no API key needed.
Claude Code acts as the Opus orchestrator; each `investigate_area` call is a Sonnet scout.

```
1. plan_pentest
   → Returns JSON plan with up to 10 investigation missions

2. [Claude Code spawns parallel agents, each calling investigate_area]
   → Each returns findings + dangerScore (0–10)

3. For missions with dangerScore >= 6:
   → Call investigate_area again with broader scope

4. get_report
   → Consolidated report with all findings
```

Example prompt to Claude Code:

```
Run a multi-agent security test on http://localhost:8080.
Source code is at /path/to/project. Auth token is Bearer eyJ...

Steps:
1. ask_target_persona (persona=commercial, hasLlmChat=false)
2. plan_pentest (sourcePath=/path/to/project)
3. Run each mission from the plan in parallel using the Agent tool
4. Deep-dive any mission with dangerScore >= 6
5. get_report
```

## Adaptive Pentest

Rule-based autonomous loop. No Claude coordination needed.

```
run_adaptive_pentest (maxRounds=3, authToken=Bearer eyJ...)
```

- Round 1: Discovery (endpoint scan + OpenAPI + SAST)
- Round 2+: Identifies attack vectors from discovered endpoints and runs them
- Stops when no new findings or `maxRounds` reached (max: 5)

## SAST: gitleaks

On first install, `gitleaks` is automatically downloaded for your platform.
It detects hardcoded secrets (API keys, passwords, tokens) in source code.
Even without gitleaks, a regex fallback still flags hardcoded secrets.

Supported: Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64)

## Safety & threat model

security-judge is a **local CLI tool**: the operator running it is the owner of
the target being tested. Its outbound requests are gated by `url_guard`:

- **Only the designated target is reachable.** Requests are allowed only when the
  URL's `protocol://host:port` exactly matches the target set via `ask_target_persona`
  (parsed match — not string prefix — so `http://127.0.0.1:3000@evil/` and
  `http://target.evil.com/` are blocked).
- **Local / private targets are supported.** `127.0.0.1`, `192.168.x`, `10.x`, etc.
  are testable when they are the designated target (intended use: local/internal apps).
- **Cloud-metadata endpoints are permanently blocked** (169.254.169.254 and friends),
  even if named as the target, so the tool can never be turned into an SSRF pivot.
  Obfuscated forms (decimal/hex/octal/IPv4-in-IPv6) are normalized before the check.

> SSRF *payloads* (metadata IPs sent as request-body values to the target) are data
> for the target to mishandle — they never become requests that security-judge itself sends.

## Testing

```bash
npm test           # unit + integration (mock-based)
npm run test:e2e   # end-to-end against spawned Express apps
npm run test:coverage
```

The E2E suite spawns real apps and measures detection, not just mocks:

- **Sensitivity** — a deliberately vulnerable app (`test/target-app`) must be fully
  detected (score 100/100).
- **Specificity** — a hardened twin (`test/secure-app`) must trigger no detections
  (0/100), so a "flag-everything" regression is caught.
- **Per-tool matrix** — `test/vuln-lab` exposes one vulnerable endpoint per tool;
  each detection tool is asserted to fire on a live target (`vuln-matrix.e2e.test.ts`).

## License

MIT
