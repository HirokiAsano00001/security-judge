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
| `analyze_sast_deep` | A03/A06 | Regex SAST with 30+ dangerous patterns + gitleaks secret detection |
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
| `test_ssrf` | A10 | SSRF: inject cloud metadata IPs into URL parameters |
| `inject_llm_jailbreak` | — | LLM guardrail bypass: DAN prompts, XML injection, extraction |

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

Supported: Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64)

## License

MIT
