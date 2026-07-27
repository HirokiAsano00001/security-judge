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
| `analyze_sast_semgrep` | A01–A08 | Semgrep-backed deep SAST: thousands of registry rules across languages, with taint / data-flow tracking (source → sink). Runs via a native `semgrep` install or the `semgrep/semgrep` Docker image; skips gracefully if neither is present. CWE/OWASP are read from Semgrep rule metadata. |
| `analyze_taint` | A01/A03 | **Built-in** taint / data-flow SAST for TS/JS — no external tools, fully offline. Uses the TypeScript Compiler API to track user input (`req.query/body/params/…`) from source to a dangerous sink (SQLi, RCE, XSS, path traversal, open redirect, SSTI) within a file. Confirmed source→sink flows are CRITICAL with a data-flow trace. Zero-dependency confident SAST when Semgrep is unavailable. |
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
5. analyze_sast_deep       →  regex SAST + secret detection from source
   analyze_taint           →  built-in TS/JS taint analysis (offline, zero-dependency)
   analyze_sast_semgrep    →  deep SAST (Semgrep taint / data-flow, multi-language)
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

## SAST: built-in taint engine (`analyze_taint`)

`analyze_taint` is a **zero-dependency, offline** taint analyzer for TS/JS. It parses
source with the TypeScript Compiler API (no tsconfig, no network, no Docker) and tracks
attacker-controlled input from a **source** to a dangerous **sink** within a single file:

- **Sources**: `req.query/body/params/headers/cookies`, `request.*`, `ctx.request.body`,
  `process.argv`, `location.search/hash`. (`process.env` is trusted config, not a source.)
- **Sinks**: SQLi (`db.query`/`execute`/`raw`), RCE (`eval`/`Function`/`child_process.exec`),
  XSS (`innerHTML`/`document.write`/`res.send`), path traversal (`fs.readFile*`/`sendFile`),
  open redirect (`res.redirect`/`location.href`), SSTI (`ejs`/`pug`/`handlebars` render).
- **Propagation**: variable assignments, string concatenation, template literals, aliasing
  (`const q = req.query`), and pass-through string methods. **Sanitizers** (`parseInt`,
  `Number`, `encodeURIComponent`, `escape`/`sanitize`-named helpers) and parameterized
  queries (`db.query(sql, [param])`) remove taint to avoid false positives.
- A confirmed flow is reported **CRITICAL** with evidence `Data-flow: source@L → N hop(s) → sink@L`.

**Scope & limits (by design):** TS/JS only; **single file, intra-procedural** — no
cross-file / cross-function taint, no tracking through user-defined function return values
or object fields; destructuring (`const { id } = req.query`) is a known gap. It is a
high-confidence CRITICAL-only engine, not a full replacement for Semgrep Pro's inter-file
analysis. Use it as the always-available confident SAST; use `analyze_sast_semgrep` for
broad multi-language coverage.

## SAST: Semgrep (deep engine)

`analyze_sast_semgrep` wraps [Semgrep](https://semgrep.dev) to add SonarQube-class
static analysis: thousands of community rules across many languages, taint-mode rules
that track user input from a source to a dangerous sink, and CWE/OWASP metadata read
straight from each rule.

- **Execution** (first available wins): a native `semgrep` on `PATH`, then the
  `semgrep/semgrep` Docker image. If neither exists the tool reports it and skips —
  it never fails the run. `postinstall` attempts a `pipx`/`pip` install and otherwise
  prints setup guidance.
- **Rulesets** — defaults to `--config auto` (registry-selected rules; needs network).
  Pass `config` to use a pack such as `p/security-audit` / `p/owasp-top-ten`, or a local
  rule path.
- **Severity** — mapped from Semgrep's own severity (`ERROR`→HIGH, `WARNING`→MEDIUM,
  `INFO`→LOW). A finding that carries a data-flow trace (`dataflow_trace`) is elevated to
  **CRITICAL** and labelled *Taint-confirmed*, with a `source → hops → sink` line in the
  evidence.
- **Data-flow traces** — the exported `dataflow_trace` is produced by Semgrep's **Pro
  engine**. The OSS engine still runs taint-mode rules (reported at their declared
  severity) but does not export the trace, so taint findings appear as HIGH rather than
  CRITICAL on OSS.

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
