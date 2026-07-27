import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { type JudgeContext } from './types/index.js'
import { askTargetPersona, ASK_TARGET_PERSONA_SCHEMA } from './tools/ask_target_persona.js'
import { analyzeSastDeep, ANALYZE_SAST_DEEP_SCHEMA } from './tools/analyze_sast_deep.js'
import { analyzeSastSemgrep } from './tools/analyze_sast_semgrep.js'
import { fuzzApiDirect, FUZZ_API_DIRECT_SCHEMA } from './tools/fuzz_api_direct.js'
import { testBolaIdor, TEST_BOLA_IDOR_SCHEMA } from './tools/test_bola_idor.js'
import { testPrivilegeEscalation, TEST_PRIVILEGE_ESCALATION_SCHEMA } from './tools/test_privilege_escalation.js'
import { testJwtTampering, TEST_JWT_TAMPERING_SCHEMA } from './tools/test_jwt_tampering.js'
import { scanExposedEndpoints, SCAN_EXPOSED_ENDPOINTS_SCHEMA } from './tools/scan_exposed_endpoints.js'
import { testSsrf, TEST_SSRF_SCHEMA } from './tools/test_ssrf.js'
import { injectLlmJailbreak, INJECT_LLM_JAILBREAK_SCHEMA } from './tools/inject_llm_jailbreak.js'
import { runAdaptivePentest, RUN_ADAPTIVE_PENTEST_SCHEMA } from './tools/run_adaptive_pentest.js'
import { planPentest, PLAN_PENTEST_SCHEMA, investigateArea, INVESTIGATE_AREA_SCHEMA } from './tools/run_multi_agent_pentest.js'
import { checkSecurityHeaders, CHECK_SECURITY_HEADERS_SCHEMA } from './tools/check_security_headers.js'
import { testCors, TEST_CORS_SCHEMA } from './tools/test_cors.js'
import { testSsti, TEST_SSTI_SCHEMA } from './tools/test_ssti.js'
import { testPathTraversal, TEST_PATH_TRAVERSAL_SCHEMA } from './tools/test_path_traversal.js'
import { scanDependencies, SCAN_DEPENDENCIES_SCHEMA } from './tools/scan_dependencies.js'
import { loginAndCapture, LOGIN_AND_CAPTURE_SCHEMA } from './tools/login_and_capture.js'
import { crawlTarget } from './recon/crawler.js'
import { buildReport, formatReport } from './reporter/report.js'
import { calculateScore } from './scorer/rubric.js'

const ctx: JudgeContext = {
  persona: 'personal',
  penaltyMultiplier: 0.3,
  targetBaseUrl: '',
  allowedUrls: [],
  hasLlmChat: false,
  endpoints: [],
  findings: [],
  extractedArtifacts: [],
  score: 10,
}

const server = new McpServer({
  name: 'security-judge',
  version: '1.0.0',
})

server.tool(
  'ask_target_persona',
  'Set up evaluation target: persona, base URL, source path, and LLM chat presence. Run this first.',
  {
    persona: z.enum(['personal', 'team', 'internal', 'commercial']),
    targetBaseUrl: z.string().url(),
    sourcePath: z.string().optional(),
    hasLlmChat: z.boolean(),
  },
  async (input) => {
    const result = askTargetPersona(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'analyze_sast_deep',
  'SAST analysis: regex-based routing extraction + gitleaks secret detection + 30 dangerous pattern checks (SQLi, XSS, RCE, SSTI, deserialization, weak crypto, etc.).',
  {
    sourcePath: z.string(),
  },
  async (input) => {
    const result = await analyzeSastDeep(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'analyze_sast_semgrep',
  'Deep SAST via Semgrep: taint / data-flow analysis (tracks user input from source to a dangerous sink) plus thousands of registry rules across languages. Complements analyze_sast_deep — taint-confirmed source→sink flows are reported as CRITICAL. Uses a native `semgrep` install or the Docker image; skips gracefully if neither is present.',
  {
    sourcePath: z.string(),
    config: z.string().optional(),
    timeoutMs: z.number().int().positive().optional(),
  },
  async (input) => {
    const result = await analyzeSastSemgrep(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'fuzz_api_direct',
  'Fuzz an API endpoint with SQLi, XSS, and boundary payloads. Uses oracle-based detection (DB error signatures, XSS reflection, stack trace analysis) with boolean-diff SQLi confirmation.',
  {
    endpoint: z.object({
      method: z.string(),
      path: z.string(),
      parameters: z.array(z.object({
        name: z.string(),
        in: z.enum(['body', 'query', 'path', 'header']),
        required: z.boolean(),
        type: z.string(),
      })).default([]),
      authRequired: z.boolean().default(false),
      sourceLanguage: z.string().default('unknown'),
    }),
    authToken: z.string().optional(),
  },
  async (input) => {
    const result = await fuzzApiDirect(input as Parameters<typeof fuzzApiDirect>[0], ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_bola_idor',
  'Test BOLA/IDOR: access resources using alternate user IDs with attacker token. Provide victimToken for confirmed CRITICAL finding; without it reports HIGH (unconfirmed).',
  {
    victimToken: z.string().optional(),
    attackerToken: z.string(),
    resourcePaths: z.array(z.string()),
  },
  async (input) => {
    const result = await testBolaIdor(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_privilege_escalation',
  'Test vertical privilege escalation: isAdmin=true, role=admin parameter injection.',
  {
    endpoint: z.string(),
    token: z.string(),
  },
  async (input) => {
    const result = await testPrivilegeEscalation(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_jwt_tampering',
  'Test JWT attacks: alg:none, RS256→HS256 confusion, expired token acceptance, admin role injection.',
  {
    token: z.string(),
    endpoint: z.string(),
  },
  async (input) => {
    const result = await testJwtTampering(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'scan_exposed_endpoints',
  'Wordlist scan for exposed endpoints: Actuator, Swagger, .env, debug, admin paths. Filters SPA soft-404s.',
  {},
  async () => {
    const result = await scanExposedEndpoints({}, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_ssrf',
  'Test SSRF: inject cloud metadata IPs into URL parameters. Only runs for internal/commercial personas.',
  {
    endpoint: z.string(),
    urlParam: z.string(),
    token: z.string().optional(),
  },
  async (input) => {
    const result = await testSsrf(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'inject_llm_jailbreak',
  'Test LLM guardrail bypass: system prompt extraction, DAN prompts, XML injection.',
  {
    chatEndpoint: z.string(),
    messageField: z.string().default('message'),
    token: z.string().optional(),
  },
  async (input) => {
    const result = await injectLlmJailbreak(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'check_security_headers',
  'Check HTTP security headers: HSTS, CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy. Flags info-leak headers and CORS wildcard+credentials.',
  {},
  async () => {
    const result = await checkSecurityHeaders({}, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_cors',
  'Test CORS misconfiguration: evil-origin reflection, null-origin, suffix-bypass. Detects credentialed cross-origin requests.',
  {
    authToken: z.string().optional(),
  },
  async (input) => {
    const result = await testCors(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_ssti',
  'Test Server-Side Template Injection: {{7*7}}, ${7*7}, #{7*7} and other math-eval payloads. Confirms reflection first, then probes for SSTI.',
  {
    authToken: z.string().optional(),
  },
  async (input) => {
    const result = await testSsti(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'test_path_traversal',
  'Test path traversal / LFI: inject ../../etc/passwd and variants into file/path/template parameters. Uses oracle signature check for confirmation.',
  {
    authToken: z.string().optional(),
  },
  async (input) => {
    const result = await testPathTraversal(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'scan_dependencies',
  'Scan npm dependencies for known vulnerabilities using npm audit. Requires package-lock.json in sourcePath.',
  {
    sourcePath: z.string(),
  },
  async (input) => {
    const result = await scanDependencies(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'login_and_capture',
  'Login with credentials and capture session cookies. Automatically extracts CSRF tokens from login page HTML. Stores cookies in ctx for subsequent tool calls.',
  {
    loginUrl: z.string(),
    username: z.string(),
    password: z.string(),
    usernameField: z.string().optional(),
    passwordField: z.string().optional(),
    submitAsJson: z.boolean().optional(),
  },
  async (input) => {
    const result = await loginAndCapture(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'crawl_target',
  'BFS crawl the target site to discover links and form endpoints. Adds discovered endpoints to ctx for subsequent attack tools.',
  {
    maxDepth: z.number().int().min(1).max(3).optional(),
    maxUrls: z.number().int().min(1).max(100).optional(),
  },
  async (input) => {
    const result = await crawlTarget(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'plan_pentest',
  [
    'Discovery phase for multi-agent pentest. Runs endpoint scan, OpenAPI fetch, and optional SAST.',
    'Returns a JSON plan with investigation missions for Claude Code to orchestrate.',
    'USAGE: Call this first, then spawn parallel agents each calling investigate_area for each mission.',
    'Missions with dangerScore >= 6 should be deep-investigated with a second investigate_area call.',
  ].join(' '),
  {
    sourcePath: z.string().optional(),
    numMissions: z.number().int().min(1).max(10).default(10).optional(),
  },
  async (input) => {
    const result = await planPentest(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'investigate_area',
  [
    'Scout investigation for one security focus area. Called by parallel agents after plan_pentest.',
    'Returns JSON with findings and dangerScore (0-10). Score >= 6 indicates high risk.',
    'dangerScore is computed as: CRITICAL=3pts, HIGH=2pts, MEDIUM=1pt, isFail=10 (instant).',
  ].join(' '),
  {
    focusArea: z.string(),
    targetPaths: z.array(z.string()),
    attackTypes: z.array(z.enum(['fuzz', 'idor', 'privesc', 'jwt', 'ssrf', 'jailbreak'])),
    authToken: z.string().optional(),
  },
  async (input) => {
    const result = await investigateArea(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'run_adaptive_pentest',
  'Autonomous adaptive pentest loop: discovers endpoints (Round 1), then iteratively selects and runs targeted attacks (fuzz/BOLA/SSRF/JWT/privesc/jailbreak) based on what is found. Stops when no new findings or maxRounds reached.',
  {
    maxRounds: z.number().int().min(1).max(5).default(3).optional(),
    authToken: z.string().optional(),
    sourcePath: z.string().optional(),
  },
  async (input) => {
    const result = await runAdaptivePentest(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'get_report',
  'Generate final security report with score and all findings.',
  {},
  async () => {
    const scoreResult = calculateScore(ctx.findings, ctx.persona)
    ctx.score = scoreResult.score

    const report = buildReport(ctx)
    const formatted = formatReport(report)

    return { content: [{ type: 'text', text: formatted }] }
  }
)

async function main() {
  const transport = new StdioServerTransport()
  await server.connect(transport)
  process.stderr.write('security-judge MCP server running on stdio\n')
}

main().catch(err => {
  process.stderr.write(`Fatal error: ${err}\n`)
  process.exit(1)
})
