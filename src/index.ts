import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { type JudgeContext } from './types/index.js'
import { askTargetPersona, ASK_TARGET_PERSONA_SCHEMA } from './tools/ask_target_persona.js'
import { analyzeSastDeep, ANALYZE_SAST_DEEP_SCHEMA } from './tools/analyze_sast_deep.js'
import { fuzzApiDirect, FUZZ_API_DIRECT_SCHEMA } from './tools/fuzz_api_direct.js'
import { testBolaIdor, TEST_BOLA_IDOR_SCHEMA } from './tools/test_bola_idor.js'
import { testPrivilegeEscalation, TEST_PRIVILEGE_ESCALATION_SCHEMA } from './tools/test_privilege_escalation.js'
import { testJwtTampering, TEST_JWT_TAMPERING_SCHEMA } from './tools/test_jwt_tampering.js'
import { scanExposedEndpoints, SCAN_EXPOSED_ENDPOINTS_SCHEMA } from './tools/scan_exposed_endpoints.js'
import { testSsrf, TEST_SSRF_SCHEMA } from './tools/test_ssrf.js'
import { injectLlmJailbreak, INJECT_LLM_JAILBREAK_SCHEMA } from './tools/inject_llm_jailbreak.js'
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
  'Run SAST analysis: tree-sitter AST scan + gitleaks secret detection. Extracts endpoints from source code.',
  {
    sourcePath: z.string(),
  },
  async (input) => {
    const result = await analyzeSastDeep(input, ctx)
    return { content: [{ type: 'text', text: result }] }
  }
)

server.tool(
  'fuzz_api_direct',
  'Fuzz a specific API endpoint with boundary values, SQLi, XSS payloads. Uses error-driven mutation (max 3 rounds).',
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
  'Test BOLA/IDOR: access resources using alternate user IDs with attacker token.',
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
  'Wordlist scan for exposed endpoints: Actuator, Swagger, .env, debug, admin paths.',
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
