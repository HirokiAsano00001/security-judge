import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { startTarget, type TargetHandle } from './helpers/target-server.js'
import { evaluate, formatScorecard, type Scorecard } from './helpers/scorecard.js'
import { type JudgeContext, type Finding } from '../../src/types/index.js'
import { assertAllowedUrl } from '../../src/safety/url_guard.js'
import { askTargetPersona } from '../../src/tools/ask_target_persona.js'
import { analyzeSastDeep } from '../../src/tools/analyze_sast_deep.js'
import { scanExposedEndpoints } from '../../src/tools/scan_exposed_endpoints.js'
import { checkSecurityHeaders } from '../../src/tools/check_security_headers.js'
import { testBolaIdor } from '../../src/tools/test_bola_idor.js'
import { testPrivilegeEscalation } from '../../src/tools/test_privilege_escalation.js'
import { testSsrf } from '../../src/tools/test_ssrf.js'
import { injectLlmJailbreak } from '../../src/tools/inject_llm_jailbreak.js'
import { fuzzApiDirect } from '../../src/tools/fuzz_api_direct.js'

const ATTACKER = 'user-token-alice'
const VICTIM = 'user-token-bob'

async function runAllTools(target: TargetHandle): Promise<{ ctx: JudgeContext; log: string[] }> {
  const ctx: JudgeContext = {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: '',
    allowedUrls: [],
    hasLlmChat: true,
    endpoints: [],
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
  const log: string[] = []
  const run = async (name: string, fn: () => Promise<string>): Promise<void> => {
    try {
      log.push(`--- ${name} ---\n${await fn()}`)
    } catch (err) {
      log.push(`--- ${name} ERRORED: ${(err as Error).message}`)
    }
  }

  askTargetPersona(
    { persona: 'commercial', targetBaseUrl: target.baseUrl, sourcePath: target.sourcePath, hasLlmChat: true },
    ctx,
  )

  await run('analyze_sast_deep', () => analyzeSastDeep({ sourcePath: target.sourcePath }, ctx))
  await run('scan_exposed_endpoints', () => scanExposedEndpoints({}, ctx))
  await run('check_security_headers', () => checkSecurityHeaders({}, ctx))
  await run('test_bola_idor', () =>
    testBolaIdor({ victimToken: VICTIM, attackerToken: ATTACKER, resourcePaths: ['/api/users/1'] }, ctx),
  )
  await run('test_privilege_escalation', () =>
    // Attack a NON-privileged user (id 1 = Alice, role 'user') so escalation is observable
    // against a non-admin baseline (avoids the already-admin false-positive).
    testPrivilegeEscalation({ endpoint: '/api/users/1/role', token: ATTACKER }, ctx),
  )
  await run('test_ssrf', () =>
    testSsrf({ endpoint: '/api/fetch', urlParam: 'url', token: ATTACKER }, ctx),
  )
  await run('inject_llm_jailbreak', () =>
    injectLlmJailbreak({ chatEndpoint: '/api/chat', messageField: 'message' }, ctx),
  )
  await run('fuzz_api_direct(/api/login)', () =>
    fuzzApiDirect(
      {
        endpoint: {
          method: 'POST',
          path: '/api/login',
          parameters: [
            { name: 'email', in: 'body', required: true, type: 'string' },
            { name: 'password', in: 'body', required: true, type: 'string' },
          ],
          authRequired: false,
          sourceLanguage: 'javascript',
        },
      },
      ctx,
    ),
  )

  return { ctx, log }
}

describe('E2E detection against target-app', () => {
  let target: TargetHandle
  let findings: Finding[]
  let scorecard: Scorecard
  let toolLog: string[]

  beforeAll(async () => {
    target = await startTarget()
    const { ctx, log } = await runAllTools(target)
    findings = ctx.findings
    toolLog = log
    scorecard = evaluate(findings)
    // Always surface the scorecard so iteration is observable.
    process.stderr.write(`\n${formatScorecard(scorecard)}\n`)
    const byTool = new Map<string, number>()
    for (const f of findings) byTool.set(`${f.toolName}/${f.severity}`, (byTool.get(`${f.toolName}/${f.severity}`) ?? 0) + 1)
    process.stderr.write(`Findings by tool/severity:\n${[...byTool.entries()].map(([k, v]) => `  ${k}: ${v}`).join('\n')}\n`)
  })

  afterAll(async () => {
    if (target) await target.stop()
  })

  it('url_guard permits the designated 127.0.0.1 target', () => {
    expect(() => assertAllowedUrl(`${target.baseUrl}/api/users/1`, [target.baseUrl])).not.toThrow()
  })

  it('url_guard blocks the userinfo→metadata bypass for this target', () => {
    const port = target.port
    expect(() =>
      assertAllowedUrl(`http://127.0.0.1:${port}@169.254.169.254/`, [target.baseUrl]),
    ).toThrow('[url_guard]')
  })

  it('reaches a detection score of at least 90/100', () => {
    if (scorecard.score < 90) {
      process.stderr.write(`\n=== TOOL LOG (score ${scorecard.score}) ===\n${toolLog.join('\n')}\n`)
    }
    expect(scorecard.score).toBeGreaterThanOrEqual(90)
  })
})

describe('E2E specificity against hardened secure-app', () => {
  let target: TargetHandle
  let scorecard: Scorecard
  let toolLog: string[]

  beforeAll(async () => {
    target = await startTarget('secure')
    const { ctx, log } = await runAllTools(target)
    toolLog = log
    scorecard = evaluate(ctx.findings)
    process.stderr.write(`\n[SECURE] ${formatScorecard(scorecard)}\n`)
  })

  afterAll(async () => {
    if (target) await target.stop()
  })

  it('does NOT false-positive on the hardened app (specificity)', () => {
    if (scorecard.score > 10) {
      process.stderr.write(`\n=== SECURE TOOL LOG (score ${scorecard.score}) ===\n${toolLog.join('\n')}\n`)
    }
    // A hardened app must trigger essentially no vulnerability detections.
    expect(scorecard.score).toBeLessThanOrEqual(10)
  })
})
