import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { startTarget, type TargetHandle } from './helpers/target-server.js'
import { type JudgeContext, type Finding, type EndpointInfo } from '../../src/types/index.js'
import { fuzzApiDirect } from '../../src/tools/fuzz_api_direct.js'
import { testBolaIdor } from '../../src/tools/test_bola_idor.js'
import { testPrivilegeEscalation } from '../../src/tools/test_privilege_escalation.js'
import { testJwtTampering } from '../../src/tools/test_jwt_tampering.js'
import { testSsrf } from '../../src/tools/test_ssrf.js'
import { injectLlmJailbreak } from '../../src/tools/inject_llm_jailbreak.js'
import { testCors } from '../../src/tools/test_cors.js'
import { testSsti } from '../../src/tools/test_ssti.js'
import { testPathTraversal } from '../../src/tools/test_path_traversal.js'
import { checkSecurityHeaders } from '../../src/tools/check_security_headers.js'
import { scanExposedEndpoints } from '../../src/tools/scan_exposed_endpoints.js'
import { analyzeSastDeep } from '../../src/tools/analyze_sast_deep.js'
import { scanDependencies } from '../../src/tools/scan_dependencies.js'

function b64url(obj: unknown): string {
  return Buffer.from(JSON.stringify(obj)).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}
// A structurally valid JWT (signature is irrelevant — the lab never verifies it).
const VALID_JWT = `${b64url({ alg: 'HS256', typ: 'JWT' })}.${b64url({ sub: 1, role: 'user', exp: 4102444800 })}.sig`

let target: TargetHandle

function makeCtx(endpoints: EndpointInfo[] = []): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: target.baseUrl,
    allowedUrls: [target.baseUrl],
    hasLlmChat: true,
    endpoints,
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

function param(name: string, where: 'query' | 'body' = 'query'): EndpointInfo['parameters'][number] {
  return { name, in: where, required: false, type: 'string' }
}

beforeAll(async () => {
  target = await startTarget('lab')
})

afterAll(async () => {
  if (target) await target.stop()
})

describe('Per-vulnerability detection matrix (vuln-lab)', () => {
  it('fuzz_api_direct detects SQL injection (/sqli)', async () => {
    const ctx = makeCtx()
    await fuzzApiDirect({ endpoint: { method: 'GET', path: '/sqli', parameters: [param('q')], authRequired: false, sourceLanguage: 'javascript' } }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'fuzz_api_direct' && f.cweId === 'CWE-89')).toBe(true)
  })

  it('fuzz_api_direct detects reflected XSS (/xss)', async () => {
    const ctx = makeCtx()
    await fuzzApiDirect({ endpoint: { method: 'GET', path: '/xss', parameters: [param('q')], authRequired: false, sourceLanguage: 'javascript' } }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'fuzz_api_direct' && f.cweId === 'CWE-79')).toBe(true)
  })

  it('test_bola_idor detects IDOR (/api/docs/:id)', async () => {
    const ctx = makeCtx()
    await testBolaIdor({ attackerToken: 'attacker', resourcePaths: ['/api/docs/1'] }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_bola_idor')).toBe(true)
  })

  it('test_privilege_escalation detects role injection (/account/:id/role)', async () => {
    const ctx = makeCtx()
    await testPrivilegeEscalation({ endpoint: '/account/1/role', token: 'user' }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_privilege_escalation')).toBe(true)
  })

  it('test_jwt_tampering detects unverified JWT (/jwt/profile)', async () => {
    const ctx = makeCtx()
    await testJwtTampering({ token: VALID_JWT, endpoint: '/jwt/profile' }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_jwt_tampering')).toBe(true)
  })

  it('test_ssrf detects SSRF (/proxy)', async () => {
    const ctx = makeCtx()
    await testSsrf({ endpoint: '/proxy', urlParam: 'url' }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_ssrf')).toBe(true)
  })

  it('inject_llm_jailbreak detects system-prompt leak (/assistant)', async () => {
    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/assistant', messageField: 'message' }, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'inject_llm_jailbreak')).toBe(true)
  })

  it('test_cors detects credentialed origin reflection', async () => {
    const ctx = makeCtx()
    await testCors({}, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_cors')).toBe(true)
  })

  it('test_ssti detects template injection (/render)', async () => {
    const ctx = makeCtx([{ method: 'GET', path: '/render', parameters: [param('name')], authRequired: false, sourceLanguage: 'javascript' }])
    await testSsti({}, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_ssti')).toBe(true)
  })

  it('test_path_traversal detects LFI (/files)', async () => {
    const ctx = makeCtx([{ method: 'GET', path: '/files', parameters: [param('file')], authRequired: false, sourceLanguage: 'javascript' }])
    await testPathTraversal({}, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'test_path_traversal')).toBe(true)
  })

  it('check_security_headers flags missing headers', async () => {
    const ctx = makeCtx()
    await checkSecurityHeaders({}, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'check_security_headers')).toBe(true)
  })

  it('scan_exposed_endpoints finds exposed sensitive paths', async () => {
    const ctx = makeCtx()
    await scanExposedEndpoints({}, ctx)
    expect(ctx.findings.some((f: Finding) => f.toolName === 'scan_exposed_endpoints')).toBe(true)
  })

  it('analyze_sast_deep finds hardcoded secret and mass assignment in source', async () => {
    const ctx = makeCtx()
    await analyzeSastDeep({ sourcePath: target.sourcePath }, ctx)
    expect(ctx.findings.some((f: Finding) => f.cweId === 'CWE-798')).toBe(true)
    expect(ctx.findings.some((f: Finding) => f.cweId === 'CWE-915')).toBe(true)
  })

  it('scan_dependencies finds the vulnerable lodash dependency', async () => {
    const ctx = makeCtx()
    const result = await scanDependencies({ sourcePath: target.sourcePath }, ctx)
    // Hard assertion — no silent-pass path. npm audit runs against the local lockfile
    // and detects lodash@4.17.4's known advisories. (Requires network to the advisory DB.)
    const finding = ctx.findings.find((f: Finding) => f.toolName === 'scan_dependencies')
    expect(finding, `scan_dependencies produced no finding. Tool output:\n${result}`).toBeDefined()
    expect(/lodash/i.test(finding!.description)).toBe(true)
  })
})
