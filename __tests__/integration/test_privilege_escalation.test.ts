import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testPrivilegeEscalation } from '../../src/tools/test_privilege_escalation.js'
import { type JudgeContext } from '../../src/types/index.js'

function makeCtx(): JudgeContext {
  return {
    persona: 'internal',
    penaltyMultiplier: 0.8,
    targetBaseUrl: 'http://test.example.com',
    allowedUrls: ['http://test.example.com'],
    hasLlmChat: false,
    endpoints: [],
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

let mockAgent: MockAgent
let originalDispatcher: Dispatcher

beforeEach(() => {
  originalDispatcher = getGlobalDispatcher()
  mockAgent = new MockAgent()
  mockAgent.disableNetConnect()
  setGlobalDispatcher(mockAgent)

  const pool = mockAgent.get('http://test.example.com')
  // Vulnerable but REALISTIC: a benign (baseline) body returns the user's real role;
  // only an escalation payload flips it to admin. This lets the differential oracle
  // distinguish a genuine escalation from an endpoint that merely echoes "admin".
  pool.intercept({ path: '/api/users/1/role', method: 'PUT' }).reply((opts) => {
    const raw = typeof opts.body === 'string' ? opts.body : ''
    const escalated = /"role"\s*:\s*"admin"|"isAdmin"\s*:\s*true|"admin"\s*:\s*(1|true)/.test(raw)
    return {
      statusCode: 200,
      data: JSON.stringify(escalated ? { success: true, role: 'admin', isAdmin: true } : { success: true, role: 'user' }),
      responseOptions: { headers: { 'content-type': 'application/json' } },
    }
  }).persist()

  // Hardened endpoint: always returns the user's real (non-admin) role regardless of payload.
  pool.intercept({ path: '/api/users/2/role', method: 'PUT' }).reply(200,
    JSON.stringify({ success: true, role: 'user' }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()

  // Endpoint that reports elevated state even for a benign baseline body — inconclusive.
  pool.intercept({ path: '/api/users/99/role', method: 'PUT' }).reply(200,
    JSON.stringify({ success: true, role: 'admin' }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('testPrivilegeEscalation', () => {
  it('detects privilege escalation via isAdmin=true', async () => {
    const ctx = makeCtx()
    await testPrivilegeEscalation({ endpoint: '/api/users/1/role', token: 'user-token' }, ctx)
    const finding = ctx.findings.find(f => f.category === 'B')
    expect(finding).toBeDefined()
  })

  it('emits exactly one finding per endpoint (no over-reporting)', async () => {
    const ctx = makeCtx()
    await testPrivilegeEscalation({ endpoint: '/api/users/1/role', token: 'user-token' }, ctx)
    expect(ctx.findings.filter(f => f.toolName === 'test_privilege_escalation')).toHaveLength(1)
  })

  it('no false positive when hardened endpoint never elevates', async () => {
    const ctx = makeCtx()
    await testPrivilegeEscalation({ endpoint: '/api/users/2/role', token: 'user-token' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('no false positive when baseline is already elevated (inconclusive)', async () => {
    const ctx = makeCtx()
    const result = await testPrivilegeEscalation({ endpoint: '/api/users/99/role', token: 'user-token' }, ctx)
    expect(ctx.findings).toHaveLength(0)
    expect(result).toContain('inconclusive')
  })

  it('returns summary string', async () => {
    const ctx = makeCtx()
    const result = await testPrivilegeEscalation({ endpoint: '/api/users/1/role', token: 'user-token' }, ctx)
    expect(result).toContain('test_privilege_escalation')
  })

  it('no finding when 200 response has no admin indicators', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/profile', method: 'PUT' }).reply(200,
      JSON.stringify({ success: true, name: 'regularuser' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await testPrivilegeEscalation({ endpoint: '/api/profile', token: 'user-token' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('handles non-JSON 200 response without throwing', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/text-endpoint', method: 'PUT' }).reply(200, 'OK plain text').persist()

    const ctx = makeCtx()
    const result = await testPrivilegeEscalation({ endpoint: '/api/text-endpoint', token: 'user-token' }, ctx)
    expect(result).toBeDefined()
    expect(ctx.findings).toHaveLength(0)
  })

  it('handles url_guard block via continue (allowedUrls empty)', async () => {
    const ctx = makeCtx()
    ctx.allowedUrls = []
    const result = await testPrivilegeEscalation({ endpoint: '/api/users/1/role', token: 'token' }, ctx)
    expect(result).toContain('test_privilege_escalation')
    expect(ctx.findings).toHaveLength(0)
  })
})
