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
  // Vulnerable: accepts isAdmin/role escalation
  pool.intercept({ path: '/api/users/1/role', method: 'PUT' }).reply(200,
    JSON.stringify({ success: true, role: 'admin', isAdmin: true }),
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
})
