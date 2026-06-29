import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testJwtTampering } from '../../src/tools/test_jwt_tampering.js'
import { type JudgeContext } from '../../src/types/index.js'

function makeCtx(): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
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
  // Vulnerable: accepts any token (including alg:none)
  pool.intercept({ path: '/api/admin', method: 'GET' }).reply(200,
    JSON.stringify({ admin: true, data: 'secret-admin-data' }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

const SAMPLE_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4iLCJpYXQiOjE1MTYyMzkwMjJ9.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'

describe('testJwtTampering', () => {
  it('detects acceptance of tampered tokens (server accepts all)', async () => {
    const ctx = makeCtx()
    await testJwtTampering({ token: SAMPLE_TOKEN, endpoint: '/api/admin' }, ctx)
    expect(ctx.findings.length).toBeGreaterThan(0)
    const bCat = ctx.findings.find(f => f.category === 'B')
    expect(bCat).toBeDefined()
  })

  it('returns result summary', async () => {
    const ctx = makeCtx()
    const result = await testJwtTampering({ token: SAMPLE_TOKEN, endpoint: '/api/admin' }, ctx)
    expect(result).toContain('test_jwt_tampering')
  })

  it('handles invalid token (not 3 parts) — null attacks are skipped, only no-token runs', async () => {
    const ctx = makeCtx()
    const result = await testJwtTampering({ token: 'invalid-token-no-dots', endpoint: '/api/admin' }, ctx)
    expect(result).toBeDefined()
    // Only 'no token' attack runs (builders return null for non-3-part tokens, those are skipped)
    // Mock returns 200 for the no-token request → 1 finding
    expect(result).toContain('test_jwt_tampering')
  })
})
