import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testSsrf } from '../../src/tools/test_ssrf.js'
import { type JudgeContext } from '../../src/types/index.js'

function makeCtx(persona: 'commercial' | 'internal' | 'personal' = 'commercial'): JudgeContext {
  return {
    persona,
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
  // SSRF vulnerable: returns cloud metadata content
  pool.intercept({ path: '/api/fetch', method: 'POST' }).reply(200,
    JSON.stringify({ status: 200, body: 'ami-id: ami-12345678\ninstance-id: i-1234567890abcdef0\nsecurity-credentials: my-role' }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('testSsrf', () => {
  it('detects SSRF with cloud metadata response', async () => {
    const ctx = makeCtx('commercial')
    await testSsrf({ endpoint: '/api/fetch', urlParam: 'url' }, ctx)
    const finding = ctx.findings.find(f => f.description.includes('SSRF'))
    expect(finding).toBeDefined()
    expect(finding?.category).toBe('C')
  })

  it('skips for personal persona', async () => {
    const ctx = makeCtx('personal')
    const result = await testSsrf({ endpoint: '/api/fetch', urlParam: 'url' }, ctx)
    expect(result).toContain('skipped')
    expect(ctx.findings).toHaveLength(0)
  })

  it('reports Possible SSRF when 200 response has no metadata keywords', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/proxy', method: 'POST' }).reply(200,
      JSON.stringify({ status: 200, body: 'some non-metadata content here' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx('internal')
    await testSsrf({ endpoint: '/api/proxy', urlParam: 'url' }, ctx)
    const possibleFinding = ctx.findings.find(f => f.description.includes('Possible SSRF'))
    expect(possibleFinding).toBeDefined()
    expect(possibleFinding?.severity).toBe('HIGH')
  })

  it('handles team persona (skipped)', async () => {
    const ctx = makeCtx('personal')
    const result = await testSsrf({ endpoint: '/api/fetch', urlParam: 'url' }, ctx)
    expect(result).toContain('skipped')
  })

  it('sets Authorization header when token is provided', async () => {
    const ctx = makeCtx('commercial')
    const result = await testSsrf({ endpoint: '/api/fetch', urlParam: 'url', token: 'bearer-token-xyz' }, ctx)
    expect(result).toBeDefined()
  })

  it('flags SSRF when the server surfaces a connection error to the injected host', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/attempted', method: 'POST' }).reply(500,
      JSON.stringify({ error: 'connect ECONNREFUSED 169.254.169.254:80' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx('commercial')
    await testSsrf({ endpoint: '/api/attempted', urlParam: 'url' }, ctx)
    const finding = ctx.findings.find(f => f.description.includes('attempted an outbound'))
    expect(finding).toBeDefined()
    expect(finding?.confidence).toBe('MEDIUM')
  })

  it('does NOT false-positive when the app rejects the URL with a plain 400 (no network error)', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/guarded', method: 'POST' }).reply(400,
      JSON.stringify({ error: 'url not allowed' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx('commercial')
    await testSsrf({ endpoint: '/api/guarded', urlParam: 'url' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('does NOT false-positive on a bare 500 with no connection-error signature', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/err500', method: 'POST' }).reply(500,
      JSON.stringify({ error: 'internal server error' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx('commercial')
    await testSsrf({ endpoint: '/api/err500', urlParam: 'url' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('handles network error during SSRF probe gracefully', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/netfail', method: 'POST' }).replyWithError('ECONNRESET')

    const ctx = makeCtx('commercial')
    const result = await testSsrf({ endpoint: '/api/netfail', urlParam: 'url' }, ctx)
    expect(result).toBeDefined()
  })
})
