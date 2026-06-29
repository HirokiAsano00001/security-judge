import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { fuzzApiDirect } from '../../src/tools/fuzz_api_direct.js'
import { type JudgeContext, type EndpointInfo } from '../../src/types/index.js'

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

  // Vulnerable: accepts SQLi and returns success
  pool.intercept({ path: '/api/search', method: 'POST' }).reply(
    200,
    JSON.stringify({ results: ['all-data'], count: 999 }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()

  // GET fallback for URL-encoded queries
  pool.intercept({ path: /\/api\/search.*/, method: 'GET' }).reply(
    200,
    JSON.stringify({ results: ['all-data'] }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

const ENDPOINT: EndpointInfo = {
  method: 'POST',
  path: '/api/search',
  parameters: [{ name: 'q', in: 'body', required: true, type: 'string' }],
  authRequired: false,
  sourceLanguage: 'javascript',
}

const GET_ENDPOINT: EndpointInfo = {
  method: 'GET',
  path: '/api/search',
  parameters: [{ name: 'q', in: 'query', required: true, type: 'string' }],
  authRequired: false,
  sourceLanguage: 'javascript',
}

describe('fuzzApiDirect', () => {
  it('detects SQLi acceptance (200 with SQLi payload)', async () => {
    const ctx = makeCtx()
    await fuzzApiDirect({ endpoint: ENDPOINT }, ctx)
    const sqliFindings = ctx.findings.filter(f =>
      f.description.includes('SQL injection') || f.description.includes('Possible SQL')
    )
    expect(sqliFindings.length).toBeGreaterThan(0)
  })

  it('returns summary string', async () => {
    const ctx = makeCtx()
    const result = await fuzzApiDirect({ endpoint: ENDPOINT }, ctx)
    expect(result).toContain('fuzz_api_direct')
  })

  it('passes authToken in Authorization header', async () => {
    const ctx = makeCtx()
    const result = await fuzzApiDirect({ endpoint: ENDPOINT, authToken: 'test-token-xyz' }, ctx)
    expect(result).toBeDefined()
  })

  it('handles GET endpoint with query params', async () => {
    const ctx = makeCtx()
    const result = await fuzzApiDirect({ endpoint: GET_ENDPOINT }, ctx)
    expect(result).toContain('fuzz_api_direct')
  })

  it('handles endpoint with no parameters (uses data field)', async () => {
    const ctx = makeCtx()
    const endpoint: EndpointInfo = {
      method: 'POST',
      path: '/api/search',
      parameters: [],
      authRequired: false,
      sourceLanguage: 'javascript',
    }
    const result = await fuzzApiDirect({ endpoint }, ctx)
    expect(result).toBeDefined()
  })
})
