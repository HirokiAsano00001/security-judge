import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testSsti } from '../../src/tools/test_ssti.js'
import { type JudgeContext, type EndpointInfo } from '../../src/types/index.js'

function makeCtx(endpoints: EndpointInfo[] = []): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: 'http://test.example.com',
    allowedUrls: ['http://test.example.com'],
    hasLlmChat: false,
    endpoints,
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

const STRING_ENDPOINT: EndpointInfo = {
  method: 'GET',
  path: '/api/render',
  parameters: [{ name: 'template', in: 'query', required: true, type: 'string' }],
  authRequired: false,
  sourceLanguage: 'python',
}

let mockAgent: MockAgent
let originalDispatcher: Dispatcher

beforeEach(() => {
  originalDispatcher = getGlobalDispatcher()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('testSsti', () => {
  it('returns early when no string-parameter endpoints', async () => {
    const ctx = makeCtx([])
    const result = await testSsti({}, ctx)
    expect(result).toContain('no string-parameter endpoints found')
    expect(ctx.findings).toHaveLength(0)
  })

  it('confirms SSTI when response contains evaluated result', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    const pool = mockAgent.get('http://test.example.com')
    // Probe: reflect the probe string
    pool.intercept({ path: /\/api\/render\?template=xQz7SstiPrb123/, method: 'GET' }).reply(200,
      'Output: xQz7SstiPrb123', { headers: { 'content-type': 'text/plain' } }
    )
    // SSTI payload: reflect the evaluated result "49"
    pool.intercept({ path: /\/api\/render\?template=%7B%7B7\*7%7D%7D/, method: 'GET' }).reply(200,
      'Output: 49', { headers: { 'content-type': 'text/plain' } }
    )
    // Confirmation payload: {{6*6}} → 36
    pool.intercept({ path: /\/api\/render\?template=%7B%7B6\*6%7D%7D/, method: 'GET' }).reply(200,
      'Output: 36', { headers: { 'content-type': 'text/plain' } }
    )
    pool.intercept({ path: /\/api\/render.*/, method: 'GET' }).reply(200, 'Output: [REDACTED]', {}).persist()

    const ctx = makeCtx([STRING_ENDPOINT])
    await testSsti({}, ctx)
    const sstiFinding = ctx.findings.find(f => f.description.includes('SSTI'))
    expect(sstiFinding).toBeDefined()
    expect(sstiFinding?.severity).toBe('CRITICAL')
    expect(sstiFinding?.isFail).toBe(true)
  })

  it('creates no finding when probe is not reflected', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    mockAgent.get('http://test.example.com')
      .intercept({ path: /\/api\/render.*/, method: 'GET' })
      .reply(200, 'Not reflected', {}).persist()

    const ctx = makeCtx([STRING_ENDPOINT])
    await testSsti({}, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('returns summary string', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com')
      .intercept({ path: /\/api\/render.*/, method: 'GET' })
      .reply(200, 'OK', {}).persist()

    const ctx = makeCtx([STRING_ENDPOINT])
    const result = await testSsti({}, ctx)
    expect(result).toContain('test_ssti')
  })
})
