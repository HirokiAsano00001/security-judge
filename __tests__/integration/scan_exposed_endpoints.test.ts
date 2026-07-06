import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { scanExposedEndpoints } from '../../src/tools/scan_exposed_endpoints.js'
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

  pool.intercept({ path: '/actuator/env', method: 'GET' }).reply(200,
    JSON.stringify({ NODE_ENV: 'production', API_KEY: 'secret123' }),
    { headers: { 'content-type': 'application/json' } }
  )

  pool.intercept({ path: '/.env', method: 'GET' }).reply(200,
    'DB_PASSWORD=secret\nAPI_KEY=sk-live-abc123',
    { headers: { 'content-type': 'text/plain' } }
  )

  // All other paths return 404
  pool.intercept({ path: /.*/, method: 'GET' }).reply(404, '').persist()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('scanExposedEndpoints', () => {
  it('silently returns when url_guard blocks all paths', async () => {
    const ctx = makeCtx()
    ctx.allowedUrls = []
    const result = await scanExposedEndpoints({}, ctx)
    expect(result).toContain('scan_exposed_endpoints')
    expect(ctx.findings).toHaveLength(0)
  })

  it('detects exposed actuator/env endpoint', async () => {
    const ctx = makeCtx()
    await scanExposedEndpoints({}, ctx)
    const envFinding = ctx.findings.find(f => f.description.includes('actuator/env'))
    expect(envFinding).toBeDefined()
    expect(envFinding?.category).toBe('C')
  })

  it('detects exposed .env file', async () => {
    const ctx = makeCtx()
    await scanExposedEndpoints({}, ctx)
    const envFinding = ctx.findings.find(f => f.description.includes('.env'))
    expect(envFinding).toBeDefined()
  })

  it('returns summary string', async () => {
    const ctx = makeCtx()
    const result = await scanExposedEndpoints({}, ctx)
    expect(result).toContain('scan_exposed_endpoints')
    expect(result).toContain('Exposed:')
  })
})

describe('scanExposedEndpoints - swagger / graphql paths', () => {
  let mockAgent2: MockAgent
  let originalDispatcher2: Dispatcher

  beforeEach(() => {
    originalDispatcher2 = getGlobalDispatcher()
    mockAgent2 = new MockAgent()
    mockAgent2.disableNetConnect()
    setGlobalDispatcher(mockAgent2)

    const pool = mockAgent2.get('http://test.example.com')
    // swagger-ui returns JSON with "swagger" keyword → sensitive content → HIGH finding
    pool.intercept({ path: '/swagger-ui.html', method: 'GET' }).reply(200,
      '{"swagger":"2.0","info":{"title":"Test API"},"paths":{}}',
      { headers: { 'content-type': 'application/json' } }
    )
    pool.intercept({ path: /.*/, method: 'GET' }).reply(404, '').persist()
  })

  afterEach(() => {
    setGlobalDispatcher(originalDispatcher2)
  })

  it('creates HIGH severity finding with category A for swagger-ui', async () => {
    const ctx = makeCtx()
    await scanExposedEndpoints({}, ctx)
    const swaggerFinding = ctx.findings.find(f => f.description.includes('swagger-ui'))
    expect(swaggerFinding).toBeDefined()
    expect(swaggerFinding?.severity).toBe('HIGH')
    expect(swaggerFinding?.category).toBe('A')
  })
})
