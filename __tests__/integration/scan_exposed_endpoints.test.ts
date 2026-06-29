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
