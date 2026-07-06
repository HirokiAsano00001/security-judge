import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testCors } from '../../src/tools/test_cors.js'
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

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('testCors', () => {
  it('detects CRITICAL when evil origin reflected with credentials', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: {
        'access-control-allow-origin': 'https://evil.attacker.com',
        'access-control-allow-credentials': 'true',
      },
    }).persist()

    const ctx = makeCtx()
    await testCors({}, ctx)
    const critFinding = ctx.findings.find(f => f.severity === 'CRITICAL')
    expect(critFinding).toBeDefined()
    expect(critFinding?.isFail).toBe(true)
    expect(critFinding?.cweId).toBe('CWE-942')
  })

  it('detects HIGH when evil origin reflected without credentials', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: { 'access-control-allow-origin': 'https://evil.attacker.com' },
    }).persist()

    const ctx = makeCtx()
    await testCors({}, ctx)
    const highFinding = ctx.findings.find(f => f.severity === 'HIGH')
    expect(highFinding).toBeDefined()
  })

  it('creates no findings when CORS is not misconfigured', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: { 'access-control-allow-origin': 'https://test.example.com' },
    }).persist()

    const ctx = makeCtx()
    await testCors({}, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('returns summary string', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {}).persist()

    const ctx = makeCtx()
    const result = await testCors({}, ctx)
    expect(result).toContain('test_cors')
  })
})
