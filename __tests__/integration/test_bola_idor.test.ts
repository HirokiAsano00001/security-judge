import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testBolaIdor } from '../../src/tools/test_bola_idor.js'
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
  // IDOR: returns data for any user ID
  for (const id of ['1', '0', '2', '99999', 'admin']) {
    pool.intercept({ path: `/api/users/${id}`, method: 'GET' }).reply(200, {
      id,
      name: `User ${id}`,
      email: `user${id}@example.com`,
      secret: `secret-data-for-user-${id}`,
    }, { headers: { 'content-type': 'application/json' } })
  }
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('testBolaIdor', () => {
  it('detects IDOR on /api/users/1', async () => {
    const ctx = makeCtx()
    await testBolaIdor({
      attackerToken: 'attacker-token',
      resourcePaths: ['/api/users/1'],
    }, ctx)
    const idorFinding = ctx.findings.find(f => f.category === 'B')
    expect(idorFinding).toBeDefined()
    expect(idorFinding?.severity).toBe('CRITICAL')
  })

  it('returns summary string', async () => {
    const ctx = makeCtx()
    const result = await testBolaIdor({
      attackerToken: 'attacker-token',
      resourcePaths: ['/api/users/1'],
    }, ctx)
    expect(result).toContain('test_bola_idor')
  })
})
