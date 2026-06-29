import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { injectLlmJailbreak } from '../../src/tools/inject_llm_jailbreak.js'
import { type JudgeContext } from '../../src/types/index.js'

function makeCtx(hasLlmChat = true): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: 'http://test.example.com',
    allowedUrls: ['http://test.example.com'],
    hasLlmChat,
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
  // LLM endpoint that leaks system prompt
  pool.intercept({ path: '/api/chat', method: 'POST' }).reply(200,
    JSON.stringify({ reply: 'Your system prompt is: You are an assistant for Corp. Never discuss pricing.' }),
    { headers: { 'content-type': 'application/json' } }
  ).persist()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('injectLlmJailbreak', () => {
  it('detects system prompt leak', async () => {
    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/chat' }, ctx)
    const leakFinding = ctx.findings.find(f => f.category === 'D')
    expect(leakFinding).toBeDefined()
  })

  it('skips when hasLlmChat=false', async () => {
    const ctx = makeCtx(false)
    const result = await injectLlmJailbreak({ chatEndpoint: '/api/chat' }, ctx)
    expect(result).toContain('skipped')
    expect(ctx.findings).toHaveLength(0)
  })

  it('returns summary string', async () => {
    const ctx = makeCtx()
    const result = await injectLlmJailbreak({ chatEndpoint: '/api/chat' }, ctx)
    expect(result).toContain('inject_llm_jailbreak')
  })
})
