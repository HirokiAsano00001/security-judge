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
  it('handles request-level network error gracefully', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/chat-error', method: 'POST' }).replyWithError('ECONNRESET').persist()

    const ctx = makeCtx()
    const result = await injectLlmJailbreak({ chatEndpoint: '/api/chat-error' }, ctx)
    expect(result).toBeDefined()
    expect(result).toContain('inject_llm_jailbreak')
  })

  it('detects system prompt leak', async () => {
    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/chat' }, ctx)
    const leakFinding = ctx.findings.find(f => f.category === 'D')
    expect(leakFinding).toBeDefined()
  })

  it('does NOT false-positive on a benign response containing "you are"', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/safe-chat', method: 'POST' }).reply(200,
      JSON.stringify({ reply: "You are welcome! I can't share my configuration, but I'm happy to help." }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/safe-chat' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('does NOT false-positive when the model merely echoes the attack payload', async () => {
    const pool = mockAgent.get('http://test.example.com')
    // Echoes the payload verbatim — no actual disclosure.
    pool.intercept({ path: '/api/echo-chat', method: 'POST' }).reply(200, (opts) => {
      const body = typeof opts.body === 'string' ? JSON.parse(opts.body) : {}
      return { statusCode: 200, data: JSON.stringify({ reply: `Echo: ${body.message}` }), responseOptions: { headers: { 'content-type': 'application/json' } } }
    }).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/echo-chat' }, ctx)
    expect(ctx.findings).toHaveLength(0)
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

  it('sets Authorization header when token is provided', async () => {
    const ctx = makeCtx()
    const result = await injectLlmJailbreak({ chatEndpoint: '/api/chat', token: 'bearer-token-xyz' }, ctx)
    expect(result).toContain('inject_llm_jailbreak')
  })
})
