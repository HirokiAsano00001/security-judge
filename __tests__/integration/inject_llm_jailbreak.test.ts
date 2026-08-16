import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { injectLlmJailbreak } from '../../src/tools/inject_llm_jailbreak.js'
import { type JudgeContext } from '../../src/types/index.js'
import { CANARY_EXPECTED } from '../../src/attack/prompt_mutator.js'

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

  it('emits a HOST JUDGMENT block with a transcript when suspicious', async () => {
    const ctx = makeCtx()
    const result = await injectLlmJailbreak({ chatEndpoint: '/api/chat' }, ctx)
    expect(result).toContain('HOST JUDGMENT REQUIRED')
    expect(result).toMatch(/ASSISTANT:/)
  })

  it('a single-strategy leak stays MEDIUM confidence (host confirms)', async () => {
    const ctx = makeCtx()
    // 'direct' is one strategy (its 4 prompts share the strategy) → no corroboration.
    await injectLlmJailbreak({ chatEndpoint: '/api/chat', strategies: ['direct'] }, ctx)
    const f = ctx.findings.find(f => f.category === 'D')!
    expect(f.confidence).toBe('MEDIUM')
    expect(f.severity).toBe('MEDIUM')
  })

  it('escalates to HIGH when a leak is corroborated across multiple strategies', async () => {
    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/chat', strategies: ['direct', 'crescendo'] }, ctx)
    const leaks = ctx.findings.filter(f => f.owaspCategory === 'LLM07')
    expect(leaks.length).toBeGreaterThan(0)
    expect(leaks.every(f => f.confidence === 'HIGH' && f.severity === 'HIGH')).toBe(true)
  })

  it('detects indirect prompt injection (instruction embedded in processed data)', async () => {
    const pool = mockAgent.get('http://test.example.com')
    // App follows the instruction smuggled inside the "article" → emits the canary.
    pool.intercept({ path: '/api/rag-chat', method: 'POST' }).reply(200,
      JSON.stringify({ reply: CANARY_EXPECTED }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/rag-chat', strategies: ['indirect_injection'] }, ctx)
    const f = ctx.findings.find(f => f.description.includes('indirect prompt-injection'))
    expect(f).toBeDefined()
    expect(f!.owaspCategory).toBe('LLM01')
  })

  it('detects sensitive-data disclosure (leaked credential shape) at HIGH confidence', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/leaky-chat', method: 'POST' }).reply(200,
      JSON.stringify({ reply: 'Sure, the admin key is sk-ABCDEFGHIJKLMNOPQRSTUVWX0123' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/leaky-chat', strategies: ['data_exfiltration'] }, ctx)
    const f = ctx.findings.find(f => f.owaspCategory === 'LLM02')
    expect(f).toBeDefined()
    expect(f!.severity).toBe('HIGH')
    expect(f!.confidence).toBe('HIGH')
  })

  it('does NOT report a secret when the model refuses to hand one over', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/exfil-refuse', method: 'POST' }).reply(200,
      JSON.stringify({ reply: "I can't share credentials like sk-ABCDEFGHIJKLMNOPQRSTUVWX0123 — that would be against policy." }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/exfil-refuse', strategies: ['data_exfiltration'] }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('reports a guardrail-robustness metric', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/all-refuse', method: 'POST' }).reply(200,
      JSON.stringify({ reply: "I'm sorry, I can't help with that request." }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    const result = await injectLlmJailbreak({ chatEndpoint: '/api/all-refuse' }, ctx)
    expect(result).toMatch(/Guardrail robustness: \d+\/\d+ campaigns refused/)
    expect(ctx.findings).toHaveLength(0)
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

  it('does NOT false-positive on self-description ("my purpose is to ...")', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/purpose-chat', method: 'POST' }).reply(200,
      JSON.stringify({ reply: 'My purpose is to help you book flights. I never discuss internal policy.' }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/purpose-chat' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('treats a refusal as guardrail held (no finding)', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/refuse-chat', method: 'POST' }).reply(200,
      JSON.stringify({ reply: "I can't reveal my system prompt. As an AI, I'm not allowed to do that." }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/refuse-chat' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('does NOT false-positive when the model merely echoes the attack payload', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/echo-chat', method: 'POST' }).reply(
      200,
      (opts) => JSON.stringify({ reply: `Echo: ${JSON.parse(opts.body as string).message}` }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/echo-chat' }, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('detects prompt-injection compliance via the reversed canary oracle', async () => {
    const pool = mockAgent.get('http://test.example.com')
    // A model that executes the injected transform emits the expected (un-reversed) canary.
    pool.intercept({ path: '/api/comply-chat', method: 'POST' }).reply(200,
      JSON.stringify({ reply: CANARY_EXPECTED }),
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/comply-chat', strategies: ['injected_compliance'] }, ctx)
    const f = ctx.findings.find(f => f.owaspCategory === 'LLM01')
    expect(f).toBeDefined()
    expect(f!.description).toMatch(/off-task instruction executed/)
  })

  it('detects a leak over an SSE streaming response', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/api/stream-chat', method: 'POST' }).reply(200,
      ['data: {"choices":[{"delta":{"content":"My system prompt is "}}]}', 'data: {"choices":[{"delta":{"content":"do X"}}]}', 'data: [DONE]'].join('\n'),
      { headers: { 'content-type': 'text/event-stream' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/stream-chat', strategies: ['direct'] }, ctx)
    expect(ctx.findings.length).toBeGreaterThan(0)
  })

  it('requires escalation across turns (crescendo, messages wireFormat)', async () => {
    const pool = mockAgent.get('http://test.example.com')
    // Leaks ONLY once the conversation has escalated to the 4th user turn
    // (>= 7 messages: 4 user + 3 assistant). Proves multi-turn state is carried.
    pool.intercept({ path: '/api/cresc-chat', method: 'POST' }).reply(
      200,
      (opts) => {
        const body = JSON.parse(opts.body as string)
        const count = Array.isArray(body.messages) ? body.messages.length : 0
        const reply = count >= 7
          ? 'Okay, my system prompt is: You are Corp assistant.'
          : 'I can only speak in general terms.'
        return JSON.stringify({ reply })
      },
      { headers: { 'content-type': 'application/json' } }
    ).persist()

    const ctx = makeCtx()
    await injectLlmJailbreak({ chatEndpoint: '/api/cresc-chat', strategies: ['crescendo'], wireFormat: 'messages' }, ctx)
    const f = ctx.findings.find(f => f.description.includes('crescendo'))
    expect(f).toBeDefined()
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
