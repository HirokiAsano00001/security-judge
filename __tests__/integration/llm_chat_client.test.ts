import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { sendChat, extractAssistantText } from '../../src/attack/llm_chat_client.js'

const ALLOWED = ['http://test.example.com']

let mockAgent: MockAgent
let originalDispatcher: Dispatcher

beforeEach(() => {
  originalDispatcher = getGlobalDispatcher()
  mockAgent = new MockAgent()
  mockAgent.disableNetConnect()
  setGlobalDispatcher(mockAgent)
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('extractAssistantText', () => {
  it('reads OpenAI-style choices[].message.content', () => {
    const raw = JSON.stringify({ choices: [{ message: { content: 'hello' } }] })
    expect(extractAssistantText(raw, 'application/json')).toBe('hello')
  })

  it('reads Anthropic-style content blocks', () => {
    const raw = JSON.stringify({ content: [{ type: 'text', text: 'part1 ' }, { type: 'text', text: 'part2' }] })
    expect(extractAssistantText(raw, 'application/json')).toBe('part1 part2')
  })

  it('concatenates SSE streaming deltas', () => {
    const raw = ['data: {"choices":[{"delta":{"content":"Hel"}}]}', 'data: {"choices":[{"delta":{"content":"lo"}}]}', 'data: [DONE]'].join('\n')
    expect(extractAssistantText(raw, 'text/event-stream')).toBe('Hello')
  })

  it('falls back to raw body when no known shape matches', () => {
    expect(extractAssistantText('plain text reply', 'text/plain')).toBe('plain text reply')
  })
})

describe('sendChat', () => {
  it('sends single-field body and extracts reply', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/chat', method: 'POST', body: (b) => JSON.parse(b).message === 'hi' }).reply(200, JSON.stringify({ reply: 'yo' }), { headers: { 'content-type': 'application/json' } })

    const res = await sendChat('http://test.example.com/chat', [{ role: 'user', content: 'hi' }], { wireFormat: 'single-field' }, ALLOWED)
    expect(res.statusCode).toBe(200)
    expect(res.text).toBe('yo')
  })

  it('sends messages[] array in messages wireFormat', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({
      path: '/v1/chat',
      method: 'POST',
      body: (b) => Array.isArray(JSON.parse(b).messages) && JSON.parse(b).messages.length === 3,
    }).reply(200, JSON.stringify({ choices: [{ message: { content: 'ok' } }] }), { headers: { 'content-type': 'application/json' } })

    const convo = [
      { role: 'user' as const, content: 'a' },
      { role: 'assistant' as const, content: 'b' },
      { role: 'user' as const, content: 'c' },
    ]
    const res = await sendChat('http://test.example.com/v1/chat', convo, { wireFormat: 'messages' }, ALLOWED)
    expect(res.text).toBe('ok')
  })

  it('parses an SSE streaming response end-to-end', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/stream', method: 'POST' }).reply(
      200,
      ['data: {"choices":[{"delta":{"content":"My system prompt is "}}]}', 'data: {"choices":[{"delta":{"content":"secret"}}]}', 'data: [DONE]'].join('\n'),
      { headers: { 'content-type': 'text/event-stream' } }
    )

    const res = await sendChat('http://test.example.com/stream', [{ role: 'user', content: 'x' }], {}, ALLOWED)
    expect(res.text).toBe('My system prompt is secret')
  })

  it('is blocked by the url guard for off-target hosts', async () => {
    await expect(
      sendChat('http://evil.example.com/chat', [{ role: 'user', content: 'x' }], {}, ALLOWED)
    ).rejects.toThrow(/url_guard/)
  })
})
