import { describe, it, expect, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { loginAndCapture } from '../../src/tools/login_and_capture.js'
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

describe('loginAndCapture', () => {
  it('stores cookies in ctx.sessionCookies on successful login', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/login', method: 'GET' }).reply(200, '<html><form action="/login" method="post"></form></html>', {
      headers: { 'content-type': 'text/html' },
    })
    pool.intercept({ path: '/login', method: 'POST' }).reply(302, '', {
      headers: { 'set-cookie': ['session=abc123; Path=/; HttpOnly', 'user_id=42; Path=/'] },
    })

    const ctx = makeCtx()
    const result = await loginAndCapture({ loginUrl: '/login', username: 'admin', password: 'pass123' }, ctx)
    expect(ctx.sessionCookies).toBeDefined()
    expect(ctx.sessionCookies).toContain('session=abc123')
    expect(result).toContain('SUCCESS')
  })

  it('extracts CSRF token from HTML meta tag', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/login', method: 'GET' }).reply(200,
      '<html><head><meta name="csrf-token" content="tok-xyz-987"></head><body></body></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/login', method: 'POST' }).reply(200, '{"ok":true}', {
      headers: { 'set-cookie': ['session=newsess; Path=/'] },
    })

    const ctx = makeCtx()
    await loginAndCapture({ loginUrl: '/login', username: 'u', password: 'p' }, ctx)
    expect(ctx.sessionCookies).toContain('session=newsess')
  })

  it('reports failure when login returns 401', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/login', method: 'GET' }).reply(200, '<html></html>', {})
    pool.intercept({ path: '/login', method: 'POST' }).reply(401, '{"error":"invalid credentials"}', {})

    const ctx = makeCtx()
    const result = await loginAndCapture({ loginUrl: '/login', username: 'bad', password: 'wrong' }, ctx)
    expect(result).toContain('FAILED')
    expect(ctx.sessionCookies).toBeUndefined()
  })

  it('resolves absolute loginUrl directly', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/auth/login', method: 'GET' }).reply(200, '<html></html>', {})
    pool.intercept({ path: '/auth/login', method: 'POST' }).reply(200, 'ok', {
      headers: { 'set-cookie': ['token=t1; Path=/'] },
    })

    const ctx = makeCtx()
    await loginAndCapture({
      loginUrl: 'http://test.example.com/auth/login',
      username: 'u',
      password: 'p',
    }, ctx)
    expect(ctx.sessionCookies).toContain('token=t1')
  })
})
