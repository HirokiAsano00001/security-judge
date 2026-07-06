import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { checkSecurityHeaders } from '../../src/tools/check_security_headers.js'
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

describe('checkSecurityHeaders', () => {
  it('flags missing CSP and HSTS as findings', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: { 'content-type': 'text/html' },
    })

    const ctx = makeCtx()
    await checkSecurityHeaders({}, ctx)
    expect(ctx.findings.some(f => f.description.includes('CSP'))).toBe(true)
    expect(ctx.findings.some(f => f.description.includes('HSTS'))).toBe(true)
  })

  it('detects CORS wildcard + credentials as CRITICAL', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: {
        'access-control-allow-origin': '*',
        'access-control-allow-credentials': 'true',
      },
    })

    const ctx = makeCtx()
    await checkSecurityHeaders({}, ctx)
    const critFinding = ctx.findings.find(f => f.severity === 'CRITICAL' && f.cweId === 'CWE-942')
    expect(critFinding).toBeDefined()
    expect(critFinding?.isFail).toBe(true)
  })

  it('detects Server header info leak as LOW', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: { 'server': 'Apache/2.4.51 (Unix)' },
    })

    const ctx = makeCtx()
    await checkSecurityHeaders({}, ctx)
    const infoLeak = ctx.findings.find(f => f.severity === 'LOW' && f.description.includes('server'))
    expect(infoLeak).toBeDefined()
  })

  it('returns summary string', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)
    mockAgent.get('http://test.example.com').intercept({ path: '/', method: 'GET' }).reply(200, 'OK', {
      headers: { 'content-type': 'text/html' },
    })

    const ctx = makeCtx()
    const result = await checkSecurityHeaders({}, ctx)
    expect(result).toContain('check_security_headers')
    expect(result).toContain('Findings:')
  })
})
