import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { testPathTraversal } from '../../src/tools/test_path_traversal.js'
import { type JudgeContext, type EndpointInfo } from '../../src/types/index.js'

function makeCtx(endpoints: EndpointInfo[] = []): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: 'http://test.example.com',
    allowedUrls: ['http://test.example.com'],
    hasLlmChat: false,
    endpoints,
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

const FILE_ENDPOINT: EndpointInfo = {
  method: 'GET',
  path: '/api/download',
  parameters: [{ name: 'file', in: 'query', required: true, type: 'string' }],
  authRequired: false,
  sourceLanguage: 'java',
}

let mockAgent: MockAgent
let originalDispatcher: Dispatcher

beforeEach(() => {
  originalDispatcher = getGlobalDispatcher()
})

afterEach(() => {
  setGlobalDispatcher(originalDispatcher)
})

describe('testPathTraversal', () => {
  it('returns early when no endpoints with parameters', async () => {
    const ctx = makeCtx([])
    const result = await testPathTraversal({}, ctx)
    expect(result).toContain('no endpoints')
    expect(ctx.findings).toHaveLength(0)
  })

  it('confirms path traversal when response contains /etc/passwd content', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    mockAgent.get('http://test.example.com')
      .intercept({ path: /\/api\/download.*/, method: 'GET' })
      .reply(200, 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin', {
        headers: { 'content-type': 'text/plain' },
      }).persist()

    const ctx = makeCtx([FILE_ENDPOINT])
    await testPathTraversal({}, ctx)
    const finding = ctx.findings.find(f => f.description.includes('traversal'))
    expect(finding).toBeDefined()
    expect(finding?.severity).toBe('CRITICAL')
    expect(finding?.isFail).toBe(true)
    expect(finding?.cweId).toBe('CWE-22')
  })

  it('creates no finding when response has no file signatures', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    mockAgent.get('http://test.example.com')
      .intercept({ path: /\/api\/download.*/, method: 'GET' })
      .reply(200, '{"error":"file not found"}', {}).persist()

    const ctx = makeCtx([FILE_ENDPOINT])
    await testPathTraversal({}, ctx)
    expect(ctx.findings).toHaveLength(0)
  })

  it('returns summary string', async () => {
    originalDispatcher = getGlobalDispatcher()
    mockAgent = new MockAgent()
    mockAgent.disableNetConnect()
    setGlobalDispatcher(mockAgent)

    mockAgent.get('http://test.example.com')
      .intercept({ path: /\/api\/download.*/, method: 'GET' })
      .reply(200, 'nothing', {}).persist()

    const ctx = makeCtx([FILE_ENDPOINT])
    const result = await testPathTraversal({}, ctx)
    expect(result).toContain('test_path_traversal')
  })
})
