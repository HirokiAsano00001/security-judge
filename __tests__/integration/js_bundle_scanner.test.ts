import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { MockAgent, setGlobalDispatcher, getGlobalDispatcher, type Dispatcher } from 'undici'
import { scanJsBundle, fetchOpenApiEndpoints } from '../../src/recon/js_bundle_scanner.js'

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

describe('scanJsBundle', () => {
  it('returns empty array on non-200 home page', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(404, 'Not Found')

    const result = await scanJsBundle('http://test.example.com')
    expect(result).toEqual([])
  })

  it('extracts API endpoints from JS bundle', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(200,
      '<html><script src="/main.js"></script></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/main.js', method: 'GET' }).reply(200,
      `fetch('/api/users'); fetch('/api/products'); const x = '/api/orders';`,
      { headers: { 'content-type': 'application/javascript' } }
    )

    const result = await scanJsBundle('http://test.example.com')
    expect(result.length).toBeGreaterThan(0)
    expect(result.some(e => e.path === '/api/users')).toBe(true)
  })

  it('handles network error gracefully', async () => {
    const pool = mockAgent.get('http://unreachable.example.com')
    pool.intercept({ path: '/', method: 'GET' }).replyWithError('ECONNREFUSED')

    const result = await scanJsBundle('http://unreachable.example.com')
    expect(result).toEqual([])
  })
})

describe('fetchOpenApiEndpoints', () => {
  it('extracts endpoints from OpenAPI spec', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/openapi.json', method: 'GET' }).reply(200,
      JSON.stringify({
        paths: {
          '/api/users': { get: {}, post: {} },
          '/api/users/{id}': { get: {}, put: {}, delete: {} },
        }
      }),
      { headers: { 'content-type': 'application/json' } }
    )

    const result = await fetchOpenApiEndpoints('http://test.example.com')
    expect(result.length).toBeGreaterThanOrEqual(5)
    expect(result.some(e => e.path === '/api/users')).toBe(true)
  })

  it('returns empty array when no spec found', async () => {
    const pool = mockAgent.get('http://test.example.com')
    for (const p of ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs']) {
      pool.intercept({ path: p, method: 'GET' }).reply(404, 'Not Found')
    }

    const result = await fetchOpenApiEndpoints('http://test.example.com')
    expect(result).toEqual([])
  })
})
