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
  it('skips absolute URL script src (external CDN)', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(200,
      '<html><script src="https://cdn.external.com/lib.js"></script><script src="/app.js"></script></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/app.js', method: 'GET' }).reply(200,
      `fetch('/api/items');`,
      { headers: { 'content-type': 'application/javascript' } }
    )
    const result = await scanJsBundle('http://test.example.com')
    expect(result.some(e => e.path === '/api/items')).toBe(true)
  })

  it('skips script when JS fetch returns non-200', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(200,
      '<html><script src="/missing.js"></script></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/missing.js', method: 'GET' }).reply(404, 'Not Found')
    const result = await scanJsBundle('http://test.example.com')
    expect(result).toEqual([])
  })

  it('extracts path with /api/ not at start of segment', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(200,
      '<html><script src="/bundle.js"></script></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/bundle.js', method: 'GET' }).reply(200,
      `axios.get('/v2/api/orders');`,
      { headers: { 'content-type': 'application/javascript' } }
    )
    const result = await scanJsBundle('http://test.example.com')
    expect(result.some(e => e.path.includes('/api/'))).toBe(true)
  })

  it('handles relative script src without leading slash', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(200,
      '<html><script src="chunk.js"></script></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/chunk.js', method: 'GET' }).reply(200,
      `fetch('/api/chunks');`,
      { headers: { 'content-type': 'application/javascript' } }
    )
    const result = await scanJsBundle('http://test.example.com')
    expect(result.some(e => e.path === '/api/chunks')).toBe(true)
  })

  it('handles JS bundle network error gracefully', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/', method: 'GET' }).reply(200,
      '<html><script src="/broken.js"></script></html>',
      { headers: { 'content-type': 'text/html' } }
    )
    pool.intercept({ path: '/broken.js', method: 'GET' }).replyWithError('ETIMEDOUT')
    const result = await scanJsBundle('http://test.example.com')
    expect(result).toEqual([])
  })

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
  it('creates one endpoint per HTTP method in a path', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/openapi.json', method: 'GET' }).reply(200,
      JSON.stringify({
        paths: {
          '/api/items': { get: {}, post: {}, delete: {} },
        }
      }),
      { headers: { 'content-type': 'application/json' } }
    )
    const result = await fetchOpenApiEndpoints('http://test.example.com')
    const itemEndpoints = result.filter(e => e.path === '/api/items')
    expect(itemEndpoints.length).toBe(3)
    expect(itemEndpoints.some(e => e.method === 'DELETE')).toBe(true)
  })

  it('stops at first successful candidate (break statement)', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/openapi.json', method: 'GET' }).reply(200,
      JSON.stringify({ paths: { '/api/break-test': { get: {} } } }),
      { headers: { 'content-type': 'application/json' } }
    )
    // Intercept remaining candidates so they return a real response (not a connection error)
    // They won't be called if break works, but intercepting prevents MockNotMatchedError
    pool.intercept({ path: '/swagger.json', method: 'GET' }).reply(404, '').persist()
    pool.intercept({ path: '/v3/api-docs', method: 'GET' }).reply(404, '').persist()
    pool.intercept({ path: '/api-docs', method: 'GET' }).reply(404, '').persist()
    const result = await fetchOpenApiEndpoints('http://test.example.com')
    expect(result.some(e => e.path === '/api/break-test')).toBe(true)
  })

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

  it('handles OpenAPI spec with no paths property', async () => {
    const pool = mockAgent.get('http://test.example.com')
    pool.intercept({ path: '/openapi.json', method: 'GET' }).reply(200,
      JSON.stringify({ info: { title: 'API', version: '1.0' } }),
      { headers: { 'content-type': 'application/json' } }
    )
    const result = await fetchOpenApiEndpoints('http://test.example.com')
    expect(result).toEqual([])
  })

  it('returns empty array when no spec found', async () => {
    const pool = mockAgent.get('http://test.example.com')
    for (const p of ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs']) {
      pool.intercept({ path: p, method: 'GET' }).reply(404, 'Not Found')
    }

    const result = await fetchOpenApiEndpoints('http://test.example.com')
    expect(result).toEqual([])
  })

  it('catches JSON parse error and tries next candidate', async () => {
    const pool = mockAgent.get('http://test.example.com')
    // /openapi.json returns 200 but with non-JSON body → body.json() throws → catch → try next
    pool.intercept({ path: '/openapi.json', method: 'GET' }).reply(200,
      'not valid json!!!',
      { headers: { 'content-type': 'text/plain' } }
    )
    pool.intercept({ path: '/swagger.json', method: 'GET' }).reply(200,
      JSON.stringify({ paths: { '/api/fallback': { get: {} } } }),
      { headers: { 'content-type': 'application/json' } }
    )
    pool.intercept({ path: '/v3/api-docs', method: 'GET' }).reply(404, '').persist()
    pool.intercept({ path: '/api-docs', method: 'GET' }).reply(404, '').persist()
    const result = await fetchOpenApiEndpoints('http://test.example.com')
    expect(result.some(e => e.path === '/api/fallback')).toBe(true)
  })
})
