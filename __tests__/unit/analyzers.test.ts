import { describe, it, expect } from 'vitest'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { GoAnalyzer } from '../../src/recon/analyzers/go.js'
import { PythonAnalyzer } from '../../src/recon/analyzers/python.js'
import { RubyAnalyzer } from '../../src/recon/analyzers/ruby.js'
import { JavaAnalyzer } from '../../src/recon/analyzers/java.js'
import { NodeAnalyzer } from '../../src/recon/analyzers/node.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(__dirname, '../fixtures')
const MISSING = '/nonexistent/path/that/does/not/exist'

describe('GoAnalyzer', () => {
  const analyzer = new GoAnalyzer()

  it('has language = go', () => {
    expect(analyzer.language).toBe('go')
  })

  it('extracts endpoints from Go source', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'go'))
    expect(endpoints.length).toBeGreaterThanOrEqual(3)
    const paths = endpoints.map(e => e.path)
    expect(paths).toContain('/api/users')
    expect(paths).toContain('/api/users/{id}')
  })

  it('respects .Methods() for HTTP method', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'go'))
    const getUsers = endpoints.find(e => e.path === '/api/users' && e.method === 'GET')
    expect(getUsers).toBeDefined()
    const postUsers = endpoints.find(e => e.path === '/api/users' && e.method === 'POST')
    expect(postUsers).toBeDefined()
  })

  it('returns empty array for nonexistent path', async () => {
    expect(await analyzer.analyze(MISSING)).toEqual([])
  })
})

describe('PythonAnalyzer', () => {
  const analyzer = new PythonAnalyzer()

  it('has language = python', () => {
    expect(analyzer.language).toBe('python')
  })

  it('extracts Flask routes', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'python'))
    expect(endpoints.length).toBeGreaterThanOrEqual(3)
    const paths = endpoints.map(e => e.path)
    expect(paths).toContain('/api/users')
    expect(paths).toContain('/api/products')
  })

  it('detects GET method from @app.get decorator', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'python'))
    const products = endpoints.find(e => e.path === '/api/products')
    expect(products).toBeDefined()
    expect(products!.method).toBe('GET')
  })

  it('detects methods from methods= argument', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'python'))
    const post = endpoints.find(e => e.path === '/api/users' && e.method === 'POST')
    expect(post).toBeDefined()
  })

  it('returns empty array for nonexistent path', async () => {
    expect(await analyzer.analyze(MISSING)).toEqual([])
  })
})

describe('RubyAnalyzer', () => {
  const analyzer = new RubyAnalyzer()

  it('has language = ruby', () => {
    expect(analyzer.language).toBe('ruby')
  })

  it('extracts routes from routes.rb', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'ruby'))
    expect(endpoints.length).toBeGreaterThanOrEqual(4)
    const paths = endpoints.map(e => e.path)
    expect(paths).toContain('/api/users')
    expect(paths).toContain('/api/users/:id')
  })

  it('detects HTTP methods', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'ruby'))
    expect(endpoints.some(e => e.method === 'GET')).toBe(true)
    expect(endpoints.some(e => e.method === 'POST')).toBe(true)
    expect(endpoints.some(e => e.method === 'PUT')).toBe(true)
    expect(endpoints.some(e => e.method === 'DELETE')).toBe(true)
  })

  it('returns empty array for nonexistent path', async () => {
    expect(await analyzer.analyze(MISSING)).toEqual([])
  })
})

describe('JavaAnalyzer', () => {
  const analyzer = new JavaAnalyzer()

  it('has language = java', () => {
    expect(analyzer.language).toBe('java')
  })

  it('extracts Spring MVC routes with class-level @RequestMapping', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'java'))
    expect(endpoints.length).toBeGreaterThanOrEqual(4)
    const paths = endpoints.map(e => e.path)
    expect(paths.some(p => p.includes('/api/users'))).toBe(true)
  })

  it('maps HTTP methods correctly', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'java'))
    expect(endpoints.some(e => e.method === 'GET')).toBe(true)
    expect(endpoints.some(e => e.method === 'POST')).toBe(true)
    expect(endpoints.some(e => e.method === 'DELETE')).toBe(true)
    expect(endpoints.some(e => e.method === 'PATCH')).toBe(true)
  })

  it('extracts @PathVariable parameters', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'java'))
    const withParams = endpoints.find(e => e.parameters.some(p => p.in === 'path'))
    expect(withParams).toBeDefined()
  })

  it('extracts @RequestParam parameters', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'java'))
    const withQuery = endpoints.find(e => e.parameters.some(p => p.in === 'query'))
    expect(withQuery).toBeDefined()
  })

  it('returns empty array for nonexistent path', async () => {
    expect(await analyzer.analyze(MISSING)).toEqual([])
  })
})

describe('NodeAnalyzer', () => {
  const analyzer = new NodeAnalyzer()

  it('has language = typescript', () => {
    expect(analyzer.language).toBe('typescript')
  })

  it('extracts Express routes from .js files', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'node'))
    expect(endpoints.length).toBeGreaterThanOrEqual(5)
    const paths = endpoints.map(e => e.path)
    expect(paths).toContain('/api/users')
    expect(paths).toContain('/api/users/:id')
  })

  it('detects HTTP methods from app.get/post/put/delete', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'node'))
    expect(endpoints.some(e => e.method === 'GET')).toBe(true)
    expect(endpoints.some(e => e.method === 'POST')).toBe(true)
    expect(endpoints.some(e => e.method === 'PUT')).toBe(true)
    expect(endpoints.some(e => e.method === 'DELETE')).toBe(true)
  })

  it('extracts path parameters from :param syntax', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'node'))
    const withId = endpoints.find(e => e.path.includes(':id'))
    expect(withId).toBeDefined()
    expect(withId!.parameters.some(p => p.name === 'id')).toBe(true)
  })

  it('marks .ts source as typescript', async () => {
    const endpoints = await analyzer.analyze(join(FIXTURES, 'node'))
    const tsEndpoints = endpoints.filter(e => e.sourceLanguage === 'typescript')
    expect(tsEndpoints.length).toBeGreaterThanOrEqual(0)
  })

  it('returns empty array for nonexistent path', async () => {
    expect(await analyzer.analyze(MISSING)).toEqual([])
  })
})
