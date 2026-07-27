import { describe, it, expect } from 'vitest'
import { matchSource } from '../../src/sast/taint/catalog/sources.js'
import { matchCallSink, matchAssignmentSink } from '../../src/sast/taint/catalog/sinks.js'
import { isSanitizer } from '../../src/sast/taint/catalog/sanitizers.js'
import { scriptKindForExt, isAnalyzableExt } from '../../src/sast/taint/script_kind.js'

describe('source catalog', () => {
  it('matches source prefixes and their members', () => {
    expect(matchSource('req.query')).toBe('req.query')
    expect(matchSource('req.query.id')).toBe('req.query')
    expect(matchSource('req.body.user.name')).toBe('req.body')
    expect(matchSource('process.argv')).toBe('process.argv')
  })

  it('does not match trusted / unrelated paths', () => {
    expect(matchSource('req.method')).toBeUndefined()
    expect(matchSource('process.env.KEY')).toBeUndefined()
    expect(matchSource('user.query')).toBeUndefined()
  })
})

describe('sink catalog', () => {
  it('maps call sinks to correct CWE/OWASP', () => {
    expect(matchCallSink('db.query')?.def.cweId).toBe('CWE-89')
    expect(matchCallSink('eval')?.def.cweId).toBe('CWE-95')
    expect(matchCallSink('child_process.exec')?.def.cweId).toBe('CWE-78')
    expect(matchCallSink('fs.readFileSync')?.def.vulnKind).toBe('PATH_TRAVERSAL')
    expect(matchCallSink('res.redirect')?.def.vulnKind).toBe('OPEN_REDIRECT')
    expect(matchCallSink('ejs.render')?.def.vulnKind).toBe('SSTI')
  })

  it('does not flag benign calls', () => {
    expect(matchCallSink('regex.exec')).toBeUndefined()
    expect(matchCallSink('res.render')).toBeUndefined() // template data, not SSTI sink
    expect(matchCallSink('console.log')).toBeUndefined()
  })

  it('all call sinks target arg 0', () => {
    expect(matchCallSink('db.query')?.injectableArgs).toEqual([0])
  })

  it('matches assignment sinks by property name and full path', () => {
    expect(matchAssignmentSink('el.innerHTML', 'innerHTML')?.vulnKind).toBe('XSS')
    expect(matchAssignmentSink(undefined, 'innerHTML')?.vulnKind).toBe('XSS')
    expect(matchAssignmentSink('a.href', 'href')?.vulnKind).toBe('OPEN_REDIRECT')
    expect(matchAssignmentSink('window.location', 'location')?.vulnKind).toBe('OPEN_REDIRECT')
    expect(matchAssignmentSink('x', undefined)).toBeUndefined()
  })
})

describe('sanitizer catalog', () => {
  it('recognizes coercion and encoding sanitizers', () => {
    expect(isSanitizer('parseInt')).toBe(true)
    expect(isSanitizer('Number')).toBe(true)
    expect(isSanitizer('encodeURIComponent')).toBe(true)
    expect(isSanitizer('DOMPurify.sanitize')).toBe(true)
    expect(isSanitizer('validator.escape')).toBe(true)
    expect(isSanitizer('escapeHtml')).toBe(true)
  })

  it('does not treat arbitrary calls as sanitizers', () => {
    expect(isSanitizer('foo')).toBe(false)
    expect(isSanitizer('db.query')).toBe(false)
  })
})

describe('scriptKindForExt', () => {
  it('maps known TS/JS extensions', () => {
    expect(scriptKindForExt('ts')).toBeDefined()
    expect(scriptKindForExt('tsx')).toBeDefined()
    expect(scriptKindForExt('js')).toBeDefined()
    expect(scriptKindForExt('jsx')).toBeDefined()
    expect(scriptKindForExt('mjs')).toBeDefined()
    expect(isAnalyzableExt('ts')).toBe(true)
    expect(isAnalyzableExt('py')).toBe(false)
    expect(isAnalyzableExt('java')).toBe(false)
  })
})
