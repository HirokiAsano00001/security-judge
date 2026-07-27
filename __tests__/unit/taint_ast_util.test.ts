import { describe, it, expect } from 'vitest'
import * as ts from 'typescript'
import { parseSource } from '../../src/sast/taint/parse.js'
import { memberPath, calleePath, lastSegment } from '../../src/sast/taint/ast_util.js'

/** Parse an expression statement and hand its expression to a callback. */
function withExpr<T>(code: string, fn: (e: ts.Expression) => T): T {
  const sf = parseSource(code, 'x.ts')
  const stmt = sf.statements[0] as ts.ExpressionStatement
  return fn(stmt.expression)
}

describe('memberPath', () => {
  it('resolves a dotted property-access path', () => {
    expect(withExpr('req.query.id', memberPath)).toBe('req.query.id')
  })

  it('resolves a string-literal element access', () => {
    expect(withExpr('req.query["id"]', memberPath)).toBe('req.query.id')
  })

  it('stops at a dynamic element access, keeping the resolved base', () => {
    expect(withExpr('req.query[i]', memberPath)).toBe('req.query')
  })

  it('unwraps parentheses / non-null / as before resolving', () => {
    expect(withExpr('(req.query).id', memberPath)).toBe('req.query.id')
    expect(withExpr('(req as any).query', memberPath)).toBe('req.query')
    expect(withExpr('req!.query', memberPath)).toBe('req.query')
  })

  it('returns undefined when the head is not an identifier', () => {
    expect(withExpr('getReq().query', memberPath)).toBeUndefined()
  })
})

describe('calleePath', () => {
  it('resolves the dotted callee of a call expression', () => {
    const p = withExpr('child_process.exec("x")', (e) => calleePath(e as ts.CallExpression))
    expect(p).toBe('child_process.exec')
  })
})

describe('lastSegment', () => {
  it('returns the final path segment', () => {
    expect(lastSegment('db.query')).toBe('query')
    expect(lastSegment('eval')).toBe('eval')
  })
})
