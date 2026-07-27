import * as ts from 'typescript'
import { type TaintResult } from './types.js'
import { type TaintEnv, lookup } from './taint_state.js'
import { getLine, memberPath, calleePath, lastSegment, unwrap } from './ast_util.js'
import { matchSource } from './catalog/sources.js'
import { isSanitizer } from './catalog/sanitizers.js'

const UNTAINTED: TaintResult = { tainted: false }

/** String methods that preserve taint when called on a tainted receiver. */
const PASSTHROUGH_METHODS = new Set([
  'trim', 'trimStart', 'trimEnd', 'toString', 'toLowerCase', 'toUpperCase',
  'slice', 'substring', 'substr', 'replace', 'replaceAll', 'concat',
  'padStart', 'padEnd', 'normalize', 'charAt', 'repeat', 'at',
])

/**
 * Evaluate whether an expression carries attacker-controlled taint, returning the
 * provenance if so. Pure and free of filesystem/scope-walk concerns (env is passed in).
 */
export function evalExpr(node: ts.Expression, env: TaintEnv, sf: ts.SourceFile): TaintResult {
  const n = unwrap(node)

  if (ts.isIdentifier(n)) {
    const prov = lookup(env, n.text)
    return prov ? { tainted: true, prov } : UNTAINTED
  }

  if (ts.isPropertyAccessExpression(n) || ts.isElementAccessExpression(n)) {
    const path = memberPath(n)
    if (path) {
      const label = matchSource(path)
      if (label) {
        return { tainted: true, prov: { sourceLabel: label, sourceLine: getLine(sf, n), hops: [] } }
      }
    }
    // Member access of a tainted base object is itself tainted (alias propagation).
    return evalExpr(n.expression, env, sf)
  }

  if (ts.isBinaryExpression(n)) {
    if (n.operatorToken.kind === ts.SyntaxKind.PlusToken) {
      const left = evalExpr(n.left, env, sf)
      if (left.tainted) return left
      return evalExpr(n.right, env, sf)
    }
    return UNTAINTED
  }

  if (ts.isTemplateExpression(n)) {
    for (const span of n.templateSpans) {
      const r = evalExpr(span.expression, env, sf)
      if (r.tainted) return r
    }
    return UNTAINTED
  }

  if (ts.isConditionalExpression(n)) {
    const t = evalExpr(n.whenTrue, env, sf)
    if (t.tainted) return t
    return evalExpr(n.whenFalse, env, sf)
  }

  if (ts.isCallExpression(n)) {
    const cp = calleePath(n)
    if (cp && isSanitizer(cp)) return UNTAINTED
    // Pass-through string methods preserve the receiver's taint.
    if (ts.isPropertyAccessExpression(n.expression)) {
      const method = lastSegment(memberPath(n.expression) ?? '')
      if (PASSTHROUGH_METHODS.has(method)) {
        return evalExpr(n.expression.expression, env, sf)
      }
    }
    return UNTAINTED
  }

  return UNTAINTED
}
