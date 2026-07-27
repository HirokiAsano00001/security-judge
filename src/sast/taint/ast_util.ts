import * as ts from 'typescript'

/** 1-based line number of a node within its source file. */
export function getLine(sf: ts.SourceFile, node: ts.Node): number {
  return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1
}

/** Strip parentheses, `as`/`satisfies`, and non-null `!` wrappers to reach the inner expression. */
export function unwrap(node: ts.Expression): ts.Expression {
  let n: ts.Expression = node
  while (
    ts.isParenthesizedExpression(n) ||
    ts.isAsExpression(n) ||
    ts.isSatisfiesExpression(n) ||
    ts.isNonNullExpression(n)
  ) {
    n = n.expression
  }
  return n
}

/**
 * Build a dotted member path for a property/element access or identifier, e.g.
 * `req.query.id` for `req.query.id` and `req.query.id` for `req.query["id"]`.
 * String-literal element access contributes the literal; dynamic access stops
 * the path (returns what was resolved so far). Returns undefined if the head is
 * not an identifier.
 */
export function memberPath(node: ts.Expression): string | undefined {
  const n = unwrap(node)

  if (ts.isIdentifier(n)) return n.text

  if (ts.isPropertyAccessExpression(n)) {
    const base = memberPath(n.expression)
    return base ? `${base}.${n.name.text}` : undefined
  }

  if (ts.isElementAccessExpression(n)) {
    const base = memberPath(n.expression)
    if (!base) return undefined
    const arg = unwrap(n.argumentExpression)
    if (ts.isStringLiteralLike(arg)) return `${base}.${arg.text}`
    // Dynamic index (e.g. req.query[i]) — keep the resolved base as the path.
    return base
  }

  return undefined
}

/**
 * For a call expression, return the dotted callee path (e.g. "db.query", "eval",
 * "child_process.exec"). Undefined if the callee is not a plain identifier/member.
 */
export function calleePath(call: ts.CallExpression): string | undefined {
  return memberPath(call.expression)
}

/** Last segment of a dotted path, e.g. "query" for "db.query". */
export function lastSegment(path: string): string {
  const i = path.lastIndexOf('.')
  return i === -1 ? path : path.slice(i + 1)
}

/** True if a binary expression is string concatenation / concat-assign (`+` or `+=`). */
export function isConcat(op: ts.BinaryOperatorToken): boolean {
  return op.kind === ts.SyntaxKind.PlusToken || op.kind === ts.SyntaxKind.PlusEqualsToken
}

/** True if a binary operator is a plain or compound assignment we track. */
export function isAssignment(op: ts.BinaryOperatorToken): boolean {
  return (
    op.kind === ts.SyntaxKind.EqualsToken ||
    op.kind === ts.SyntaxKind.PlusEqualsToken
  )
}
