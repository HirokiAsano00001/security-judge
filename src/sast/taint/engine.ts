import * as ts from 'typescript'
import { type Flow } from './types.js'
import { type TaintEnv, EMPTY_ENV, withVar, withoutVar, appendHop } from './taint_state.js'
import { getLine, memberPath, calleePath, isAssignment } from './ast_util.js'
import { evalExpr } from './expression.js'
import { matchCallSink, matchAssignmentSink } from './catalog/sinks.js'

/**
 * Analyze one parsed source file for intra-procedural source → sink taint flows.
 *
 * Strategy: each function-like scope (plus the top-level module) is processed
 * independently, starting from an empty environment. Within a scope, statements are
 * walked sequentially so taint threads through variable bindings; sinks are detected
 * on each statement's own expressions. Nested function scopes are NOT recursed into
 * here — they are collected and processed as their own scopes (so their locals get a
 * fresh environment), which keeps precision high.
 */
export function analyzeSourceFile(sf: ts.SourceFile, fileName: string): Flow[] {
  const flows: Flow[] = []
  for (const scope of collectScopes(sf)) {
    processScope(scope, sf, fileName, flows)
  }
  return flows
}

type ScopeNode = ts.SourceFile | ts.FunctionLikeDeclarationBase

function isFunctionLike(node: ts.Node): node is ts.FunctionLikeDeclarationBase {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isConstructorDeclaration(node) ||
    ts.isGetAccessorDeclaration(node) ||
    ts.isSetAccessorDeclaration(node)
  )
}

/** Collect the source file plus every function-like node as independent scopes. */
function collectScopes(sf: ts.SourceFile): ScopeNode[] {
  const scopes: ScopeNode[] = [sf]
  const visit = (node: ts.Node): void => {
    if (isFunctionLike(node)) scopes.push(node)
    ts.forEachChild(node, visit)
  }
  ts.forEachChild(sf, visit)
  return scopes
}

function processScope(scope: ScopeNode, sf: ts.SourceFile, fileName: string, flows: Flow[]): void {
  if (ts.isSourceFile(scope)) {
    processStatements(scope.statements, EMPTY_ENV, sf, fileName, flows)
    return
  }
  const body = scope.body
  if (body && ts.isBlock(body)) {
    processStatements(body.statements, EMPTY_ENV, sf, fileName, flows)
  } else if (body) {
    // Arrow function with an expression body: no bindings, just scan for sinks.
    scanExpr(body, EMPTY_ENV, sf, fileName, flows)
  }
}

function processStatements(
  statements: readonly ts.Statement[],
  startEnv: TaintEnv,
  sf: ts.SourceFile,
  fileName: string,
  flows: Flow[]
): void {
  let env = startEnv
  for (const stmt of statements) {
    env = processStatement(stmt, env, sf, fileName, flows)
  }
}

/** Process one statement: detect sinks with the current env, then thread bindings. */
function processStatement(
  stmt: ts.Statement,
  env: TaintEnv,
  sf: ts.SourceFile,
  fileName: string,
  flows: Flow[]
): TaintEnv {
  if (ts.isVariableStatement(stmt)) {
    let next = env
    for (const decl of stmt.declarationList.declarations) {
      if (decl.initializer) {
        scanExpr(decl.initializer, next, sf, fileName, flows)
        if (ts.isIdentifier(decl.name)) {
          const r = evalExpr(decl.initializer, next, sf)
          next = r.tainted && r.prov
            ? withVar(next, decl.name.text, appendHop(r.prov, getLine(sf, decl)))
            : withoutVar(next, decl.name.text)
        }
      }
    }
    return next
  }

  if (ts.isExpressionStatement(stmt)) {
    return handleExpressionStatement(stmt.expression, env, sf, fileName, flows)
  }

  if (ts.isIfStatement(stmt)) {
    scanExpr(stmt.expression, env, sf, fileName, flows)
    processStatement(stmt.thenStatement, env, sf, fileName, flows)
    if (stmt.elseStatement) processStatement(stmt.elseStatement, env, sf, fileName, flows)
    return env
  }

  if (ts.isBlock(stmt)) {
    processStatements(stmt.statements, env, sf, fileName, flows)
    return env
  }

  if (
    ts.isForStatement(stmt) ||
    ts.isForOfStatement(stmt) ||
    ts.isForInStatement(stmt) ||
    ts.isWhileStatement(stmt) ||
    ts.isDoStatement(stmt)
  ) {
    const expr = 'expression' in stmt ? (stmt as { expression?: ts.Expression }).expression : undefined
    if (expr) scanExpr(expr, env, sf, fileName, flows)
    processStatement(stmt.statement, env, sf, fileName, flows)
    return env
  }

  if (ts.isReturnStatement(stmt) || ts.isThrowStatement(stmt)) {
    if (stmt.expression) scanExpr(stmt.expression, env, sf, fileName, flows)
    return env
  }

  if (ts.isTryStatement(stmt)) {
    processStatement(stmt.tryBlock, env, sf, fileName, flows)
    if (stmt.catchClause) processStatement(stmt.catchClause.block, env, sf, fileName, flows)
    if (stmt.finallyBlock) processStatement(stmt.finallyBlock, env, sf, fileName, flows)
    return env
  }

  if (ts.isSwitchStatement(stmt)) {
    scanExpr(stmt.expression, env, sf, fileName, flows)
    for (const clause of stmt.caseBlock.clauses) {
      processStatements(clause.statements, env, sf, fileName, flows)
    }
    return env
  }

  return env
}

function handleExpressionStatement(
  expr: ts.Expression,
  env: TaintEnv,
  sf: ts.SourceFile,
  fileName: string,
  flows: Flow[]
): TaintEnv {
  scanExpr(expr, env, sf, fileName, flows)

  if (ts.isBinaryExpression(expr) && isAssignment(expr.operatorToken)) {
    if (ts.isIdentifier(expr.left)) {
      const r = evalExpr(expr.right, env, sf)
      return r.tainted && r.prov
        ? withVar(env, expr.left.text, appendHop(r.prov, getLine(sf, expr)))
        : withoutVar(env, expr.left.text)
    }
  }
  return env
}

/**
 * Recursively scan an expression tree for sinks (call sinks and assignment sinks),
 * evaluating injectable arguments against the given environment. Does not descend
 * into nested function-like nodes — those are separate scopes.
 */
function scanExpr(
  node: ts.Node,
  env: TaintEnv,
  sf: ts.SourceFile,
  fileName: string,
  flows: Flow[]
): void {
  if (isFunctionLike(node)) return

  if (ts.isCallExpression(node)) {
    const cp = calleePath(node)
    if (cp) {
      const sink = matchCallSink(cp)
      if (sink) {
        for (const idx of sink.injectableArgs) {
          const arg = node.arguments[idx]
          if (arg) {
            const r = evalExpr(arg, env, sf)
            if (r.tainted && r.prov) {
              flows.push({ sink: sink.def, sinkLine: getLine(sf, node), prov: r.prov, fileName })
              break
            }
          }
        }
      }
    }
  }

  if (ts.isBinaryExpression(node) && isAssignment(node.operatorToken)) {
    const left = node.left
    const name = ts.isPropertyAccessExpression(left) ? left.name.text : undefined
    const path = memberPath(left)
    const sink = matchAssignmentSink(path, name)
    if (sink) {
      const r = evalExpr(node.right, env, sf)
      if (r.tainted && r.prov) {
        flows.push({ sink, sinkLine: getLine(sf, node), prov: r.prov, fileName })
      }
    }
  }

  ts.forEachChild(node, (child) => scanExpr(child, env, sf, fileName, flows))
}
