import * as ts from 'typescript'
import { scriptKindForExt } from './script_kind.js'

/**
 * Syntax-only parse of a TS/JS source string. No tsconfig, no type-checker, no
 * program — fast, offline, and never throws on missing modules (malformed input
 * yields a partial tree). `setParentNodes` is required because the engine walks
 * upward (node.parent) to classify identifier reads vs. assignment context.
 */
export function parseSource(code: string, fileName: string): ts.SourceFile {
  const ext = fileName.split('.').pop() ?? 'ts'
  const kind = scriptKindForExt(ext) ?? ts.ScriptKind.TS
  return ts.createSourceFile(
    fileName,
    code,
    ts.ScriptTarget.Latest,
    /* setParentNodes */ true,
    kind
  )
}
