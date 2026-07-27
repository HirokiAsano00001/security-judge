import * as ts from 'typescript'

/**
 * Map a file extension to a TypeScript ScriptKind so the parser treats JSX/TSX
 * correctly. Only TS/JS-family extensions are analyzable by the taint engine.
 */
const EXT_TO_KIND: Record<string, ts.ScriptKind> = {
  ts: ts.ScriptKind.TS,
  tsx: ts.ScriptKind.TSX,
  mts: ts.ScriptKind.TS,
  cts: ts.ScriptKind.TS,
  js: ts.ScriptKind.JS,
  jsx: ts.ScriptKind.JSX,
  mjs: ts.ScriptKind.JS,
  cjs: ts.ScriptKind.JS,
}

export function scriptKindForExt(ext: string): ts.ScriptKind | undefined {
  return EXT_TO_KIND[ext.toLowerCase()]
}

export function isAnalyzableExt(ext: string): boolean {
  return scriptKindForExt(ext) !== undefined
}
