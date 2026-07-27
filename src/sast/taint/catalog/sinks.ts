import { type SinkDef, type VulnKind } from '../types.js'
import { lastSegment } from '../ast_util.js'

/** Canonical sink metadata per vulnerability kind (used for finding fields). */
const KIND_META: Record<VulnKind, Omit<SinkDef, 'label' | 'cweId'>> = {
  SQLI: { vulnKind: 'SQLI', owaspCategory: 'A03:2021', category: 'A', severity: 'HIGH' },
  RCE: { vulnKind: 'RCE', owaspCategory: 'A03:2021', category: 'A', severity: 'HIGH' },
  XSS: { vulnKind: 'XSS', owaspCategory: 'A03:2021', category: 'A', severity: 'HIGH' },
  PATH_TRAVERSAL: { vulnKind: 'PATH_TRAVERSAL', owaspCategory: 'A01:2021', category: 'A', severity: 'HIGH' },
  OPEN_REDIRECT: { vulnKind: 'OPEN_REDIRECT', owaspCategory: 'A01:2021', category: 'A', severity: 'MEDIUM' },
  SSTI: { vulnKind: 'SSTI', owaspCategory: 'A03:2021', category: 'A', severity: 'HIGH' },
}

function def(vulnKind: VulnKind, label: string, cweId: string): SinkDef {
  return { ...KIND_META[vulnKind], label, cweId }
}

export interface CallSinkRule {
  /** Return a SinkDef if this callee path is a sink, else undefined. */
  match(calleePath: string): SinkDef | undefined
  /** Argument positions that are injectable (the taint must reach one of these). */
  injectableArgs: number[]
}

const CP_ALIASES = new Set(['cp', 'child_process', 'childProcess', 'child'])
const TEMPLATE_ENGINES = new Set(['ejs', 'pug', 'handlebars', 'Handlebars', 'hbs', 'nunjucks', 'template'])
const HTTP_RES = new Set(['res', 'response'])

function firstSegment(path: string): string {
  const i = path.indexOf('.')
  return i === -1 ? path : path.slice(0, i)
}

/**
 * Call-expression sinks. Each rule inspects the dotted callee path (e.g. "db.query",
 * "child_process.exec", "eval") and returns the matched SinkDef. Matching is kept
 * precise to limit false positives (e.g. `regex.exec` is NOT treated as RCE).
 */
export const CALL_SINKS: readonly CallSinkRule[] = [
  // SQL injection: query builders / drivers.
  {
    injectableArgs: [0],
    match(path) {
      const seg = lastSegment(path)
      if (seg === 'query' || seg === 'execute') return def('SQLI', path, 'CWE-89')
      if (seg === 'raw') return def('SQLI', path, 'CWE-89')
      return undefined
    },
  },
  // Remote code execution: eval / Function / child_process exec family.
  {
    injectableArgs: [0],
    match(path) {
      if (path === 'eval' || path === 'Function') return def('RCE', path, 'CWE-95')
      const seg = lastSegment(path)
      if (seg === 'exec' || seg === 'execSync' || seg === 'spawn' || seg === 'spawnSync') {
        // Only when it is a bare call or a child_process alias — avoids regex.exec.
        if (path === seg || CP_ALIASES.has(firstSegment(path))) return def('RCE', path, 'CWE-78')
      }
      return undefined
    },
  },
  // XSS: DOM/document write and framework HTML responders.
  {
    injectableArgs: [0],
    match(path) {
      if (path === 'document.write' || path === 'document.writeln') return def('XSS', path, 'CWE-79')
      const seg = lastSegment(path)
      if (seg === 'send' && HTTP_RES.has(firstSegment(path))) return def('XSS', path, 'CWE-79')
      return undefined
    },
  },
  // Path traversal / LFI: filesystem reads/writes and file responders.
  {
    injectableArgs: [0],
    match(path) {
      const seg = lastSegment(path)
      const fsSinks = new Set([
        'readFile', 'readFileSync', 'writeFile', 'writeFileSync',
        'createReadStream', 'createWriteStream', 'sendFile',
      ])
      if (fsSinks.has(seg)) return def('PATH_TRAVERSAL', path, 'CWE-22')
      return undefined
    },
  },
  // Open redirect: res.redirect(userUrl).
  {
    injectableArgs: [0],
    match(path) {
      const seg = lastSegment(path)
      if (seg === 'redirect' && HTTP_RES.has(firstSegment(path))) return def('OPEN_REDIRECT', path, 'CWE-601')
      return undefined
    },
  },
  // Server-side template injection: template engine render/compile from user input.
  {
    injectableArgs: [0],
    match(path) {
      const seg = lastSegment(path)
      if ((seg === 'render' || seg === 'compile') && TEMPLATE_ENGINES.has(firstSegment(path))) {
        return def('SSTI', path, 'CWE-94')
      }
      return undefined
    },
  },
]

/** Resolve the first matching call sink for a dotted callee path. */
export function matchCallSink(calleePath: string): { def: SinkDef; injectableArgs: number[] } | undefined {
  for (const rule of CALL_SINKS) {
    const d = rule.match(calleePath)
    if (d) return { def: d, injectableArgs: rule.injectableArgs }
  }
  return undefined
}

/**
 * Assignment sinks: `x.innerHTML = tainted`, `location.href = tainted`. Matched on
 * the left-hand-side property name (works even when the base object is a call
 * expression, e.g. `document.getElementById('x').innerHTML`) and/or its full path.
 */
export function matchAssignmentSink(
  lhsPath: string | undefined,
  lhsName: string | undefined
): SinkDef | undefined {
  const seg = lhsName ?? (lhsPath ? lastSegment(lhsPath) : undefined)
  const label = lhsPath ?? seg ?? '<assignment>'
  if (seg === 'innerHTML' || seg === 'outerHTML') return def('XSS', label, 'CWE-79')
  if (seg === 'href') return def('OPEN_REDIRECT', label, 'CWE-601')
  if (lhsPath === 'location' || lhsPath === 'window.location' || lhsPath === 'document.location') {
    return def('OPEN_REDIRECT', lhsPath, 'CWE-601')
  }
  return undefined
}
