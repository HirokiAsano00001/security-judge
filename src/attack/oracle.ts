export type OracleConfidence = 'HIGH' | 'MEDIUM' | 'LOW'

export interface OracleResult {
  isVulnerable: boolean
  confidence: OracleConfidence
  evidence: string
}

const DB_ERROR_SIGNATURES: RegExp[] = [
  /ORA-\d+/,
  /SQLSTATE\[/i,
  /SQLServerException/i,
  /MySQLSyntaxError/i,
  /PG::SyntaxError/i,
  /sqlite3\.OperationalError/i,
  /Warning: mysql_fetch_array\(\)/i,
  /You have an error in your SQL syntax/i,
  /Unclosed quotation mark after the character string/i,
  /quoted string not properly terminated/i,
  /syntax error at or near/i,
  /mysql_num_rows\(\)/i,
  /pg_query\(\)/i,
  /JdbcSQLSyntaxErrorException/i,
]

const FILE_READ_SIGNATURES: RegExp[] = [
  /root:x:0:0/,
  /daemon:x:\d+:\d+/,
  /nobody:x:\d+:\d+/,
  /root:\$[0-9a-z$]+/,
  /\[extensions\]/i,
  /Volume in drive [A-Z]/,
  /Directory of [A-Z]:\\/i,
  /\[fonts\]/i,
]

const STACK_TRACE_SIGNATURES: RegExp[] = [
  /at\s+[\w$.]+\([\w/.:]+\.java:\d+\)/,
  /Traceback \(most recent call last\):/,
  /at\s+Object\.<anonymous>\s+\([^)]+\.js:\d+:\d+\)/,
  // General Node/JS stack frame — an arrow/anonymous handler leaks as `at <path>.js:line:col`
  // (with or without a wrapping "(...)"), which the Object.<anonymous>-only pattern missed.
  /\bat\s+[^\s"]*\.(?:js|ts|jsx|tsx|mjs|cjs):\d+:\d+/,
  // Express/Node returning the raw Error.stack in a JSON field.
  /"stack"\s*:\s*"(?:Error|TypeError|ReferenceError|RangeError|SyntaxError)[: ]/i,
  /panic: runtime error/,
  /goroutine \d+ \[running\]/,
  /SystemError:/,
  /Exception in thread "main"/,
  /Caused by: /,
]

export function checkDbErrorSignatures(responseBody: string): OracleResult {
  for (const sig of DB_ERROR_SIGNATURES) {
    const match = responseBody.match(sig)
    if (match) {
      return {
        isVulnerable: true,
        confidence: 'HIGH',
        evidence: `DB error signature: "${match[0].slice(0, 200)}"`,
      }
    }
  }
  return { isVulnerable: false, confidence: 'LOW', evidence: '' }
}

export function checkFileReadSignatures(responseBody: string): OracleResult {
  for (const sig of FILE_READ_SIGNATURES) {
    const match = responseBody.match(sig)
    if (match) {
      return {
        isVulnerable: true,
        confidence: 'HIGH',
        evidence: `File contents leaked: "${match[0].slice(0, 200)}"`,
      }
    }
  }
  return { isVulnerable: false, confidence: 'LOW', evidence: '' }
}

export function checkStackTraceSignatures(responseBody: string): OracleResult {
  for (const sig of STACK_TRACE_SIGNATURES) {
    const match = responseBody.match(sig)
    if (match) {
      return {
        isVulnerable: true,
        confidence: 'HIGH',
        evidence: `Stack trace exposed: "${match[0].slice(0, 200)}"`,
      }
    }
  }
  return { isVulnerable: false, confidence: 'LOW', evidence: '' }
}

export function checkXssReflection(responseBody: string, payload: string): OracleResult {
  if (payload && responseBody.includes(payload)) {
    return {
      isVulnerable: true,
      confidence: 'HIGH',
      evidence: 'XSS payload reflected unescaped in response body',
    }
  }
  const partialTag = '<script'
  if (payload.includes('<script') && responseBody.toLowerCase().includes(partialTag)) {
    return {
      isVulnerable: false,
      confidence: 'MEDIUM',
      evidence: 'Partial script tag found — manual verification recommended',
    }
  }
  return { isVulnerable: false, confidence: 'LOW', evidence: '' }
}

function normalizeBody(body: string): string {
  return body
    .replace(/\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?/g, '[DATE]')
    .replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '[UUID]')
    .replace(/\b\d{10,}\b/g, '[NUM]')
    .trim()
}

function jaccardSimilarity(a: string, b: string): number {
  const setA = new Set(a.split(/\s+/).filter(Boolean))
  const setB = new Set(b.split(/\s+/).filter(Boolean))
  if (setA.size === 0 && setB.size === 0) return 1
  const intersection = [...setA].filter(x => setB.has(x)).length
  const union = new Set([...setA, ...setB]).size
  return union === 0 ? 1 : intersection / union
}

export function checkBooleanDiff(
  baselineBody: string,
  trueBody: string,
  falseBody: string,
): OracleResult {
  const normBase = normalizeBody(baselineBody)
  const normTrue = normalizeBody(trueBody)
  const normFalse = normalizeBody(falseBody)

  const simTrueBase = jaccardSimilarity(normTrue, normBase)
  const simTrueFalse = jaccardSimilarity(normTrue, normFalse)

  if (simTrueBase > 0.7 && simTrueFalse < 0.5) {
    return {
      isVulnerable: true,
      confidence: 'MEDIUM',
      evidence: `Boolean diff: OR 1=1 ≈ baseline (${(simTrueBase * 100).toFixed(0)}%), OR 1=1 ≠ OR 1=2 (${(simTrueFalse * 100).toFixed(0)}% similar)`,
    }
  }

  return { isVulnerable: false, confidence: 'LOW', evidence: '' }
}
