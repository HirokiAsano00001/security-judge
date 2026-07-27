import { describe, it, expect } from 'vitest'
import { parseSemgrepJson } from '../../src/tools/analyze_sast_semgrep.js'

function taintResult() {
  return {
    check_id: 'javascript.express.sqli.tainted-sql-string',
    path: 'src/routes/user.js',
    start: { line: 42, col: 3 },
    end: { line: 42, col: 60 },
    extra: {
      message: 'User input from req.query flows into a SQL query without sanitization',
      severity: 'ERROR',
      lines: 'db.query("SELECT * FROM users WHERE id = " + req.query.id)',
      metadata: {
        cwe: ['CWE-89: Improper Neutralization of Special Elements used in an SQL Command'],
        owasp: ['A03:2021 - Injection'],
        confidence: 'HIGH',
        category: 'security',
      },
      dataflow_trace: {
        taint_source: { location: { line: 40, col: 5 } },
        intermediate_vars: [{ location: { line: 41 }, content: 'id' }],
        taint_sink: { location: { line: 42, col: 3 } },
      },
    },
  }
}

function warningResult() {
  return {
    check_id: 'javascript.lang.security.audit.md5-used',
    path: 'src/crypto.js',
    start: { line: 7, col: 1 },
    extra: {
      message: 'MD5 is a weak hash',
      severity: 'WARNING',
      metadata: {
        cwe: 'CWE-327: Use of a Broken or Risky Cryptographic Algorithm',
        owasp: 'A02:2021 - Cryptographic Failures',
      },
    },
  }
}

describe('parseSemgrepJson', () => {
  it('returns [] for empty / malformed payloads', () => {
    expect(parseSemgrepJson({}, 'commercial')).toEqual([])
    expect(parseSemgrepJson({ results: null }, 'commercial')).toEqual([])
    expect(parseSemgrepJson(undefined, 'commercial')).toEqual([])
    expect(parseSemgrepJson('nonsense', 'commercial')).toEqual([])
  })

  it('elevates a taint (dataflow_trace) finding to CRITICAL with a source→sink evidence trace', () => {
    const [f] = parseSemgrepJson({ results: [taintResult()] }, 'commercial')
    expect(f.severity).toBe('CRITICAL')
    expect(f.confidence).toBe('HIGH')
    expect(f.description.startsWith('Taint-confirmed')).toBe(true)
    expect(f.evidence).toContain('Data-flow: source@40')
    expect(f.evidence).toContain('sink@42')
    expect(f.evidence).toContain('1 hop(s)')
    expect(f.cweId).toBe('CWE-89')
    expect(f.owaspCategory).toBe('A03:2021')
    expect(f.category).toBe('A')
    expect(f.toolName).toBe('analyze_sast_semgrep')
  })

  it('marks a taint-confirmed CRITICAL as instant-fail for commercial but not personal', () => {
    const [commercial] = parseSemgrepJson({ results: [taintResult()] }, 'commercial')
    const [personal] = parseSemgrepJson({ results: [taintResult()] }, 'personal')
    expect(commercial.isFail).toBe(true)
    expect(personal.isFail).toBe(false)
  })

  it('maps a non-taint WARNING to MEDIUM and categorizes crypto (A02/CWE-327) as C', () => {
    const [f] = parseSemgrepJson({ results: [warningResult()] }, 'commercial')
    expect(f.severity).toBe('MEDIUM')
    expect(f.category).toBe('C')
    expect(f.cweId).toBe('CWE-327')
    expect(f.owaspCategory).toBe('A02:2021')
    expect(f.isFail).toBe(false)
    // no dataflow trace → default confidence MEDIUM
    expect(f.confidence).toBe('MEDIUM')
  })

  it('categorizes auth (A07 / CWE-287) as B and components (A06) as D', () => {
    const auth = parseSemgrepJson(
      { results: [{ check_id: 'a', path: 'p', start: { line: 1 }, extra: { severity: 'ERROR', metadata: { owasp: 'A07:2021 - Identification and Authentication Failures', cwe: 'CWE-287' } } }] },
      'commercial'
    )[0]
    const comp = parseSemgrepJson(
      { results: [{ check_id: 'b', path: 'p', start: { line: 1 }, extra: { severity: 'INFO', metadata: { owasp: 'A06:2021 - Vulnerable and Outdated Components' } } }] },
      'commercial'
    )[0]
    expect(auth.category).toBe('B')
    expect(comp.category).toBe('D')
    expect(comp.severity).toBe('LOW')
  })

  it('de-duplicates on (check_id, path, line)', () => {
    const dup = taintResult()
    const findings = parseSemgrepJson({ results: [taintResult(), dup] }, 'commercial')
    expect(findings).toHaveLength(1)
  })

  it('normalizes short OWASP ids like "A3:2021" to "A03:2021"', () => {
    const [f] = parseSemgrepJson(
      { results: [{ check_id: 'x', path: 'p', start: { line: 2 }, extra: { severity: 'ERROR', metadata: { owasp: 'A3:2021' } } }] },
      'commercial'
    )
    expect(f.owaspCategory).toBe('A03:2021')
  })

  it('handles results with no metadata (defaults to category A, HIGH from ERROR)', () => {
    const [f] = parseSemgrepJson(
      { results: [{ check_id: 'y', path: 'p', start: { line: 3 }, extra: { severity: 'ERROR', message: 'x' } }] },
      'commercial'
    )
    expect(f.category).toBe('A')
    expect(f.severity).toBe('HIGH')
    expect(f.cweId).toBeUndefined()
    expect(f.owaspCategory).toBeUndefined()
  })
})
