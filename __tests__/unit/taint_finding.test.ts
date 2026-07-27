import { describe, it, expect } from 'vitest'
import { flowToFinding, dedupeFlows } from '../../src/sast/taint/finding.js'
import { type Flow } from '../../src/sast/taint/types.js'

function sqlFlow(): Flow {
  return {
    sink: { vulnKind: 'SQLI', label: 'db.query', cweId: 'CWE-89', owaspCategory: 'A03:2021', category: 'A', severity: 'HIGH' },
    sinkLine: 42,
    prov: { sourceLabel: 'req.query', sourceLine: 40, hops: [41] },
    fileName: 'src/routes/user.ts',
  }
}

describe('flowToFinding', () => {
  it('produces a CRITICAL taint-confirmed finding with data-flow evidence', () => {
    const f = flowToFinding(sqlFlow(), 'commercial')
    expect(f.severity).toBe('CRITICAL')
    expect(f.confidence).toBe('HIGH')
    expect(f.description.startsWith('Taint-confirmed:')).toBe(true)
    expect(f.description).toContain('SQL injection')
    expect(f.evidence).toContain('Data-flow: source@40 → 1 hop(s) → sink@42')
    expect(f.cweId).toBe('CWE-89')
    expect(f.owaspCategory).toBe('A03:2021')
    expect(f.toolName).toBe('analyze_taint')
    expect(f.baseDeduction).toBe(10)
  })

  it('is instant-fail for commercial/internal but not personal/team', () => {
    expect(flowToFinding(sqlFlow(), 'commercial').isFail).toBe(true)
    expect(flowToFinding(sqlFlow(), 'internal').isFail).toBe(true)
    expect(flowToFinding(sqlFlow(), 'personal').isFail).toBe(false)
    expect(flowToFinding(sqlFlow(), 'team').isFail).toBe(false)
  })

  it('renders 0 hop(s) for a direct source→sink', () => {
    const flow = { ...sqlFlow(), prov: { sourceLabel: 'req.query', sourceLine: 42, hops: [] } }
    expect(flowToFinding(flow, 'commercial').evidence).toContain('0 hop(s)')
  })
})

describe('dedupeFlows', () => {
  it('de-duplicates on (file, sink line, vuln kind)', () => {
    expect(dedupeFlows([sqlFlow(), sqlFlow()])).toHaveLength(1)
  })

  it('keeps distinct sink lines', () => {
    const a = sqlFlow()
    const b = { ...sqlFlow(), sinkLine: 99 }
    expect(dedupeFlows([a, b])).toHaveLength(2)
  })
})
