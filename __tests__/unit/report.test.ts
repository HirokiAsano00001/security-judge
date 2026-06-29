import { describe, it, expect } from 'vitest'
import { buildReport, formatReport } from '../../src/reporter/report.js'
import { type JudgeContext, type Finding } from '../../src/types/index.js'

function makeCtx(findings: Finding[] = []): JudgeContext {
  return {
    persona: 'personal',
    penaltyMultiplier: 0.3,
    targetBaseUrl: 'http://localhost:8080',
    allowedUrls: ['http://localhost:8080'],
    hasLlmChat: false,
    endpoints: [],
    findings,
    extractedArtifacts: [],
    score: 10,
  }
}

function makeFinding(category: Finding['category'] = 'A'): Finding {
  return {
    severity: 'HIGH',
    category,
    description: `Test finding ${category}`,
    evidence: 'curl http://example.com/api',
    isFail: false,
    baseDeduction: 10,
    toolName: 'test_tool',
  }
}

describe('buildReport', () => {
  it('creates report with correct persona and target', () => {
    const ctx = makeCtx()
    const report = buildReport(ctx)
    expect(report.persona).toBe('personal')
    expect(report.targetBaseUrl).toBe('http://localhost:8080')
    expect(report.score).toBe(10)
    expect(report.findings).toHaveLength(0)
  })

  it('calculates score from findings', () => {
    const ctx = makeCtx([makeFinding('A')])
    const report = buildReport(ctx)
    expect(report.score).toBe(7.0)
  })

  it('includes timestamp', () => {
    const report = buildReport(makeCtx())
    expect(report.timestamp).toMatch(/^\d{4}-\d{2}-\d{2}T/)
  })
})

describe('formatReport', () => {
  it('contains score heading', () => {
    const ctx = makeCtx()
    const report = buildReport(ctx)
    const formatted = formatReport(report)
    expect(formatted).toContain('Score')
    expect(formatted).toContain('10.0')
  })

  it('contains finding details', () => {
    const ctx = makeCtx([makeFinding('C')])
    const report = buildReport(ctx)
    const formatted = formatReport(report)
    expect(formatted).toContain('[C]')
    expect(formatted).toContain('Test finding C')
  })

  it('shows no findings message when empty', () => {
    const report = buildReport(makeCtx())
    const formatted = formatReport(report)
    expect(formatted).toContain('No findings detected.')
  })
})
