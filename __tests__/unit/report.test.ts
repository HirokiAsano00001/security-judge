import { describe, it, expect } from 'vitest'
import { readFileSync, unlinkSync } from 'fs'
import { join } from 'path'
import { tmpdir } from 'os'
import { buildReport, formatReport, saveReport } from '../../src/reporter/report.js'
import { type JudgeContext, type Finding, type SecurityReport } from '../../src/types/index.js'

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
    // HIGH severity: base=10 * multiplier=0.3 * sevWeight=0.6 * confWeight=1.0 = 1.8 → score=8.2
    expect(report.score).toBeCloseTo(8.2, 5)
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

  it('includes filePath and lineNumber when remediation has filePath', () => {
    const report: SecurityReport = {
      timestamp: '2026-01-01T00:00:00.000Z',
      persona: 'personal',
      targetBaseUrl: 'http://localhost:8080',
      score: 5,
      findings: [],
      remediations: [
        {
          findingCategory: 'A',
          description: 'Fix this vulnerability',
          before: 'old code',
          after: 'new code',
          filePath: 'src/auth.ts',
          lineNumber: 42,
        }
      ]
    }
    const formatted = formatReport(report)
    expect(formatted).toContain('File: src/auth.ts:42')
  })

  it('omits file line when remediation has no filePath', () => {
    const report: SecurityReport = {
      timestamp: '2026-01-01T00:00:00.000Z',
      persona: 'personal',
      targetBaseUrl: 'http://localhost:8080',
      score: 5,
      findings: [],
      remediations: [
        {
          findingCategory: 'A',
          description: 'Fix this',
          before: 'old code',
          after: 'new code',
        }
      ]
    }
    const formatted = formatReport(report)
    expect(formatted).not.toContain('File:')
  })

  it('includes filePath without lineNumber when lineNumber is absent', () => {
    const report: SecurityReport = {
      timestamp: '2026-01-01T00:00:00.000Z',
      persona: 'personal',
      targetBaseUrl: 'http://localhost:8080',
      score: 5,
      findings: [],
      remediations: [
        {
          findingCategory: 'A',
          description: 'Fix this',
          before: 'old code',
          after: 'new code',
          filePath: 'src/config.ts',
        }
      ]
    }
    const formatted = formatReport(report)
    expect(formatted).toContain('File: src/config.ts')
    expect(formatted).not.toContain('File: src/config.ts:')
  })
})

describe('saveReport', () => {
  it('writes formatted report to file', () => {
    const outputPath = join(tmpdir(), `security-judge-test-${process.pid}.md`)
    const ctx = makeCtx([makeFinding('A')])
    const report = buildReport(ctx)
    saveReport(report, outputPath)
    try {
      const content = readFileSync(outputPath, 'utf-8')
      expect(content).toContain('# Security Judge Report')
      expect(content).toContain('Score')
    } finally {
      try { unlinkSync(outputPath) } catch { /* ignore */ }
    }
  })
})
