import { describe, it, expect } from 'vitest'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { analyzeTaint } from '../../src/tools/analyze_taint.js'
import { type JudgeContext } from '../../src/types/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(__dirname, '../fixtures')

function makeCtx(): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: 'http://localhost:8080',
    allowedUrls: ['http://localhost:8080'],
    hasLlmChat: false,
    endpoints: [],
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

describe('analyzeTaint', () => {
  it('detects taint flows across the vuln fixtures (SQLi/RCE/XSS/path)', async () => {
    const ctx = makeCtx()
    const result = await analyzeTaint({ sourcePath: join(FIXTURES, 'vuln') }, ctx)
    const taint = ctx.findings.filter((f) => f.toolName === 'analyze_taint')
    expect(taint.length).toBeGreaterThanOrEqual(4)
    const cwes = new Set(taint.map((f) => f.cweId))
    expect(cwes.has('CWE-89')).toBe(true) // SQLi
    expect(cwes.has('CWE-78')).toBe(true) // RCE
    expect(cwes.has('CWE-79')).toBe(true) // XSS
    expect(cwes.has('CWE-22')).toBe(true) // path traversal
    expect(taint.every((f) => f.severity === 'CRITICAL')).toBe(true)
    expect(result).toContain('taint-confirmed')
  })

  it('produces no taint findings on the safe fixtures (specificity)', async () => {
    const ctx = makeCtx()
    await analyzeTaint({ sourcePath: join(FIXTURES, 'safe') }, ctx)
    expect(ctx.findings.filter((f) => f.toolName === 'analyze_taint')).toHaveLength(0)
  })

  it('accepts a single file path (not just a directory)', async () => {
    const ctx = makeCtx()
    await analyzeTaint({ sourcePath: join(FIXTURES, 'vuln', 'taint_sqli.ts') }, ctx)
    const taint = ctx.findings.filter((f) => f.toolName === 'analyze_taint')
    expect(taint).toHaveLength(1)
    expect(taint[0].cweId).toBe('CWE-89')
  })

  it('handles a non-existent path without throwing', async () => {
    const ctx = makeCtx()
    const result = await analyzeTaint({ sourcePath: '/no/such/path' }, ctx)
    expect(typeof result).toBe('string')
    expect(ctx.findings).toHaveLength(0)
  })
})
