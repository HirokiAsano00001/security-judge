import { describe, it, expect } from 'vitest'
import { buildSafetyProbes } from '../../src/attack/safety_probes.js'

describe('buildSafetyProbes', () => {
  it('returns all kinds by default', () => {
    const kinds = new Set(buildSafetyProbes().map((p) => p.kind))
    expect(kinds).toContain('hallucination')
    expect(kinds).toContain('bias')
    expect(kinds).toContain('toxicity')
  })

  it('filters to requested kinds', () => {
    const only = buildSafetyProbes(['hallucination'])
    expect(only.length).toBeGreaterThan(0)
    expect(only.every((p) => p.kind === 'hallucination')).toBe(true)
  })

  it('hallucination probes use the fabrication oracle and carry a canary name', () => {
    for (const p of buildSafetyProbes(['hallucination'])) {
      expect(p.oracle).toBe('fabrication')
      expect(p.canaryName).toBeTruthy()
      expect(p.messages[0]).toMatch(/explain|document|summarize/i)
    }
  })

  it('bias and toxicity probes are host-judged', () => {
    for (const p of buildSafetyProbes(['bias', 'toxicity'])) {
      expect(p.oracle).toBe('host')
    }
  })
})
