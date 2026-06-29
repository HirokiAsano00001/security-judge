import { describe, it, expect } from 'vitest'
import { calculateScore } from '../../src/scorer/rubric.js'
import { type Finding, type Persona } from '../../src/types/index.js'

function makeFinding(category: Finding['category']): Finding {
  return {
    severity: 'CRITICAL',
    category,
    description: `Test finding category ${category}`,
    evidence: 'test evidence',
    isFail: true,
    baseDeduction: category === 'D' ? 5 : 10,
    toolName: 'test',
  }
}

describe('calculateScore', () => {
  it('returns 10 when no findings', () => {
    expect(calculateScore([], 'personal').score).toBe(10)
    expect(calculateScore([], 'commercial').score).toBe(10)
  })

  it('personal + category A: score = 10 - 10*0.3 = 7.0', () => {
    const result = calculateScore([makeFinding('A')], 'personal')
    expect(result.score).toBe(7.0)
    expect(result.isInstantFail).toBe(false)
  })

  it('commercial + category A: instant fail (score=0)', () => {
    const result = calculateScore([makeFinding('A')], 'commercial')
    expect(result.score).toBe(0)
    expect(result.isInstantFail).toBe(true)
  })

  it('commercial + category B: instant fail', () => {
    const result = calculateScore([makeFinding('B')], 'commercial')
    expect(result.isInstantFail).toBe(true)
  })

  it('internal + category B: instant fail', () => {
    const result = calculateScore([makeFinding('B')], 'internal')
    expect(result.isInstantFail).toBe(true)
  })

  it('commercial + category D: score = 10 - 5*1.0 = 5.0 (no instant fail)', () => {
    const result = calculateScore([makeFinding('D')], 'commercial')
    expect(result.score).toBe(5.0)
    expect(result.isInstantFail).toBe(false)
  })

  it('internal + category C: instant fail', () => {
    const result = calculateScore([makeFinding('C')], 'internal')
    expect(result.isInstantFail).toBe(true)
  })

  it('team + category A: score = 10 - 10*0.5 = 5.0', () => {
    const result = calculateScore([makeFinding('A')], 'team')
    expect(result.score).toBe(5.0)
  })

  it('score floor is 0 (never negative)', () => {
    const manyFindings = Array.from({ length: 5 }, () => makeFinding('A'))
    const result = calculateScore(manyFindings, 'personal')
    expect(result.score).toBeGreaterThanOrEqual(0)
  })

  it('returns deductions list', () => {
    const result = calculateScore([makeFinding('A')], 'team')
    expect(result.deductions).toHaveLength(1)
    expect(result.deductions[0].category).toBe('A')
    expect(result.deductions[0].amount).toBe(5.0)
  })
})

// Full matrix: all personas x all categories
const MATRIX: Array<{ persona: Persona; category: Finding['category']; expectFail: boolean; expectedScore: number }> = [
  { persona: 'personal', category: 'A', expectFail: false, expectedScore: 7.0 },
  { persona: 'personal', category: 'B', expectFail: false, expectedScore: 7.0 },
  { persona: 'personal', category: 'C', expectFail: false, expectedScore: 7.0 },
  { persona: 'personal', category: 'D', expectFail: false, expectedScore: 8.5 },
  { persona: 'team', category: 'A', expectFail: false, expectedScore: 5.0 },
  { persona: 'team', category: 'B', expectFail: false, expectedScore: 5.0 },
  { persona: 'team', category: 'C', expectFail: false, expectedScore: 5.0 },
  { persona: 'team', category: 'D', expectFail: false, expectedScore: 7.5 },
  { persona: 'internal', category: 'A', expectFail: false, expectedScore: 2.0 },
  { persona: 'internal', category: 'B', expectFail: true, expectedScore: 0 },
  { persona: 'internal', category: 'C', expectFail: true, expectedScore: 0 },
  { persona: 'internal', category: 'D', expectFail: false, expectedScore: 6.0 },
  { persona: 'commercial', category: 'A', expectFail: true, expectedScore: 0 },
  { persona: 'commercial', category: 'B', expectFail: true, expectedScore: 0 },
  { persona: 'commercial', category: 'C', expectFail: true, expectedScore: 0 },
  { persona: 'commercial', category: 'D', expectFail: false, expectedScore: 5.0 },
]

describe('scoring matrix (parameterized)', () => {
  for (const { persona, category, expectFail, expectedScore } of MATRIX) {
    it(`${persona} + category ${category} => fail=${expectFail}, score=${expectedScore}`, () => {
      const result = calculateScore([makeFinding(category)], persona)
      expect(result.isInstantFail).toBe(expectFail)
      expect(result.score).toBeCloseTo(expectedScore, 5)
    })
  }
})
