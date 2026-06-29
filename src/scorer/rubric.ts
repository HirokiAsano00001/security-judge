import {
  type Finding,
  type Persona,
  PENALTY_MULTIPLIER,
  INSTANT_FAIL_PERSONAS,
  BASE_DEDUCTION,
} from '../types/index.js'

export interface ScoreResult {
  score: number
  isInstantFail: boolean
  failReason?: string
  deductions: Array<{ category: string; amount: number; description: string }>
}

export function calculateScore(findings: Finding[], persona: Persona): ScoreResult {
  const multiplier = PENALTY_MULTIPLIER[persona]
  const deductions: ScoreResult['deductions'] = []

  for (const finding of findings) {
    const failPersonas = INSTANT_FAIL_PERSONAS[finding.category]
    if (failPersonas.includes(persona)) {
      return {
        score: 0,
        isInstantFail: true,
        failReason: `Instant fail: category ${finding.category} finding for ${persona} persona — ${finding.description}`,
        deductions,
      }
    }
  }

  let total = 0
  for (const finding of findings) {
    const base = BASE_DEDUCTION[finding.category]
    const amount = base * multiplier
    total += amount
    deductions.push({
      category: finding.category,
      amount,
      description: finding.description,
    })
  }

  return {
    score: Math.max(0, 10 - total),
    isInstantFail: false,
    deductions,
  }
}
