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

const SEVERITY_WEIGHT: Record<string, number> = {
  CRITICAL: 1.0,
  HIGH: 0.6,
  MEDIUM: 0.3,
  LOW: 0.1,
}

const CONFIDENCE_WEIGHT: Record<string, number> = {
  HIGH: 1.0,
  MEDIUM: 0.6,
  LOW: 0.2,
}

export function calculateScore(findings: Finding[], persona: Persona): ScoreResult {
  const multiplier = PENALTY_MULTIPLIER[persona]
  const deductions: ScoreResult['deductions'] = []

  // Instant fail only for HIGH/MEDIUM confidence isFail findings.
  // LOW confidence findings (e.g., unconfirmed SSTI, noisy BOLA) never trigger instant-fail.
  for (const finding of findings) {
    const conf = finding.confidence ?? 'HIGH'
    if (conf === 'LOW') continue
    if (!finding.isFail) continue
    const failPersonas = INSTANT_FAIL_PERSONAS[finding.category]
    if (failPersonas.includes(persona)) {
      return {
        score: 0,
        isInstantFail: true,
        failReason: `Instant fail [${conf} confidence]: ${finding.description}`,
        deductions,
      }
    }
  }

  let total = 0
  for (const finding of findings) {
    const base = BASE_DEDUCTION[finding.category]
    const sevWeight = SEVERITY_WEIGHT[finding.severity] ?? 1.0
    const confWeight = CONFIDENCE_WEIGHT[finding.confidence ?? 'HIGH'] ?? 1.0
    const amount = base * multiplier * sevWeight * confWeight
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
