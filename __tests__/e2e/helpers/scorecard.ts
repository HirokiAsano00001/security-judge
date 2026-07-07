import { type Finding } from '../../../src/types/index.js'

export interface VulnSpec {
  id: string
  weight: number
  label: string
  detect: (findings: Finding[]) => boolean
}

function has(findings: Finding[], pred: (f: Finding) => boolean): boolean {
  return findings.some(pred)
}

function text(f: Finding): string {
  return `${f.description} ${f.evidence}`.toLowerCase()
}

// Ground-truth vulnerabilities planted in test/target-app/server.js (8 total, weight 100).
export const GROUND_TRUTH: VulnSpec[] = [
  {
    id: 'V2_idor',
    weight: 15,
    label: 'IDOR/BOLA on /api/users/:id',
    detect: f => has(f, x => x.toolName === 'test_bola_idor'),
  },
  {
    id: 'V3_privesc',
    weight: 15,
    label: 'Privilege escalation on /api/users/:id/role',
    detect: f => has(f, x => x.toolName === 'test_privilege_escalation'),
  },
  {
    id: 'V4_ssrf',
    weight: 15,
    label: 'SSRF on /api/fetch',
    detect: f => has(f, x => x.toolName === 'test_ssrf'),
  },
  {
    id: 'V5_jailbreak',
    weight: 15,
    label: 'System-prompt leak on /api/chat',
    detect: f => has(f, x => x.toolName === 'inject_llm_jailbreak'),
  },
  {
    id: 'V1_actuator',
    weight: 10,
    label: 'Exposed /actuator/env leaking API key',
    // Bound to the endpoint-scan tool AND the specific exposed path (no generic token match).
    detect: f => has(f, x => x.toolName === 'scan_exposed_endpoints' && /actuator|\/env\b/.test(text(x))),
  },
  {
    id: 'V7_hardcoded_secret',
    weight: 10,
    label: 'Hardcoded API key in source',
    detect: f =>
      has(f, x => x.toolName === 'analyze_sast_deep' && x.cweId === 'CWE-798'),
  },
  {
    id: 'V6_stacktrace',
    weight: 10,
    label: 'Stack-trace / verbose error leak on /api/login',
    // Must be a genuine stack-trace finding from the fuzzer (CWE-209), not any 500.
    detect: f =>
      has(f, x => x.toolName === 'fuzz_api_direct' && (x.cweId === 'CWE-209' || /stack trace exposed/.test(text(x)))),
  },
  {
    id: 'V8_mass_assignment',
    weight: 10,
    label: 'Mass assignment on /api/users/:id/update',
    detect: f =>
      has(f, x => x.toolName === 'analyze_sast_deep' && x.cweId === 'CWE-915'),
  },
]

export interface Scorecard {
  score: number
  detected: string[]
  missed: string[]
  breakdown: Array<{ id: string; label: string; weight: number; detected: boolean }>
  totalFindings: number
}

export function evaluate(findings: Finding[]): Scorecard {
  const breakdown = GROUND_TRUTH.map(v => ({
    id: v.id,
    label: v.label,
    weight: v.weight,
    detected: v.detect(findings),
  }))
  const score = breakdown.reduce((s, b) => s + (b.detected ? b.weight : 0), 0)
  return {
    score,
    detected: breakdown.filter(b => b.detected).map(b => b.id),
    missed: breakdown.filter(b => !b.detected).map(b => b.id),
    breakdown,
    totalFindings: findings.length,
  }
}

export function formatScorecard(sc: Scorecard): string {
  const lines = [`Detection score: ${sc.score}/100  (findings: ${sc.totalFindings})`]
  for (const b of sc.breakdown) {
    lines.push(`  [${b.detected ? 'x' : ' '}] ${b.id} (${b.weight}) — ${b.label}`)
  }
  return lines.join('\n')
}
