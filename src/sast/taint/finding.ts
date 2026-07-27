import {
  type Finding,
  type Persona,
  type FindingCategory,
  BASE_DEDUCTION,
} from '../../types/index.js'
import { type Flow, type VulnKind } from './types.js'

const VULN_NAME: Record<VulnKind, string> = {
  SQLI: 'SQL injection',
  RCE: 'remote code execution',
  XSS: 'cross-site scripting',
  PATH_TRAVERSAL: 'path traversal',
  OPEN_REDIRECT: 'open redirect',
  SSTI: 'server-side template injection',
}

/**
 * Convert a confirmed taint Flow into a Judge Finding. Mirrors the taint contract in
 * `parseSemgrepJson` (analyze_sast_semgrep): CRITICAL severity, "Taint-confirmed:"
 * description, a `Data-flow: source@L → N hop(s) → sink@L` evidence line, and
 * instant-fail only for high-stakes personas.
 */
export function flowToFinding(flow: Flow, persona: Persona): Finding {
  const { sink, prov, sinkLine, fileName } = flow
  const category: FindingCategory = sink.category
  const hops = prov.hops.length
  const evidence =
    `File: ${fileName}:${sinkLine}\n` +
    `Sink: ${sink.label} (${sink.cweId})\n` +
    `Data-flow: source@${prov.sourceLine} → ${hops} hop(s) → sink@${sinkLine}`

  return {
    severity: 'CRITICAL',
    category,
    description: `Taint-confirmed: ${prov.sourceLabel} flows into ${sink.label} (${VULN_NAME[sink.vulnKind]})`,
    evidence,
    isFail: ['commercial', 'internal'].includes(persona),
    baseDeduction: BASE_DEDUCTION[category],
    toolName: 'analyze_taint',
    owaspCategory: sink.owaspCategory,
    cweId: sink.cweId,
    confidence: 'HIGH',
  }
}

/** De-duplicate flows on (file, sink line, vulnerability kind). */
export function dedupeFlows(flows: readonly Flow[]): Flow[] {
  const seen = new Set<string>()
  const out: Flow[] = []
  for (const f of flows) {
    const key = `${f.fileName}|${f.sinkLine}|${f.sink.vulnKind}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(f)
  }
  return out
}
