import { type JudgeContext, type Finding } from '../types/index.js'
import { analyzeFiles } from '../sast/taint/analyze.js'
import { flowToFinding, dedupeFlows } from '../sast/taint/finding.js'

/**
 * Built-in, zero-dependency taint SAST for TS/JS. Uses the TypeScript Compiler API to
 * track attacker-controlled input (req.query/body/params/…) from source to a dangerous
 * sink (SQL/exec/eval/innerHTML/fs/redirect/template) within a single file. Runs fully
 * offline — the confident SAST fallback when Semgrep is unavailable.
 */
export const ANALYZE_TAINT_SCHEMA = {
  type: 'object',
  properties: {
    sourcePath: {
      type: 'string',
      description: 'Root path of the TS/JS source to analyze for taint flows',
    },
  },
  required: ['sourcePath'],
}

export async function analyzeTaint(
  input: { sourcePath: string },
  ctx: JudgeContext
): Promise<string> {
  const flows = dedupeFlows(analyzeFiles(input.sourcePath))
  const findings: Finding[] = flows.map((f) => flowToFinding(f, ctx.persona))
  ctx.findings.push(...findings)

  const lines: string[] = []
  lines.push(`analyze_taint: built-in TS/JS taint analysis — ${findings.length} taint-confirmed flow(s).`)
  for (const f of findings.slice(0, 50)) {
    lines.push(`[${f.category}] ${f.severity} (${f.confidence}): ${f.description}`)
  }
  if (findings.length > 50) {
    lines.push(`… and ${findings.length - 50} more finding(s).`)
  }
  return lines.join('\n')
}
