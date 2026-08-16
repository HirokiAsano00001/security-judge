import { writeFileSync } from 'fs'
import { type JudgeContext, type SecurityReport, type Remediation } from '../types/index.js'
import { calculateScore } from '../scorer/rubric.js'

// OWASP-aware remediation guidance. LLM Top-10 categories get LLM-specific advice
// so the report is actionable for AI findings, not just classic AppSec ones.
const REMEDIATION_BY_OWASP: Record<string, string> = {
  LLM01: 'Enforce a strict instruction/data boundary: treat retrieved content and tool output as untrusted, use delimiters + system-role separation, and validate that user/data input cannot override system instructions.',
  LLM02: 'Never expose secrets or other users\' data to the model context; apply output filtering/DLP, scope credentials per request, and redact PII before it reaches the LLM.',
  LLM06: 'Constrain agent authority: allowlist tools, require human/authorization checks for state-changing or outbound calls, and never let model output directly trigger network egress to arbitrary URLs.',
  LLM07: 'Assume the system prompt is not secret; move secrets/policy enforcement server-side, and add output checks that block verbatim system-prompt disclosure.',
  LLM09: 'Add grounding/citation and uncertainty handling; verify factual claims against authoritative sources and label unverifiable answers instead of fabricating.',
  LLM10: 'Enforce output/token caps, per-user rate limits, and timeouts; reject or truncate requests that demand unbounded generation.',
}

function remediationFor(owasp: string | undefined): string {
  return (owasp && REMEDIATION_BY_OWASP[owasp]) ?? 'Implement proper validation, authorization, or secret management.'
}

export function buildReport(ctx: JudgeContext): SecurityReport {
  const scoreResult = calculateScore(ctx.findings, ctx.persona)

  const remediations: Remediation[] = ctx.findings.map(f => ({
    findingCategory: f.category,
    before: f.evidence,
    after: remediationFor(f.owaspCategory),
    description: f.description,
  }))

  return {
    timestamp: new Date().toISOString(),
    persona: ctx.persona,
    targetBaseUrl: ctx.targetBaseUrl,
    score: scoreResult.score,
    findings: ctx.findings,
    remediations,
  }
}

export function formatReport(report: SecurityReport): string {
  const lines: string[] = [
    '# Security Judge Report',
    '',
    `**Timestamp**: ${report.timestamp}`,
    `**Target**: ${report.targetBaseUrl}`,
    `**Persona**: ${report.persona}`,
    `**Score**: ${report.score.toFixed(1)} / 10`,
    '',
  ]

  if (report.findings.length === 0) {
    lines.push('No findings detected.')
  } else {
    lines.push(`## Findings (${report.findings.length})`, '')
    for (const f of report.findings) {
      const tags = [
        f.owaspCategory ? `OWASP ${f.owaspCategory}` : '',
        f.cweId ?? '',
        f.confidence ? `confidence ${f.confidence}` : '',
      ].filter(Boolean).join(' · ')
      lines.push(
        `### [${f.category}] ${f.severity}: ${f.description}`,
        `- Tool: ${f.toolName}`,
        tags ? `- ${tags}` : '',
        `- Base deduction: ${f.baseDeduction}pt`,
        `- Instant fail: ${f.isFail}`,
        '```',
        f.evidence,
        '```',
        '',
      )
    }
  }

  if (report.remediations.length > 0) {
    lines.push('## Remediations', '')
    for (const r of report.remediations) {
      lines.push(
        `### [${r.findingCategory}] ${r.description}`,
        r.filePath ? `File: ${r.filePath}${r.lineNumber ? `:${r.lineNumber}` : ''}` : '',
        '```diff',
        `- ${r.before}`,
        `+ ${r.after}`,
        '```',
        '',
      )
    }
  }

  return lines.join('\n')
}

export function saveReport(report: SecurityReport, outputPath: string): void {
  const content = formatReport(report)
  writeFileSync(outputPath, content, 'utf-8')
}
