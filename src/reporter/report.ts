import { writeFileSync } from 'fs'
import { type JudgeContext, type SecurityReport, type Remediation } from '../types/index.js'
import { calculateScore } from '../scorer/rubric.js'

export function buildReport(ctx: JudgeContext): SecurityReport {
  const scoreResult = calculateScore(ctx.findings, ctx.persona)

  const remediations: Remediation[] = ctx.findings.map(f => ({
    findingCategory: f.category,
    before: f.evidence,
    after: 'Implement proper validation, authorization, or secret management.',
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
      lines.push(
        `### [${f.category}] ${f.severity}: ${f.description}`,
        `- Tool: ${f.toolName}`,
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
