import { execFile } from 'child_process'
import { existsSync } from 'fs'
import { join } from 'path'
import { type JudgeContext, type Finding } from '../types/index.js'

function runNpmAudit(cwd: string): Promise<string> {
  const npmCmd = process.platform === 'win32' ? 'npm.cmd' : 'npm'
  return new Promise((resolve, reject) => {
    execFile(npmCmd, ['audit', '--json'], { cwd, encoding: 'utf-8', timeout: 60000 },
      (err, stdout) => {
        // npm audit exits with code 1 when vulnerabilities are found — stdout still has JSON
        if (err && !stdout) reject(err)
        else resolve(stdout)
      }
    )
  })
}

export const SCAN_DEPENDENCIES_SCHEMA = {
  type: 'object',
  properties: {
    sourcePath: {
      type: 'string',
      description: 'Root path of the project to audit (must contain package-lock.json)',
    },
  },
  required: ['sourcePath'],
}

interface NpmAuditVulnerability {
  name: string
  severity: 'info' | 'low' | 'moderate' | 'high' | 'critical'
  isDirect: boolean
  range: string
  fixAvailable: boolean | { name: string; version: string; isSemVerMajor: boolean }
  via: Array<{ title?: string; url?: string; cwe?: string[] }>
}

interface NpmAuditReport {
  metadata?: { vulnerabilities?: Record<string, number> }
  vulnerabilities?: Record<string, NpmAuditVulnerability>
}

function mapNpmSeverity(severity: string): 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' {
  switch (severity) {
    case 'critical': return 'CRITICAL'
    case 'high': return 'HIGH'
    case 'moderate': return 'MEDIUM'
    default: return 'LOW'
  }
}

export async function scanDependencies(
  input: { sourcePath: string },
  ctx: JudgeContext
): Promise<string> {
  const { sourcePath } = input
  const findings: Finding[] = []
  const lines: string[] = []

  const lockFile = join(sourcePath, 'package-lock.json')
  const packageJson = join(sourcePath, 'package.json')

  if (!existsSync(lockFile)) {
    const hasPackageJson = existsSync(packageJson)
    lines.push(hasPackageJson
      ? 'package.json found but package-lock.json missing — run npm install first to generate lock file'
      : 'No package.json or package-lock.json found — npm dependency scan skipped'
    )
    return `scan_dependencies: ${lines[0]}`
  }

  try {
    const output = await runNpmAudit(sourcePath)
    const report: NpmAuditReport = JSON.parse(output)
    const vulnerabilities = report.vulnerabilities ?? {}
    const meta = report.metadata?.vulnerabilities ?? {}

    const totalCount = Object.values(meta).reduce((acc, n) => acc + (n as number), 0)
    lines.push(`npm audit: ${totalCount} vulnerabilities found`)
    lines.push(`  critical: ${meta['critical'] ?? 0}, high: ${meta['high'] ?? 0}, moderate: ${meta['moderate'] ?? 0}, low: ${meta['low'] ?? 0}`)

    for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
      if (vuln.severity === 'info') continue

      const cves = vuln.via.flatMap(v => v.cwe ?? []).join(', ')
      const urls = vuln.via.flatMap(v => v.url ? [v.url] : []).join(', ')
      const titles = vuln.via.flatMap(v => v.title ? [v.title] : []).join('; ')
      const fixable = vuln.fixAvailable
        ? typeof vuln.fixAvailable === 'object'
          ? `fix available via ${vuln.fixAvailable.name}@${vuln.fixAvailable.version}`
          : 'fix available (npm audit fix)'
        : 'no fix available'

      findings.push({
        severity: mapNpmSeverity(vuln.severity),
        category: 'D',
        description: `Vulnerable dependency: ${pkgName}@${vuln.range}${titles ? ` — ${titles}` : ''}`,
        evidence: `Package: ${pkgName}\nSeverity: ${vuln.severity}\nRange: ${vuln.range}\nDirect: ${vuln.isDirect}\n${cves ? `CWE: ${cves}\n` : ''}${urls ? `Advisory: ${urls}\n` : ''}Fix: ${fixable}`,
        isFail: vuln.severity === 'critical' && vuln.isDirect,
        baseDeduction: 5,
        toolName: 'scan_dependencies',
        owaspCategory: 'A06:2021',
        cweId: cves.split(',')[0]?.trim() || 'CWE-1035',
        confidence: 'HIGH',
      })
    }
  } catch (err) {
    const errMsg = (err as Error).message
    if (errMsg.includes('ENOENT')) {
      lines.push('npm not found — install Node.js to enable dependency scanning')
    } else if (errMsg.includes('JSON')) {
      lines.push('npm audit returned non-JSON output — project may have no lock file')
    } else {
      lines.push(`npm audit failed: ${errMsg.slice(0, 200)}`)
    }
  }

  ctx.findings.push(...findings)
  return `scan_dependencies:\n${lines.join('\n')}\nFindings: ${findings.length}`
}
