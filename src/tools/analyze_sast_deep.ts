import { execFileSync } from 'child_process'
import { existsSync, readdirSync, readFileSync, unlinkSync } from 'fs'
import { join, dirname } from 'path'
import { tmpdir } from 'os'
import { fileURLToPath } from 'url'
import { type JudgeContext, type Finding, type GitleaksSecret } from '../types/index.js'
import { extractEndpoints } from '../recon/endpoint_extractor.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const GITLEAKS_BIN = join(__dirname, '..', '..', 'bin', process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks')

export const ANALYZE_SAST_DEEP_SCHEMA = {
  type: 'object',
  properties: {
    sourcePath: {
      type: 'string',
      description: 'Root path of the source code to analyze',
    },
  },
  required: ['sourcePath'],
}

export async function analyzeSastDeep(
  input: { sourcePath: string },
  ctx: JudgeContext
): Promise<string> {
  const { sourcePath } = input
  const findings: Finding[] = []
  const lines: string[] = []

  const endpoints = await extractEndpoints(sourcePath)
  ctx.endpoints.push(...endpoints)
  lines.push(`Extracted ${endpoints.length} endpoint(s) from source code.`)

  const secrets = runGitleaks(sourcePath)
  lines.push(`gitleaks found ${secrets.length} secret(s).`)

  for (const secret of secrets) {
    findings.push({
      severity: 'CRITICAL',
      category: 'C',
      description: `Hardcoded secret detected: ${secret.RuleID} — ${secret.Description}`,
      evidence: `File: ${secret.File}:${secret.StartLine}\nMatch: ${secret.Match}`,
      isFail: ['commercial', 'internal'].includes(ctx.persona),
      baseDeduction: 10,
      toolName: 'analyze_sast_deep',
    })
  }

  const dangerousFindings = scanDangerousPatterns(sourcePath)
  findings.push(...dangerousFindings)

  ctx.findings.push(...findings)
  lines.push(`Total findings: ${findings.length}`)

  for (const f of findings) {
    lines.push(`[${f.category}] ${f.severity}: ${f.description}`)
  }

  return lines.join('\n')
}

function runGitleaks(sourcePath: string): GitleaksSecret[] {
  if (!existsSync(GITLEAKS_BIN)) return []

  const reportPath = join(tmpdir(), `gitleaks-report-${process.pid}.json`)
  try {
    execFileSync(GITLEAKS_BIN, [
      'detect',
      '--source', sourcePath,
      '--report-format', 'json',
      '--report-path', reportPath,
      '--no-git',
      '--exit-code', '0',
    ], { encoding: 'utf-8', timeout: 30000 })

    if (!existsSync(reportPath)) return []
    const content = readFileSync(reportPath, 'utf-8')
    if (!content.trim()) return []
    const all = JSON.parse(content) as GitleaksSecret[]
    return all.filter(s => !GITLEAKS_IGNORE_DIRS.some(d => s.File.includes(`/${d}/`) || s.File.includes(`\\${d}\\`)))
  } catch {
    return []
  } finally {
    try { unlinkSync(reportPath) } catch { /* ignore */ }
  }
}

const DANGEROUS_PATTERNS: Array<{ regex: RegExp; desc: string }> = [
  { regex: /\beval\s*\(/g, desc: 'eval() usage detected' },
  { regex: /exec\s*\(\s*[`$]/, desc: 'shell exec with interpolation' },
  { regex: /ProcessBuilder|Runtime\.getRuntime\(\)\.exec/, desc: 'Java shell exec' },
  { regex: /os\.system\s*\(|subprocess\.call/, desc: 'Python shell exec' },
]

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'target', '__pycache__', 'vendor'])
const GITLEAKS_IGNORE_DIRS = ['node_modules', 'vendor', 'dist', 'target', '.git']
const SOURCE_EXTS = new Set(['ts', 'js', 'java', 'py', 'go', 'rb'])

function scanDangerousPatterns(sourcePath: string): Finding[] {
  const findings: Finding[] = []

  function walk(dir: string): void {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }

    for (const entry of entries) {
      const full = join(dir, entry.name)

      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full)
        continue
      }

      if (!entry.isFile()) continue
      const ext = entry.name.split('.').pop() ?? ''
      if (!SOURCE_EXTS.has(ext)) continue

      let content: string
      try {
        content = readFileSync(full, 'utf-8')
      } catch {
        continue
      }

      for (const { regex, desc } of DANGEROUS_PATTERNS) {
        const r = new RegExp(regex.source, regex.flags.replace('g', '') + 'g')
        if (r.test(content)) {
          findings.push({
            severity: 'HIGH',
            category: 'A',
            description: desc,
            evidence: `File: ${full}`,
            isFail: false,
            baseDeduction: 10,
            toolName: 'analyze_sast_deep',
          })
        }
      }
    }
  }

  walk(sourcePath)
  return findings
}
