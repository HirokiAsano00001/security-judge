import { execFile } from 'child_process'
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

  const secrets = await runGitleaks(sourcePath)
  lines.push(`gitleaks found ${secrets.length} secret(s).`)

  for (const secret of secrets) {
    findings.push({
      severity: 'CRITICAL',
      category: 'C',
      description: `Hardcoded secret: ${secret.RuleID} — ${secret.Description}`,
      evidence: `File: ${secret.File}:${secret.StartLine}\nMatch: ${secret.Match}`,
      isFail: ['commercial', 'internal'].includes(ctx.persona),
      baseDeduction: 10,
      toolName: 'analyze_sast_deep',
      owaspCategory: 'A02:2021',
      cweId: 'CWE-798',
      confidence: 'HIGH',
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

async function runGitleaks(sourcePath: string): Promise<GitleaksSecret[]> {
  if (!existsSync(GITLEAKS_BIN)) return []

  const reportPath = join(tmpdir(), `gitleaks-report-${process.pid}.json`)
  try {
    await new Promise<void>((resolve, reject) => {
      execFile(GITLEAKS_BIN, [
        'detect',
        '--source', sourcePath,
        '--report-format', 'json',
        '--report-path', reportPath,
        '--no-git',
        '--exit-code', '0',
      ], { encoding: 'utf-8', timeout: 30000 }, (err) => {
        if (err) reject(err)
        else resolve()
      })
    })

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

interface DangerPattern {
  regex: RegExp
  desc: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM'
  category: 'A' | 'B' | 'C' | 'D'
  owaspCategory: string
  cweId: string
}

const DANGEROUS_PATTERNS: DangerPattern[] = [
  { regex: /\beval\s*\(/g, desc: 'eval() usage — arbitrary code execution risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-95' },
  { regex: /exec\s*\(\s*[`$]/, desc: 'Shell exec with string interpolation — command injection risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-78' },
  { regex: /ProcessBuilder|Runtime\.getRuntime\(\)\.exec/, desc: 'Java shell exec — command injection risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-78' },
  { regex: /os\.system\s*\(|subprocess\.call|subprocess\.Popen/, desc: 'Python shell exec — command injection risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-78' },

  // SQL injection
  { regex: /"SELECT\s+.+"\s*\+|'\s*\+\s*(id|user|name|query)\b/i, desc: 'SQL query built by string concatenation — injection risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-89' },
  { regex: /query\s*[+=]\s*["']?\s*(SELECT|INSERT|UPDATE|DELETE)/i, desc: 'SQL query string concatenation — injection risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-89' },
  { regex: /cursor\.execute\s*\(\s*["'][^"']*%s/, desc: 'Python DB query with %-format — SQLi risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-89' },

  // XSS
  { regex: /\.innerHTML\s*=(?!=)/, desc: 'innerHTML assignment without sanitization — XSS risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-79' },
  { regex: /document\.write\s*\(/, desc: 'document.write() — XSS risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-79' },
  { regex: /dangerouslySetInnerHTML/, desc: 'React dangerouslySetInnerHTML — XSS risk if unsanitized', severity: 'MEDIUM', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-79' },

  // Deserialization
  { regex: /pickle\.loads?\s*\(|marshal\.loads?\s*\(/, desc: 'Python pickle/marshal deserialization — arbitrary code execution', severity: 'CRITICAL', category: 'A', owaspCategory: 'A08:2021', cweId: 'CWE-502' },
  { regex: /yaml\.load\s*\([^,)]+\)(?!\s*,\s*Loader=yaml\.SafeLoader)/, desc: 'Unsafe YAML.load() — arbitrary code execution (use yaml.safe_load)', severity: 'HIGH', category: 'A', owaspCategory: 'A08:2021', cweId: 'CWE-502' },
  { regex: /ObjectInputStream|readObject\s*\(\)/, desc: 'Java object deserialization — remote code execution risk', severity: 'HIGH', category: 'A', owaspCategory: 'A08:2021', cweId: 'CWE-502' },

  // Weak crypto
  { regex: /createHash\s*\(\s*["']md5["']|createHash\s*\(\s*["']sha1["']/, desc: 'Weak hash algorithm (MD5/SHA1) — collision attacks possible', severity: 'MEDIUM', category: 'C', owaspCategory: 'A02:2021', cweId: 'CWE-327' },
  { regex: /MessageDigest\.getInstance\s*\(\s*["'](MD5|SHA-1)["']/, desc: 'Java weak hash (MD5/SHA-1)', severity: 'MEDIUM', category: 'C', owaspCategory: 'A02:2021', cweId: 'CWE-327' },
  { regex: /Math\.random\s*\(\s*\).*(?:token|session|key|secret|salt|nonce)/i, desc: 'Math.random() for security-sensitive value — use crypto.randomBytes()', severity: 'HIGH', category: 'C', owaspCategory: 'A02:2021', cweId: 'CWE-338' },

  // Prototype pollution
  { regex: /__proto__\s*=|Object\.assign\s*\(\s*\{\}|Object\.assign\s*\(\s*target/, desc: 'Potential prototype pollution — validate deep merge inputs', severity: 'MEDIUM', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-1321' },

  // Path traversal
  { regex: /path\.join\s*\([^)]*req\.(params|query|body)/, desc: 'path.join with user input — path traversal risk', severity: 'HIGH', category: 'A', owaspCategory: 'A01:2021', cweId: 'CWE-22' },
  { regex: /readFile(?:Sync)?\s*\([^)]*req\.(params|query|body)/, desc: 'fs.readFile with user input — path traversal risk', severity: 'HIGH', category: 'A', owaspCategory: 'A01:2021', cweId: 'CWE-22' },

  // JWT
  { regex: /jwt\.decode\s*\((?![^)]*,\s*\{)/, desc: 'JWT decoded without verification — authentication bypass', severity: 'HIGH', category: 'B', owaspCategory: 'A02:2021', cweId: 'CWE-345' },
  { regex: /algorithms\s*=\s*\[\s*["']none["']/, desc: 'JWT algorithm "none" accepted — signature bypass', severity: 'CRITICAL', category: 'B', owaspCategory: 'A02:2021', cweId: 'CWE-327' },

  // Open redirect
  { regex: /res\.redirect\s*\(\s*req\.(query|body|params)/, desc: 'Unvalidated redirect — open redirect risk', severity: 'MEDIUM', category: 'A', owaspCategory: 'A01:2021', cweId: 'CWE-601' },

  // CORS
  { regex: /Access-Control-Allow-Origin.*\*.*credentials.*true|credentials.*true.*Access-Control-Allow-Origin.*\*/i, desc: 'CORS wildcard with credentials=true — cross-origin auth bypass', severity: 'CRITICAL', category: 'A', owaspCategory: 'A05:2021', cweId: 'CWE-942' },

  // SSL verification
  { regex: /verify\s*=\s*False|ssl_verify\s*=\s*false|rejectUnauthorized\s*:\s*false/i, desc: 'SSL certificate verification disabled — MITM attacks possible', severity: 'HIGH', category: 'C', owaspCategory: 'A05:2021', cweId: 'CWE-295' },

  // Sensitive logging
  { regex: /console\.log\s*\([^)]*(?:password|token|secret|key)\b/i, desc: 'Sensitive data logged to console', severity: 'MEDIUM', category: 'C', owaspCategory: 'A09:2021', cweId: 'CWE-532' },

  // XXE
  { regex: /DocumentBuilderFactory|SAXParserFactory|XMLInputFactory/, desc: 'XML parser without disabling external entities — XXE risk', severity: 'HIGH', category: 'A', owaspCategory: 'A05:2021', cweId: 'CWE-611' },
  { regex: /etree\.fromstring|xml\.etree|lxml\.etree/, desc: 'Python XML parser — ensure external entity resolution disabled', severity: 'MEDIUM', category: 'A', owaspCategory: 'A05:2021', cweId: 'CWE-611' },

  // SSTI
  { regex: /template\.render\s*\([^)]*req\.(query|body|params)/, desc: 'Template rendered with user input — SSTI risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-94' },
  { regex: /Environment\(\)\.from_string\s*\(|jinja2\.Template\s*\(/, desc: 'Jinja2 template compiled from user input — SSTI risk', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-94' },

  // Go command injection
  { regex: /exec\.Command\s*\([^)]*fmt\.Sprintf|exec\.Command\s*\([^)]*\+/, desc: 'Go exec.Command with string concatenation — command injection', severity: 'HIGH', category: 'A', owaspCategory: 'A03:2021', cweId: 'CWE-78' },
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

      for (const pat of DANGEROUS_PATTERNS) {
        const r = new RegExp(pat.regex.source, pat.regex.flags.replace('g', '') + 'g')
        if (r.test(content)) {
          findings.push({
            severity: pat.severity,
            category: pat.category,
            description: pat.desc,
            evidence: `File: ${full}`,
            isFail: false,
            baseDeduction: 10,
            toolName: 'analyze_sast_deep',
            owaspCategory: pat.owaspCategory,
            cweId: pat.cweId,
            confidence: 'MEDIUM',
          })
        }
      }
    }
  }

  walk(sourcePath)
  return findings
}
