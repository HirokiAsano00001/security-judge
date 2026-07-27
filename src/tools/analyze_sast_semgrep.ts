import { execFile } from 'child_process'
import { isAbsolute, resolve as resolvePath } from 'path'
import {
  type JudgeContext,
  type Finding,
  type FindingCategory,
  type FindingSeverity,
  type Persona,
  BASE_DEDUCTION,
} from '../types/index.js'

/**
 * Semgrep-backed SAST engine.
 *
 * Wraps the Semgrep CLI (taint / data-flow analysis, thousands of registry rules,
 * multi-language) and maps its findings into the Judge's `Finding` model. This is the
 * SonarQube-class complement to the regex engine in `analyze_sast_deep`: instead of a
 * single-line pattern match, Semgrep tracks user input from source to a dangerous sink
 * (a `dataflow_trace`), which we surface as a CRITICAL, taint-confirmed finding.
 *
 * Execution strategy (first available wins):
 *   1. `semgrep` on PATH (native install)
 *   2. official Docker image `semgrep/semgrep`
 *   3. otherwise: graceful "unavailable" message (no throw), like the gitleaks fallback.
 */

const DEFAULT_CONFIG = 'auto'
const DEFAULT_TIMEOUT_MS = 300_000
const PER_RULE_TIMEOUT_SEC = '30'
const MAX_BUFFER = 128 * 1024 * 1024
const DOCKER_IMAGE = 'semgrep/semgrep'
const DOCKER_MOUNT = '/src'

export const ANALYZE_SAST_SEMGREP_SCHEMA = {
  type: 'object',
  properties: {
    sourcePath: {
      type: 'string',
      description: 'Root path of the source code to analyze with Semgrep',
    },
    config: {
      type: 'string',
      description:
        'Semgrep ruleset. Default "auto" (registry-selected rules; needs network). ' +
        'Also accepts packs like "p/security-audit", "p/owasp-top-ten", or a local rule path.',
    },
    timeoutMs: {
      type: 'number',
      description: 'Overall Semgrep timeout in milliseconds (default 300000).',
    },
  },
  required: ['sourcePath'],
}

// --- Semgrep JSON output types (defensive: metadata is a raw, rule-authored object) ---

interface SemgrepPosition {
  line?: number
  col?: number
}

interface SemgrepDataflowTrace {
  taint_source?: unknown
  intermediate_vars?: unknown[]
  taint_sink?: unknown
}

interface SemgrepMetadata {
  cwe?: string | string[]
  owasp?: string | string[]
  confidence?: string
  category?: string
  references?: string[]
  vulnerability_class?: string[]
  [key: string]: unknown
}

interface SemgrepExtra {
  message?: string
  severity?: string
  lines?: string
  metadata?: SemgrepMetadata
  dataflow_trace?: SemgrepDataflowTrace
}

interface SemgrepResult {
  check_id?: string
  path?: string
  start?: SemgrepPosition
  end?: SemgrepPosition
  extra?: SemgrepExtra
}

interface SemgrepError {
  message?: string
  level?: string
}

export interface SemgrepJson {
  results?: SemgrepResult[]
  errors?: SemgrepError[]
}

// --- Pure mapping helpers ---

function toArray(value: string | string[] | undefined): string[] {
  if (Array.isArray(value)) return value
  if (typeof value === 'string' && value.trim()) return [value]
  return []
}

/** Normalize "CWE-89: SQL Injection" → "CWE-89". */
function normalizeCwe(raw: string | string[] | undefined): string | undefined {
  for (const entry of toArray(raw)) {
    const m = entry.match(/CWE-\d+/i)
    if (m) return m[0].toUpperCase()
  }
  return undefined
}

/** Normalize "A03:2021 - Injection" / "A3:2021" → "A03:2021". */
function normalizeOwasp(raw: string | string[] | undefined): string | undefined {
  for (const entry of toArray(raw)) {
    const m = entry.match(/A(\d{1,2}):(\d{4})/i)
    if (m) {
      const num = m[1].padStart(2, '0')
      return `A${num}:${m[2]}`
    }
  }
  return undefined
}

function cweNumbers(raw: string | string[] | undefined): number[] {
  return toArray(raw)
    .flatMap((e) => Array.from(e.matchAll(/CWE-(\d+)/gi), (m) => Number(m[1])))
    .filter((n) => Number.isFinite(n))
}

const CRYPTO_SECRET_CWES = new Set([326, 327, 328, 330, 338, 916, 798])
const AUTH_SESSION_CWES = new Set([287, 306, 384, 522, 613, 640])

/** Map a Semgrep finding to a Judge scoring category (A/B/C/D). */
function categorize(owasp: string | undefined, cwes: number[]): FindingCategory {
  if (owasp?.startsWith('A06')) return 'D' // vulnerable/outdated components
  if (owasp?.startsWith('A02') || cwes.some((c) => CRYPTO_SECRET_CWES.has(c))) return 'C'
  if (owasp?.startsWith('A07') || cwes.some((c) => AUTH_SESSION_CWES.has(c))) return 'B'
  return 'A'
}

/** Map Semgrep severity string → Judge severity. Taint findings are elevated to CRITICAL. */
function mapSeverity(raw: string | undefined, hasTaint: boolean): FindingSeverity {
  if (hasTaint) return 'CRITICAL'
  switch ((raw ?? '').toUpperCase()) {
    case 'CRITICAL':
      return 'CRITICAL'
    case 'ERROR':
    case 'HIGH':
      return 'HIGH'
    case 'WARNING':
    case 'MEDIUM':
      return 'MEDIUM'
    default:
      return 'LOW'
  }
}

function mapConfidence(raw: string | undefined, hasTaint: boolean): 'HIGH' | 'MEDIUM' | 'LOW' {
  switch ((raw ?? '').toUpperCase()) {
    case 'HIGH':
      return 'HIGH'
    case 'MEDIUM':
      return 'MEDIUM'
    case 'LOW':
      return 'LOW'
    default:
      return hasTaint ? 'HIGH' : 'MEDIUM'
  }
}

function truncate(text: string, max: number): string {
  const clean = text.replace(/\s+/g, ' ').trim()
  return clean.length > max ? `${clean.slice(0, max - 1)}…` : clean
}

function traceLine(node: unknown): number | undefined {
  // taint_source / taint_sink are match_call_trace objects with a nested location.
  const loc = (node as { location?: SemgrepPosition })?.location
  return loc?.line
}

/**
 * Map a raw Semgrep JSON payload to Judge findings. Pure and side-effect free so it can
 * be unit-tested without invoking the Semgrep binary. Findings are de-duplicated on
 * (check_id, path, start line).
 */
export function parseSemgrepJson(json: unknown, persona: Persona): Finding[] {
  const results = (json as SemgrepJson)?.results
  if (!Array.isArray(results)) return []

  const findings: Finding[] = []
  const seen = new Set<string>()

  for (const r of results) {
    const path = r?.path ?? '<unknown>'
    const line = r?.start?.line ?? 0
    const checkId = r?.check_id ?? 'semgrep'
    const key = `${checkId}|${path}|${line}`
    if (seen.has(key)) continue
    seen.add(key)

    const extra = r?.extra ?? {}
    const meta = extra.metadata ?? {}
    const trace = extra.dataflow_trace
    const hasTaint =
      !!trace && (trace.taint_source !== undefined || trace.taint_sink !== undefined)

    const cwes = cweNumbers(meta.cwe)
    const owasp = normalizeOwasp(meta.owasp)
    const cweId = normalizeCwe(meta.cwe)
    const category = categorize(owasp, cwes)
    const severity = mapSeverity(extra.severity, hasTaint)
    const confidence = mapConfidence(meta.confidence, hasTaint)

    const message = truncate(extra.message ?? checkId, 300)
    const description = hasTaint
      ? `Taint-confirmed: ${message}`
      : message

    let evidence = `File: ${path}:${line}\nRule: ${checkId}`
    // Semgrep replaces `lines` with the literal "requires login" when unauthenticated —
    // don't surface that placeholder as if it were the offending code.
    if (extra.lines && extra.lines.trim().toLowerCase() !== 'requires login') {
      evidence += `\nCode: ${truncate(extra.lines, 200)}`
    }
    if (hasTaint) {
      const src = traceLine(trace!.taint_source)
      const sink = traceLine(trace!.taint_sink)
      const hops = Array.isArray(trace!.intermediate_vars)
        ? trace!.intermediate_vars.length
        : 0
      evidence += `\nData-flow: source@${src ?? '?'} → ${hops} hop(s) → sink@${sink ?? '?'}`
    }

    // Instant-fail only for a taint-confirmed, top-severity flow on higher-stakes personas.
    const isFail =
      hasTaint && severity === 'CRITICAL' && ['commercial', 'internal'].includes(persona)

    findings.push({
      severity,
      category,
      description,
      evidence,
      isFail,
      baseDeduction: BASE_DEDUCTION[category],
      toolName: 'analyze_sast_semgrep',
      owaspCategory: owasp,
      cweId,
      confidence,
    })
  }

  return findings
}

// --- Subprocess execution ---

interface RunnerResult {
  stdout: string
  code: number | null
  ok: boolean
}

function run(cmd: string, args: string[], timeoutMs: number): Promise<RunnerResult> {
  return new Promise((resolve) => {
    execFile(
      cmd,
      args,
      { encoding: 'utf-8', timeout: timeoutMs, maxBuffer: MAX_BUFFER },
      (err, stdout) => {
        const code =
          err && typeof (err as { code?: unknown }).code === 'number'
            ? ((err as { code: number }).code)
            : err
              ? null
              : 0
        resolve({ stdout: stdout ?? '', code, ok: !err })
      }
    )
  })
}

/** True if `<cmd> --version` runs successfully (used to detect semgrep / docker on PATH). */
async function isAvailable(cmd: string): Promise<boolean> {
  const res = await run(cmd, ['--version'], 10_000)
  // ENOENT surfaces as code === null with no stdout; a real version print returns 0.
  return res.ok || res.stdout.trim().length > 0
}

export type SemgrepRunMode = 'native' | 'docker' | null

export async function resolveSemgrepMode(): Promise<SemgrepRunMode> {
  if (await isAvailable('semgrep')) return 'native'
  if (await isAvailable('docker')) return 'docker'
  return null
}

function buildArgs(mode: 'native' | 'docker', absPath: string, config: string): { cmd: string; args: string[] } {
  // --dataflow-traces asks Semgrep to emit the source→sink path for taint findings.
  // The Pro engine populates `extra.dataflow_trace`; the OSS engine ignores the flag
  // and reports taint-mode rules at their declared severity instead.
  const scan = ['scan', '--config', config, '--json', '--dataflow-traces', '--quiet', '--timeout', PER_RULE_TIMEOUT_SEC]
  if (mode === 'native') {
    return { cmd: 'semgrep', args: [...scan, absPath] }
  }
  return {
    cmd: 'docker',
    args: ['run', '--rm', '-v', `${absPath}:${DOCKER_MOUNT}`, DOCKER_IMAGE, 'semgrep', ...scan, DOCKER_MOUNT],
  }
}

// --- Orchestration ---

export async function analyzeSastSemgrep(
  input: { sourcePath: string; config?: string; timeoutMs?: number },
  ctx: JudgeContext
): Promise<string> {
  const { sourcePath } = input
  const config = input.config ?? DEFAULT_CONFIG
  const timeoutMs = input.timeoutMs ?? DEFAULT_TIMEOUT_MS
  const absPath = isAbsolute(sourcePath) ? sourcePath : resolvePath(sourcePath)

  const mode = await resolveSemgrepMode()
  if (!mode) {
    return (
      'analyze_sast_semgrep: Semgrep is not available (no `semgrep` on PATH and no Docker). ' +
      'Install with `pipx install semgrep` or `pip install semgrep`, or install Docker to use the ' +
      '`semgrep/semgrep` image. SAST scan skipped.'
    )
  }

  const { cmd, args } = buildArgs(mode, absPath, config)
  const res = await run(cmd, args, timeoutMs)

  let parsed: SemgrepJson
  try {
    parsed = JSON.parse(res.stdout) as SemgrepJson
  } catch {
    // Exit code 2 = fatal error; anything else without JSON is also unusable.
    const detail = res.code === 2 ? 'Semgrep reported a fatal error.' : `exit code ${res.code}`
    return `analyze_sast_semgrep (${mode}): could not parse Semgrep output — ${detail} Scan produced no findings.`
  }

  const findings = parseSemgrepJson(parsed, ctx.persona)
  ctx.findings.push(...findings)

  const lines: string[] = []
  lines.push(`analyze_sast_semgrep (${mode}, config=${config}):`)
  lines.push(`Semgrep produced ${parsed.results?.length ?? 0} raw result(s), ${findings.length} finding(s) after dedup.`)

  const scanErrors = parsed.errors ?? []
  if (scanErrors.length > 0) {
    lines.push(`Semgrep reported ${scanErrors.length} scan error(s) (e.g., unparseable files) — findings above are still valid.`)
  }

  const taintCount = findings.filter((f) => f.description.startsWith('Taint-confirmed')).length
  if (taintCount > 0) {
    lines.push(`${taintCount} taint-confirmed data-flow vulnerability(ies) (source → sink).`)
  }

  for (const f of findings.slice(0, 50)) {
    lines.push(`[${f.category}] ${f.severity} (${f.confidence}): ${f.description}`)
  }
  if (findings.length > 50) {
    lines.push(`… and ${findings.length - 50} more finding(s).`)
  }

  return lines.join('\n')
}
