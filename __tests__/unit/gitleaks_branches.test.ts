import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'

type GitleaksBehavior = 'bin-missing' | 'report-missing' | 'report-empty' | 'exec-throws'
let behavior: GitleaksBehavior = 'report-missing'

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs')
  return {
    ...actual,
    existsSync: vi.fn((p: unknown) => {
      const ps = String(p)
      // Fake gitleaks binary as existing (path ends with gitleaks or gitleaks.exe, not a report)
      if (
        (ps.endsWith('gitleaks.exe') || ps.endsWith('/gitleaks') || ps.endsWith('\\gitleaks')) &&
        !ps.includes('gitleaks-report-')
      ) {
        return behavior !== 'bin-missing'
      }
      // Report file: exists only in report-empty mode
      if (ps.includes('gitleaks-report-')) {
        return behavior === 'report-empty'
      }
      return actual.existsSync(p as never)
    }),
    readFileSync: vi.fn((p: unknown, options?: unknown) => {
      if (String(p).includes('gitleaks-report-') && behavior === 'report-empty') {
        return ''
      }
      return actual.readFileSync(p as never, options as never)
    }),
    unlinkSync: vi.fn(),
  }
})

vi.mock('child_process', () => ({
  execFile: vi.fn((_cmd: unknown, _args: unknown, _opts: unknown, callback: (err: Error | null) => void) => {
    if (behavior === 'exec-throws') {
      callback(new Error('gitleaks execution failed'))
    } else {
      callback(null)
    }
    return undefined as never
  }),
}))

import { mkdirSync, rmSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { analyzeSastDeep } from '../../src/tools/analyze_sast_deep.js'
import { type JudgeContext } from '../../src/types/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const TMP = join(__dirname, '../.tmp-gitleaks')

function makeCtx(): JudgeContext {
  return {
    persona: 'commercial',
    penaltyMultiplier: 1.0,
    targetBaseUrl: 'http://localhost:8080',
    allowedUrls: ['http://localhost:8080'],
    hasLlmChat: false,
    endpoints: [],
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

describe('runGitleaks branch coverage', () => {
  beforeEach(() => {
    mkdirSync(TMP, { recursive: true })
  })

  afterEach(() => {
    try { rmSync(TMP, { recursive: true, force: true }) } catch { /* ignore */ }
  })

  it('returns [] when gitleaks binary does not exist', async () => {
    behavior = 'bin-missing'
    const ctx = makeCtx()
    const result = await analyzeSastDeep({ sourcePath: TMP }, ctx)
    expect(result).toContain('gitleaks found 0 secret(s).')
  })

  it('returns [] when report file does not exist after execFile', async () => {
    behavior = 'report-missing'
    const ctx = makeCtx()
    const result = await analyzeSastDeep({ sourcePath: TMP }, ctx)
    expect(result).toContain('gitleaks found 0 secret(s).')
  })

  it('returns [] when report file is empty', async () => {
    behavior = 'report-empty'
    const ctx = makeCtx()
    const result = await analyzeSastDeep({ sourcePath: TMP }, ctx)
    expect(result).toContain('gitleaks found 0 secret(s).')
  })

  it('returns [] when execFile throws', async () => {
    behavior = 'exec-throws'
    const ctx = makeCtx()
    const result = await analyzeSastDeep({ sourcePath: TMP }, ctx)
    expect(result).toContain('gitleaks found 0 secret(s).')
  })
})
