import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('child_process', () => ({
  execFile: vi.fn(),
}))

import { execFile } from 'child_process'
import { analyzeSastSemgrep, resolveSemgrepMode } from '../../src/tools/analyze_sast_semgrep.js'
import { type JudgeContext } from '../../src/types/index.js'

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

const SEMGREP_JSON = JSON.stringify({
  results: [
    {
      check_id: 'javascript.express.sqli',
      path: '/src/routes/user.js',
      start: { line: 42, col: 3 },
      end: { line: 42, col: 60 },
      extra: {
        message: 'Tainted SQL string',
        severity: 'ERROR',
        metadata: { cwe: ['CWE-89'], owasp: ['A03:2021 - Injection'], confidence: 'HIGH' },
        dataflow_trace: {
          taint_source: { location: { line: 40 } },
          intermediate_vars: [],
          taint_sink: { location: { line: 42 } },
        },
      },
    },
  ],
  errors: [],
})

type ExecCb = (err: (Error & { code?: number }) | null, stdout: string, stderr: string) => void

/**
 * Route the mocked execFile by command name:
 *  - `semgrep --version` / `docker --version` → availability probe
 *  - `semgrep scan ...` / `docker run ...` → scan output
 */
function mockExec(opts: {
  semgrepAvailable?: boolean
  dockerAvailable?: boolean
  scanStdout?: string
  scanErrorCode?: number
}) {
  vi.mocked(execFile).mockImplementation((cmd: unknown, args: unknown, _o: unknown, cb: unknown) => {
    const callback = cb as ExecCb
    const argv = args as string[]
    const isVersion = argv[0] === '--version'
    const enoent = () => {
      const e = new Error('spawn ENOENT') as Error & { code?: number }
      callback(e, '', '')
    }

    if (cmd === 'semgrep' && isVersion) {
      opts.semgrepAvailable ? callback(null, '1.90.0\n', '') : enoent()
    } else if (cmd === 'docker' && isVersion) {
      opts.dockerAvailable ? callback(null, 'Docker version 28\n', '') : enoent()
    } else {
      // scan invocation (semgrep scan ... OR docker run ...)
      if (opts.scanErrorCode !== undefined) {
        const e = new Error('semgrep failed') as Error & { code?: number }
        e.code = opts.scanErrorCode
        callback(e, opts.scanStdout ?? '', '')
      } else {
        callback(null, opts.scanStdout ?? '{"results":[],"errors":[]}', '')
      }
    }
    return undefined as never
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('analyzeSastSemgrep', () => {
  it('reports gracefully when neither semgrep nor docker is available', async () => {
    mockExec({ semgrepAvailable: false, dockerAvailable: false })
    const ctx = makeCtx()
    const result = await analyzeSastSemgrep({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('not available')
    expect(ctx.findings).toHaveLength(0)
  })

  it('runs via native semgrep and pushes taint findings into ctx', async () => {
    mockExec({ semgrepAvailable: true, scanStdout: SEMGREP_JSON })
    const ctx = makeCtx()
    const result = await analyzeSastSemgrep({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('native')
    expect(result).toContain('taint-confirmed')
    expect(ctx.findings).toHaveLength(1)
    expect(ctx.findings[0].severity).toBe('CRITICAL')
    expect(ctx.findings[0].isFail).toBe(true)
  })

  it('treats semgrep exit code 1 (findings found) as success, not failure', async () => {
    mockExec({ semgrepAvailable: true, scanStdout: SEMGREP_JSON, scanErrorCode: 1 })
    const ctx = makeCtx()
    await analyzeSastSemgrep({ sourcePath: '/some/project' }, ctx)
    expect(ctx.findings).toHaveLength(1)
  })

  it('falls back to docker when semgrep is absent', async () => {
    mockExec({ semgrepAvailable: false, dockerAvailable: true, scanStdout: SEMGREP_JSON })
    const ctx = makeCtx()
    const result = await analyzeSastSemgrep({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('docker')
    expect(ctx.findings).toHaveLength(1)
  })

  it('handles a fatal semgrep error (exit 2, no JSON) without throwing', async () => {
    mockExec({ semgrepAvailable: true, scanStdout: 'traceback...', scanErrorCode: 2 })
    const ctx = makeCtx()
    const result = await analyzeSastSemgrep({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('fatal error')
    expect(ctx.findings).toHaveLength(0)
  })

  it('resolveSemgrepMode returns null when nothing is installed', async () => {
    mockExec({ semgrepAvailable: false, dockerAvailable: false })
    expect(await resolveSemgrepMode()).toBeNull()
  })
})
