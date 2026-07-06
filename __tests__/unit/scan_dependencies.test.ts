import { vi, describe, it, expect, beforeEach } from 'vitest'

vi.mock('child_process', () => ({
  execFile: vi.fn(),
}))

vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('fs')>()
  return {
    ...actual,
    existsSync: vi.fn(),
  }
})

import { execFile } from 'child_process'
import { existsSync } from 'fs'
import { scanDependencies } from '../../src/tools/scan_dependencies.js'
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

const MOCK_NPM_AUDIT = JSON.stringify({
  metadata: { vulnerabilities: { critical: 1, high: 2, moderate: 1, low: 0, info: 0 } },
  vulnerabilities: {
    'lodash': {
      name: 'lodash',
      severity: 'high',
      isDirect: true,
      range: '<4.17.21',
      fixAvailable: true,
      via: [{ title: 'Prototype Pollution', url: 'https://npmjs.com/advisories/1523', cwe: ['CWE-1321'] }],
    },
    'axios': {
      name: 'axios',
      severity: 'critical',
      isDirect: true,
      range: '<1.6.0',
      fixAvailable: { name: 'axios', version: '1.6.0', isSemVerMajor: false },
      via: [{ title: 'SSRF vulnerability', cwe: ['CWE-918'] }],
    },
  },
})

function mockExecFileSuccess(output: string) {
  vi.mocked(execFile).mockImplementation((_cmd: unknown, _args: unknown, _opts: unknown, callback: unknown) => {
    (callback as (err: null, stdout: string, stderr: string) => void)(null, output, '')
    return undefined as never
  })
}

function mockExecFileError(message: string) {
  vi.mocked(execFile).mockImplementation((_cmd: unknown, _args: unknown, _opts: unknown, callback: unknown) => {
    (callback as (err: Error, stdout: string, stderr: string) => void)(new Error(message), '', '')
    return undefined as never
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('scanDependencies', () => {
  it('skips when no package.json or lock file found', async () => {
    vi.mocked(existsSync).mockReturnValue(false)
    const ctx = makeCtx()
    const result = await scanDependencies({ sourcePath: '/no/project' }, ctx)
    expect(result).toContain('No package.json')
    expect(ctx.findings).toHaveLength(0)
  })

  it('suggests running npm install when package.json exists but no lock file', async () => {
    vi.mocked(existsSync).mockImplementation((p) => String(p).endsWith('package.json'))
    const ctx = makeCtx()
    const result = await scanDependencies({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('npm install')
  })

  it('creates findings from npm audit output', async () => {
    vi.mocked(existsSync).mockReturnValue(true)
    mockExecFileSuccess(MOCK_NPM_AUDIT)
    const ctx = makeCtx()
    await scanDependencies({ sourcePath: '/some/project' }, ctx)
    expect(ctx.findings.length).toBeGreaterThan(0)
    const lodashFinding = ctx.findings.find(f => f.description.includes('lodash'))
    expect(lodashFinding).toBeDefined()
    expect(lodashFinding?.severity).toBe('HIGH')
    expect(lodashFinding?.owaspCategory).toBe('A06:2021')
  })

  it('marks critical direct dependencies as isFail', async () => {
    vi.mocked(existsSync).mockReturnValue(true)
    mockExecFileSuccess(MOCK_NPM_AUDIT)
    const ctx = makeCtx()
    await scanDependencies({ sourcePath: '/some/project' }, ctx)
    const criticalFinding = ctx.findings.find(f => f.severity === 'CRITICAL')
    expect(criticalFinding).toBeDefined()
    expect(criticalFinding?.isFail).toBe(true)
  })

  it('handles npm not found gracefully', async () => {
    vi.mocked(existsSync).mockReturnValue(true)
    mockExecFileError('ENOENT: npm not found')
    const ctx = makeCtx()
    const result = await scanDependencies({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('npm not found')
    expect(ctx.findings).toHaveLength(0)
  })

  it('returns summary string', async () => {
    vi.mocked(existsSync).mockReturnValue(true)
    mockExecFileSuccess(MOCK_NPM_AUDIT)
    const ctx = makeCtx()
    const result = await scanDependencies({ sourcePath: '/some/project' }, ctx)
    expect(result).toContain('scan_dependencies')
    expect(result).toContain('Findings:')
  })
})
