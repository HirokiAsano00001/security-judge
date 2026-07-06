import { vi, describe, it, expect } from 'vitest'
import { tmpdir } from 'os'

// Module-level flag: when true, readFileSync throws for non-tmpdir paths
let shouldThrowOnRead = false

vi.mock('fs', async () => {
  const actual = await vi.importActual<typeof import('fs')>('fs')
  return {
    ...actual,
    readFileSync: vi.fn((path: Parameters<typeof actual.readFileSync>[0], options?: unknown) => {
      // Only throw for paths outside tmpdir (i.e., actual source files, not gitleaks reports)
      if (shouldThrowOnRead && !String(path).startsWith(tmpdir())) {
        throw new Error('EACCES: permission denied, open')
      }
      return actual.readFileSync(path as never, options as never)
    })
  }
})

import { mkdirSync, writeFileSync, rmSync } from 'fs'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { GoAnalyzer } from '../../src/recon/analyzers/go.js'
import { PythonAnalyzer } from '../../src/recon/analyzers/python.js'
import { RubyAnalyzer } from '../../src/recon/analyzers/ruby.js'
import { NodeAnalyzer } from '../../src/recon/analyzers/node.js'
import { JavaAnalyzer } from '../../src/recon/analyzers/java.js'
import { analyzeSastDeep } from '../../src/tools/analyze_sast_deep.js'
import { type JudgeContext } from '../../src/types/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const TMP = join(__dirname, '../.tmp-read-error')

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

function setup(ext: string, content: string): string {
  mkdirSync(TMP, { recursive: true })
  writeFileSync(join(TMP, `file.${ext}`), content)
  return TMP
}

function cleanup() {
  try { rmSync(TMP, { recursive: true, force: true }) } catch { /* ignore */ }
}

describe('analyzer readFileSync catch blocks', () => {
  it('GoAnalyzer skips unreadable .go files', async () => {
    setup('go', 'package main')
    shouldThrowOnRead = true
    try {
      const endpoints = await new GoAnalyzer().analyze(TMP)
      expect(endpoints).toEqual([])
    } finally {
      shouldThrowOnRead = false
      cleanup()
    }
  })

  it('PythonAnalyzer skips unreadable .py files', async () => {
    setup('py', '@app.route("/api/x")')
    shouldThrowOnRead = true
    try {
      const endpoints = await new PythonAnalyzer().analyze(TMP)
      expect(endpoints).toEqual([])
    } finally {
      shouldThrowOnRead = false
      cleanup()
    }
  })

  it('RubyAnalyzer skips unreadable .rb files', async () => {
    setup('rb', "get '/api/x' do end")
    shouldThrowOnRead = true
    try {
      const endpoints = await new RubyAnalyzer().analyze(TMP)
      expect(endpoints).toEqual([])
    } finally {
      shouldThrowOnRead = false
      cleanup()
    }
  })

  it('NodeAnalyzer skips unreadable .js files', async () => {
    setup('js', "app.get('/api/x', handler)")
    shouldThrowOnRead = true
    try {
      const endpoints = await new NodeAnalyzer().analyze(TMP)
      expect(endpoints).toEqual([])
    } finally {
      shouldThrowOnRead = false
      cleanup()
    }
  })

  it('JavaAnalyzer skips unreadable .java files', async () => {
    setup('java', '@GetMapping("/api/x") public String x() { return ""; }')
    shouldThrowOnRead = true
    try {
      const endpoints = await new JavaAnalyzer().analyze(TMP)
      expect(endpoints).toEqual([])
    } finally {
      shouldThrowOnRead = false
      cleanup()
    }
  })

  it('analyzeSastDeep skips unreadable source files in scanDangerousPatterns', async () => {
    // Create a diverse directory: source file, non-source file, SKIP dir, non-SKIP dir
    mkdirSync(TMP, { recursive: true })
    writeFileSync(join(TMP, 'file.ts'), 'const x = eval("secret")')
    writeFileSync(join(TMP, 'readme.txt'), 'not a source file')       // covers line 121 false
    mkdirSync(join(TMP, 'node_modules'), { recursive: true })         // covers line 115 false (SKIP)
    writeFileSync(join(TMP, 'node_modules', 'lib.js'), 'skip me')
    mkdirSync(join(TMP, 'src'), { recursive: true })                  // non-SKIP subdir
    writeFileSync(join(TMP, 'src', 'api.ts'), 'eval("deep")')
    shouldThrowOnRead = true
    try {
      const ctx = makeCtx()
      const result = await analyzeSastDeep({ sourcePath: TMP }, ctx)
      // readFileSync throws → catch { continue } → no findings from scanDangerousPatterns
      expect(typeof result).toBe('string')
      expect(result).toContain('Extracted')
    } finally {
      shouldThrowOnRead = false
      cleanup()
    }
  })
})
