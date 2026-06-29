import { describe, it, expect } from 'vitest'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { analyzeSastDeep } from '../../src/tools/analyze_sast_deep.js'
import { type JudgeContext } from '../../src/types/index.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES_DIR = join(__dirname, '../fixtures')

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

describe('analyzeSastDeep', () => {
  it('returns summary string', async () => {
    const ctx = makeCtx()
    const result = await analyzeSastDeep({ sourcePath: join(FIXTURES_DIR, 'vuln') }, ctx)
    expect(typeof result).toBe('string')
    expect(result).toContain('Extracted')
  })

  it('runs without throwing on safe fixtures', async () => {
    const ctx = makeCtx()
    await expect(analyzeSastDeep({ sourcePath: join(FIXTURES_DIR, 'safe') }, ctx)).resolves.toBeDefined()
  })

  it('handles non-existent path gracefully', async () => {
    const ctx = makeCtx()
    const result = await analyzeSastDeep({ sourcePath: '/non/existent/path' }, ctx)
    expect(typeof result).toBe('string')
  })
})
