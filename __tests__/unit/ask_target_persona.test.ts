import { describe, it, expect } from 'vitest'
import { askTargetPersona } from '../../src/tools/ask_target_persona.js'
import { type JudgeContext } from '../../src/types/index.js'

function makeCtx(): JudgeContext {
  return {
    persona: 'personal',
    penaltyMultiplier: 0.3,
    targetBaseUrl: '',
    allowedUrls: [],
    hasLlmChat: false,
    endpoints: [],
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

describe('askTargetPersona', () => {
  it('sets persona and targetBaseUrl on ctx', () => {
    const ctx = makeCtx()
    askTargetPersona({
      persona: 'commercial',
      targetBaseUrl: 'http://localhost:8080/api/v1',
      hasLlmChat: false,
    }, ctx)
    expect(ctx.persona).toBe('commercial')
    expect(ctx.targetBaseUrl).toBe('http://localhost:8080')
    expect(ctx.penaltyMultiplier).toBe(1.0)
  })

  it('sets allowedUrls to base URL', () => {
    const ctx = makeCtx()
    askTargetPersona({
      persona: 'personal',
      targetBaseUrl: 'https://app.example.com',
      hasLlmChat: true,
    }, ctx)
    expect(ctx.allowedUrls).toContain('https://app.example.com')
    expect(ctx.hasLlmChat).toBe(true)
  })

  it('stores sourcePath when provided', () => {
    const ctx = makeCtx()
    askTargetPersona({
      persona: 'internal',
      targetBaseUrl: 'http://internal.corp',
      hasLlmChat: false,
      sourcePath: '/home/user/myapp',
    }, ctx)
    expect(ctx.sourcePath).toBe('/home/user/myapp')
  })

  it('resets findings and endpoints', () => {
    const ctx = makeCtx()
    ctx.findings.push({ severity: 'HIGH', category: 'A', description: 'old', evidence: '', isFail: false, baseDeduction: 10, toolName: 'old' })
    ctx.endpoints.push({ method: 'GET', path: '/old', parameters: [], authRequired: false, sourceLanguage: 'java' })

    askTargetPersona({ persona: 'team', targetBaseUrl: 'http://localhost', hasLlmChat: false }, ctx)

    expect(ctx.findings).toHaveLength(0)
    expect(ctx.endpoints).toHaveLength(0)
  })

  it('returns formatted string', () => {
    const ctx = makeCtx()
    const result = askTargetPersona({ persona: 'commercial', targetBaseUrl: 'http://example.com', hasLlmChat: false }, ctx)
    expect(result).toContain('commercial')
    expect(result).toContain('http://example.com')
  })

  it('sets correct multiplier for all personas', () => {
    const cases: Array<[string, number]> = [
      ['personal', 0.3], ['team', 0.5], ['internal', 0.8], ['commercial', 1.0],
    ]
    for (const [persona, expected] of cases) {
      const ctx = makeCtx()
      askTargetPersona({ persona: persona as never, targetBaseUrl: 'http://localhost', hasLlmChat: false }, ctx)
      expect(ctx.penaltyMultiplier).toBe(expected)
    }
  })

  it('strips path from targetBaseUrl', () => {
    const ctx = makeCtx()
    askTargetPersona({
      persona: 'personal',
      targetBaseUrl: 'http://192.168.100.5:8080/api/v2',
      hasLlmChat: false,
    }, ctx)
    expect(ctx.targetBaseUrl).toBe('http://192.168.100.5:8080')
  })
})
