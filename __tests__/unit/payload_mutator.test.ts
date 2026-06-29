import { describe, it, expect } from 'vitest'
import { mutatePaylod, shouldContinueMutation, buildSpoofHeaders, buildMutationRounds } from '../../src/attack/payload_mutator.js'
import { type MutationResult } from '../../src/types/index.js'

function makeResult(statusCode: number, responseBody = '', round = 0): MutationResult {
  return { success: statusCode < 400, statusCode, responseBody, roundNumber: round, payload: {} }
}

describe('shouldContinueMutation', () => {
  it('stops at round 3', () => {
    expect(shouldContinueMutation(makeResult(400), 3)).toBe(false)
  })

  it('stops on 500', () => {
    expect(shouldContinueMutation(makeResult(500), 0)).toBe(false)
  })

  it('stops on success 2xx', () => {
    expect(shouldContinueMutation(makeResult(200), 0)).toBe(false)
    expect(shouldContinueMutation(makeResult(201), 1)).toBe(false)
  })

  it('continues on 400', () => {
    expect(shouldContinueMutation(makeResult(400), 0)).toBe(true)
    expect(shouldContinueMutation(makeResult(400), 2)).toBe(true)
  })

  it('4th attempt (round=3) is blocked', () => {
    expect(shouldContinueMutation(makeResult(400), 3)).toBe(false)
  })
})

describe('mutatePaylod', () => {
  const original = { username: 'test', age: 25 }

  it('applies field_fix on 400 "field required"', () => {
    const mutated = mutatePaylod(original, 400, '"email" field required', 1)
    expect(mutated).toBeDefined()
  })

  it('applies type_coerce on 400 "invalid type"', () => {
    const mutated = mutatePaylod({ count: '5' }, 400, 'invalid type for count', 1)
    expect(mutated).toBeDefined()
  })

  it('applies shorten on 400 "max length"', () => {
    const longPayload = { text: 'A'.repeat(5000) }
    const mutated = mutatePaylod(longPayload, 400, 'max length exceeded', 1) as Record<string, unknown>
    expect((mutated.text as string).length).toBeLessThanOrEqual(100)
  })

  it('applies encoding on unknown error', () => {
    const mutated = mutatePaylod('test-value', 422, 'unprocessable', 2)
    expect(mutated).toBeDefined()
  })

  it('applies shorten on primitive string (non-object) payload', () => {
    const longStr = 'X'.repeat(5000)
    const mutated = mutatePaylod(longStr, 400, 'max length exceeded', 1) as string
    expect(mutated.length).toBeLessThanOrEqual(100)
  })

  it('falls back to boundary on unmatched strategy (alt_token / backoff_spoof)', () => {
    const payload = { x: 'test' }
    const viaAltToken = mutatePaylod(payload, 403, 'forbidden', 1)
    expect(viaAltToken).toBeDefined()
    const viaBackoff = mutatePaylod(payload, 429, 'rate limit', 1)
    expect(viaBackoff).toBeDefined()
  })

  it('applies token_refresh on 401', () => {
    const mutated = mutatePaylod({ user: 'a' }, 401, 'unauthorized', 1)
    expect(mutated).toBeDefined()
  })
})

describe('buildMutationRounds', () => {
  it('returns two predefined rounds', () => {
    const rounds = buildMutationRounds({ key: 'value' })
    expect(rounds).toHaveLength(2)
    expect(rounds[0].strategy).toBe('boundary')
    expect(rounds[1].strategy).toBe('encoding')
    expect(rounds[0].round).toBe(1)
    expect(rounds[1].round).toBe(2)
  })

  it('handles non-object payload', () => {
    const rounds = buildMutationRounds('hello')
    expect(rounds).toHaveLength(2)
  })
})

describe('buildSpoofHeaders', () => {
  it('returns X-Forwarded-For header', () => {
    const headers = buildSpoofHeaders()
    expect(headers['X-Forwarded-For']).toMatch(/^\d+\.\d+\.\d+\.\d+$/)
    expect(headers['X-Real-IP']).toBeDefined()
  })
})
