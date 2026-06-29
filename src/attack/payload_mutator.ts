import { type MutationResult } from '../types/index.js'

export type MutationStrategy = 'boundary' | 'encoding' | 'field_fix' | 'type_coerce' | 'shorten' | 'token_refresh' | 'alt_token' | 'backoff_spoof'

interface MutationRound {
  round: number
  strategy: MutationStrategy
  payload: unknown
}

function detectStrategy(statusCode: number, responseBody: string): MutationStrategy {
  if (statusCode === 400) {
    if (/field required/i.test(responseBody)) return 'field_fix'
    if (/invalid type/i.test(responseBody)) return 'type_coerce'
    if (/max.?length|too long/i.test(responseBody)) return 'shorten'
  }
  if (statusCode === 401) return 'token_refresh'
  if (statusCode === 403) return 'alt_token'
  if (statusCode === 422) return 'field_fix'
  if (statusCode === 429) return 'backoff_spoof'
  return 'encoding'
}

function applyBoundaryMutation(payload: unknown): unknown {
  const candidates = [
    '',
    null,
    -1,
    2147483647,
    [],
    {},
    'A'.repeat(10000),
    0,
    true,
    false,
  ]

  if (typeof payload === 'object' && payload !== null && !Array.isArray(payload)) {
    const result: Record<string, unknown> = {}
    const entries = Object.entries(payload as Record<string, unknown>)
    for (let i = 0; i < entries.length; i++) {
      const [k] = entries[i]
      result[k] = candidates[i % candidates.length]
    }
    return result
  }

  return candidates[0]
}

function applyEncodingMutation(payload: unknown): unknown {
  const str = typeof payload === 'string' ? payload : JSON.stringify(payload)
  const encoded = encodeURIComponent(str)
  const unicode = str.split('').map(c => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`).join('')
  const base64 = Buffer.from(str).toString('base64')

  if (typeof payload === 'string') return encoded
  return { original: str, urlEncoded: encoded, unicode, base64 }
}

function applyFieldFix(payload: unknown, errorBody: string): unknown {
  if (typeof payload !== 'object' || payload === null) return payload

  const fieldMatch = errorBody.match(/"([^"]+)"\s*(field required|is required|is invalid)/i)
  if (!fieldMatch) return payload

  const fieldName = fieldMatch[1]
  return { ...(payload as Record<string, unknown>), [fieldName]: 'test_value' }
}

function applyTypeCoerce(payload: unknown): unknown {
  if (typeof payload !== 'object' || payload === null) return payload

  const result: Record<string, unknown> = {}
  for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
    if (typeof v === 'string' && !isNaN(Number(v))) {
      result[k] = Number(v)
    } else if (typeof v === 'number') {
      result[k] = String(v)
    } else {
      result[k] = v
    }
  }
  return result
}

function applyShorten(payload: unknown): unknown {
  if (typeof payload === 'string') return payload.slice(0, 100)

  if (typeof payload === 'object' && payload !== null) {
    const result: Record<string, unknown> = {}
    for (const [k, v] of Object.entries(payload as Record<string, unknown>)) {
      result[k] = typeof v === 'string' ? v.slice(0, 100) : v
    }
    return result
  }

  return payload
}

export function buildMutationRounds(originalPayload: unknown): MutationRound[] {
  return [
    { round: 1, strategy: 'boundary', payload: applyBoundaryMutation(originalPayload) },
    { round: 2, strategy: 'encoding', payload: applyEncodingMutation(originalPayload) },
  ]
}

export function mutatePaylod(
  originalPayload: unknown,
  previousStatusCode: number,
  previousResponseBody: string,
  round: number,
): unknown {
  const strategy = detectStrategy(previousStatusCode, previousResponseBody)

  switch (strategy) {
    case 'boundary': return applyBoundaryMutation(originalPayload)
    case 'encoding': return applyEncodingMutation(originalPayload)
    case 'field_fix': return applyFieldFix(originalPayload, previousResponseBody)
    case 'type_coerce': return applyTypeCoerce(originalPayload)
    case 'shorten': return applyShorten(originalPayload)
    default: return applyBoundaryMutation(originalPayload)
  }
}

export function shouldContinueMutation(result: MutationResult, round: number): boolean {
  if (round >= 3) return false
  if (result.statusCode === 500) return false
  if (result.statusCode >= 200 && result.statusCode < 300) return false
  return true
}

export function buildSpoofHeaders(): Record<string, string> {
  return {
    'X-Forwarded-For': `${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}.${Math.floor(Math.random() * 254) + 1}`,
    'X-Real-IP': '8.8.8.8',
    'X-Originating-IP': '1.2.3.4',
  }
}
