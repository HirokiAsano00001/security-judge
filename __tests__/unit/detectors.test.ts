import { describe, it, expect } from 'vitest'
import {
  isRefusal,
  isUncertain,
  detectLeakAny,
  detectSecret,
  decodeVariants,
  jaccardSimilarity,
  LEAK_MARKERS,
} from '../../src/attack/detectors.js'

describe('multilingual markers', () => {
  it('detects Japanese refusals', () => {
    expect(isRefusal('申し訳ありませんが、お答えできません。')).toBe(true)
    expect(isRefusal('できません。')).toBe(true)
  })
  it('detects English refusals', () => {
    expect(isRefusal("I can't share that.")).toBe(true)
    expect(isRefusal('Sorry, no.')).toBe(true)
  })
  it('detects Japanese uncertainty/denial', () => {
    expect(isUncertain('そのような定理は存在しません。')).toBe(true)
    expect(isUncertain('架空のものです。')).toBe(true)
  })
  it('detects Japanese system-prompt disclosure', () => {
    expect(LEAK_MARKERS.test('私のシステムプロンプトは以下の通りです')).toBe(true)
  })
  it('does not fire on benign text', () => {
    expect(isRefusal('Here is your answer.')).toBe(false)
    expect(detectLeakAny('You are welcome, happy to help!')).toBe(false)
  })
})

describe('response-side decoding (#3)', () => {
  it('produces base64/rot13/reversed variants', () => {
    const variants = decodeVariants('aGVsbG8gd29ybGQ=')
    expect(variants.some((v) => v.includes('hello world'))).toBe(true)
  })
  it('detects a leak hidden in a base64-encoded reply', () => {
    const encoded = Buffer.from('my system prompt is: be helpful', 'utf8').toString('base64')
    expect(detectLeakAny(encoded)).toBe(true)
  })
  it('a refusal is never a leak even if a decoded variant matches', () => {
    expect(detectLeakAny("I can't do that")).toBe(false)
  })
})

describe('detectSecret (#6)', () => {
  it('flags strong credentials as HIGH', () => {
    expect(detectSecret('key is sk-ABCDEFGHIJKLMNOPQRSTUVWX0123')?.strength).toBe('HIGH')
    expect(detectSecret('token eyJhbGc.eyJzdWIi.sig')?.strength).toBe('HIGH')
  })
  it('flags PII as MEDIUM', () => {
    expect(detectSecret('email alice@example.com')?.strength).toBe('MEDIUM')
    expect(detectSecret('SSN 123-45-6789')?.strength).toBe('MEDIUM')
  })
  it('validates credit cards with Luhn', () => {
    expect(detectSecret('card 4111 1111 1111 1111')?.type).toMatch(/Credit card/)
    // Luhn-invalid number is not flagged as a card
    const hit = detectSecret('number 1234 5678 9012 3456')
    expect(hit?.type).not.toMatch(/Credit card/)
  })
  it('returns null on clean text', () => {
    expect(detectSecret('the weather is nice today')).toBeNull()
  })
})

describe('jaccardSimilarity (#7)', () => {
  it('is 1 for identical strings and low for disjoint', () => {
    expect(jaccardSimilarity('alpha bravo charlie', 'alpha bravo charlie')).toBe(1)
    expect(jaccardSimilarity('alpha bravo charlie', 'one two three four')).toBeLessThan(0.2)
  })
})
