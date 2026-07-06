import { describe, it, expect } from 'vitest'
import {
  checkDbErrorSignatures,
  checkFileReadSignatures,
  checkStackTraceSignatures,
  checkXssReflection,
  checkBooleanDiff,
} from '../../src/attack/oracle.js'

describe('checkDbErrorSignatures', () => {
  it('detects MySQL syntax error', () => {
    const result = checkDbErrorSignatures("You have an error in your SQL syntax near '' OR 1=1--'")
    expect(result.isVulnerable).toBe(true)
    expect(result.confidence).toBe('HIGH')
  })

  it('detects Oracle error', () => {
    const result = checkDbErrorSignatures('ORA-00907: missing right parenthesis')
    expect(result.isVulnerable).toBe(true)
    expect(result.confidence).toBe('HIGH')
  })

  it('detects PostgreSQL error', () => {
    const result = checkDbErrorSignatures('PG::SyntaxError: ERROR: syntax error')
    expect(result.isVulnerable).toBe(true)
  })

  it('returns not vulnerable for normal response', () => {
    const result = checkDbErrorSignatures('{"results":[{"id":1,"name":"test"}]}')
    expect(result.isVulnerable).toBe(false)
    expect(result.confidence).toBe('LOW')
  })
})

describe('checkFileReadSignatures', () => {
  it('detects /etc/passwd content', () => {
    const result = checkFileReadSignatures('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin')
    expect(result.isVulnerable).toBe(true)
    expect(result.confidence).toBe('HIGH')
  })

  it('detects /etc/shadow content', () => {
    const result = checkFileReadSignatures('root:$6$saltsalt$hashedpassword:18000:0:99999:7:::')
    expect(result.isVulnerable).toBe(true)
  })

  it('returns not vulnerable for normal response', () => {
    const result = checkFileReadSignatures('{"ok":true}')
    expect(result.isVulnerable).toBe(false)
  })
})

describe('checkStackTraceSignatures', () => {
  it('detects Java stack trace', () => {
    const result = checkStackTraceSignatures('java.lang.NullPointerException\n\tat com.example.App.doGet(App.java:42)')
    expect(result.isVulnerable).toBe(true)
    expect(result.confidence).toBe('HIGH')
  })

  it('detects Python traceback', () => {
    const result = checkStackTraceSignatures('Traceback (most recent call last):\n  File "app.py", line 10')
    expect(result.isVulnerable).toBe(true)
  })

  it('returns not vulnerable for generic 500 message', () => {
    const result = checkStackTraceSignatures('{"error":"Internal Server Error"}')
    expect(result.isVulnerable).toBe(false)
  })
})

describe('checkXssReflection', () => {
  it('detects full XSS payload reflection', () => {
    const payload = '<script>alert(1)</script>'
    const result = checkXssReflection(`<html><body>${payload}</body></html>`, payload)
    expect(result.isVulnerable).toBe(true)
    expect(result.confidence).toBe('HIGH')
  })

  it('returns not vulnerable when payload is encoded', () => {
    const payload = '<script>alert(1)</script>'
    const result = checkXssReflection('<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>', payload)
    expect(result.isVulnerable).toBe(false)
  })

  it('returns not vulnerable for empty body', () => {
    const result = checkXssReflection('', '<script>alert(1)</script>')
    expect(result.isVulnerable).toBe(false)
  })
})

describe('checkBooleanDiff', () => {
  it('detects SQLi when true-condition matches baseline but false-condition differs', () => {
    const baseline = '{"count":5,"results":["a","b","c","d","e"]}'
    const trueBody = '{"count":5,"results":["a","b","c","d","e"]}'
    const falseBody = '{"count":0,"results":[]}'
    const result = checkBooleanDiff(baseline, trueBody, falseBody)
    expect(result.isVulnerable).toBe(true)
    expect(result.confidence).toBe('MEDIUM')
  })

  it('returns not vulnerable when all responses are identical', () => {
    const body = '{"count":0,"results":[]}'
    const result = checkBooleanDiff(body, body, body)
    expect(result.isVulnerable).toBe(false)
  })
})
