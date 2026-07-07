import { describe, it, expect } from 'vitest'
import {
  isCloudMetadataUrl,
  isPrivateUrl,
  assertAllowedUrl,
  extractBaseUrl,
} from '../../src/safety/url_guard.js'

describe('isCloudMetadataUrl', () => {
  it('returns true for invalid URL string', () => {
    expect(isCloudMetadataUrl('not-a-valid-url')).toBe(true)
  })

  it('detects known metadata endpoints', () => {
    expect(isCloudMetadataUrl('http://169.254.169.254/latest/meta-data/')).toBe(true)
    expect(isCloudMetadataUrl('http://100.100.100.200/')).toBe(true)
    expect(isCloudMetadataUrl('http://metadata.google.internal/')).toBe(true)
  })

  it('detects obfuscated metadata IPs', () => {
    // decimal 169.254.169.254 = 2852039166
    expect(isCloudMetadataUrl('http://2852039166/')).toBe(true)
    expect(isCloudMetadataUrl('http://[::ffff:a9fe:a9fe]/')).toBe(true)
  })

  it('is false for private (non-metadata) and public hosts', () => {
    expect(isCloudMetadataUrl('http://127.0.0.1/')).toBe(false)
    expect(isCloudMetadataUrl('http://192.168.1.1/')).toBe(false)
    expect(isCloudMetadataUrl('https://example.com/')).toBe(false)
  })
})

describe('isPrivateUrl', () => {
  it('detects private / loopback / link-local ranges', () => {
    expect(isPrivateUrl('http://10.0.0.1/')).toBe(true)
    expect(isPrivateUrl('http://192.168.1.100/')).toBe(true)
    expect(isPrivateUrl('http://172.16.0.1/')).toBe(true)
    expect(isPrivateUrl('http://172.31.255.255/')).toBe(true)
    expect(isPrivateUrl('http://127.0.0.1/')).toBe(true)
    expect(isPrivateUrl('http://[::1]/')).toBe(true)
  })

  it('is false for public hosts', () => {
    expect(isPrivateUrl('http://8.8.8.8/')).toBe(false)
    expect(isPrivateUrl('https://example.com/')).toBe(false)
    expect(isPrivateUrl('http://203.0.113.1/')).toBe(false)
  })
})

describe('assertAllowedUrl — local-CLI threat model', () => {
  it('allows a designated private/loopback target (the core fix)', () => {
    expect(() => assertAllowedUrl('http://127.0.0.1:3737/api/users/1', ['http://127.0.0.1:3737']))
      .not.toThrow()
    expect(() => assertAllowedUrl('http://192.168.1.50:8080/x', ['http://192.168.1.50:8080']))
      .not.toThrow()
  })

  it('allows a designated public target', () => {
    expect(() => assertAllowedUrl('https://example.com/api/test', ['https://example.com']))
      .not.toThrow()
  })

  it('blocks cloud-metadata even when present in allowedUrls', () => {
    expect(() => assertAllowedUrl('http://169.254.169.254/latest/meta-data/', ['http://169.254.169.254']))
      .toThrow('[url_guard]')
  })

  it('blocks the userinfo bypass (host resolves to metadata)', () => {
    // hostname parses to 169.254.169.254; the 127.0.0.1:3737@ userinfo is stripped
    expect(() => assertAllowedUrl('http://127.0.0.1:3737@169.254.169.254/', ['http://127.0.0.1:3737']))
      .toThrow('[url_guard]')
  })

  it('blocks suffix look-alike hosts (exact host match, not prefix)', () => {
    expect(() => assertAllowedUrl('http://127.0.0.1.evil.com/', ['http://127.0.0.1:3737']))
      .toThrow('[url_guard]')
    expect(() => assertAllowedUrl('https://example.com.evil.com/', ['https://example.com']))
      .toThrow('[url_guard]')
  })

  it('blocks port mismatch', () => {
    expect(() => assertAllowedUrl('http://127.0.0.1:9999/', ['http://127.0.0.1:3737']))
      .toThrow('[url_guard]')
  })

  it('blocks a host not in allowedUrls', () => {
    expect(() => assertAllowedUrl('https://evil.com/api', ['https://example.com']))
      .toThrow('[url_guard]')
  })

  it('blocks an invalid URL', () => {
    expect(() => assertAllowedUrl('not-a-url', ['https://example.com']))
      .toThrow('[url_guard]')
  })
})

describe('extractBaseUrl', () => {
  it('extracts base URL correctly', () => {
    expect(extractBaseUrl('http://localhost:8080/api/v1/users')).toBe('http://localhost:8080')
    expect(extractBaseUrl('https://app.example.com/path?q=1')).toBe('https://app.example.com')
  })

  it('throws on invalid URL', () => {
    expect(() => extractBaseUrl('not-a-url')).toThrow('Invalid URL')
  })
})
