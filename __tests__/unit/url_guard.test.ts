import { describe, it, expect } from 'vitest'
import { isPrivateOrMetadataUrl, assertAllowedUrl, extractBaseUrl } from '../../src/safety/url_guard.js'

describe('isPrivateOrMetadataUrl', () => {
  it('blocks 10.x.x.x', () => {
    expect(isPrivateOrMetadataUrl('http://10.0.0.1/test')).toBe(true)
  })

  it('blocks 192.168.x.x', () => {
    expect(isPrivateOrMetadataUrl('http://192.168.1.100/api')).toBe(true)
  })

  it('blocks 172.16-31.x.x', () => {
    expect(isPrivateOrMetadataUrl('http://172.16.0.1/')).toBe(true)
    expect(isPrivateOrMetadataUrl('http://172.31.255.255/')).toBe(true)
  })

  it('blocks 127.x.x.x', () => {
    expect(isPrivateOrMetadataUrl('http://127.0.0.1/')).toBe(true)
  })

  it('blocks cloud metadata IPs', () => {
    expect(isPrivateOrMetadataUrl('http://169.254.169.254/latest/meta-data/')).toBe(true)
    expect(isPrivateOrMetadataUrl('http://100.100.100.200/')).toBe(true)
    expect(isPrivateOrMetadataUrl('http://metadata.google.internal/')).toBe(true)
  })

  it('allows public IPs', () => {
    expect(isPrivateOrMetadataUrl('http://8.8.8.8/')).toBe(false)
    expect(isPrivateOrMetadataUrl('https://example.com/api')).toBe(false)
    expect(isPrivateOrMetadataUrl('http://203.0.113.1/')).toBe(false)
  })
})

describe('assertAllowedUrl', () => {
  it('throws for private IP', () => {
    expect(() => assertAllowedUrl('http://10.0.0.1/', ['http://10.0.0.1/']))
      .toThrow('[url_guard]')
  })

  it('throws when not in allowedUrls', () => {
    expect(() => assertAllowedUrl('https://evil.com/api', ['https://example.com']))
      .toThrow('[url_guard]')
  })

  it('passes for allowed public URL', () => {
    expect(() => assertAllowedUrl('https://example.com/api/test', ['https://example.com']))
      .not.toThrow()
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
