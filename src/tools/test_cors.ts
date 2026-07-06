import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const TEST_CORS_SCHEMA = {
  type: 'object',
  properties: {
    authToken: {
      type: 'string',
      description: 'Auth token to include in CORS preflight test (optional)',
    },
  },
  required: [],
}

interface CorsTestCase {
  label: string
  origin: string
}

export async function testCors(
  input: { authToken?: string },
  ctx: JudgeContext
): Promise<string> {
  const targetUrl = ctx.targetBaseUrl
  assertAllowedUrl(targetUrl, ctx.allowedUrls)

  const targetDomain = new URL(targetUrl).hostname
  const findings: Finding[] = []
  const results: string[] = []

  const testCases: CorsTestCase[] = [
    { label: 'evil-origin', origin: 'https://evil.attacker.com' },
    { label: 'null-origin', origin: 'null' },
    { label: 'suffix-bypass', origin: `https://${targetDomain}.evil.com` },
    { label: 'subdomain-wildcard', origin: `https://evil.${targetDomain}` },
  ]

  const headers: Record<string, string> = { 'User-Agent': 'security-judge/1.0' }
  if (input.authToken) headers['Authorization'] = `Bearer ${input.authToken}`
  if (ctx.sessionCookies) headers['Cookie'] = ctx.sessionCookies

  for (const tc of testCases) {
    try {
      const res = await request(targetUrl, {
        method: 'GET',
        headers: { ...headers, 'Origin': tc.origin },
      })
      await res.body.text()

      const resHeaders = res.headers as Record<string, string | string[] | undefined>
      const getH = (name: string) => {
        const v = resHeaders[name]
        return Array.isArray(v) ? v[0] : v
      }

      const acao = getH('access-control-allow-origin') ?? ''
      const acac = getH('access-control-allow-credentials') ?? ''

      results.push(`${tc.label}: ACAO="${acao}" ACAC="${acac}"`)

      const originReflected = acao === tc.origin || acao === '*'
      const credentialed = acac.toLowerCase() === 'true'

      if (originReflected && credentialed) {
        findings.push({
          severity: 'CRITICAL',
          category: 'A',
          description: `CORS: Origin "${tc.origin}" reflected with credentials — any attacker site can make authenticated requests`,
          evidence: `GET ${targetUrl}\nOrigin: ${tc.origin}\naccess-control-allow-origin: ${acao}\naccess-control-allow-credentials: ${acac}`,
          isFail: true,
          baseDeduction: 10,
          toolName: 'test_cors',
          owaspCategory: 'A01:2021',
          cweId: 'CWE-942',
          confidence: 'HIGH',
        })
      } else if (originReflected && !credentialed) {
        findings.push({
          severity: 'HIGH',
          category: 'A',
          description: `CORS: Origin "${tc.origin}" reflected without credentials — public data may be cross-origin accessible`,
          evidence: `GET ${targetUrl}\nOrigin: ${tc.origin}\naccess-control-allow-origin: ${acao}`,
          isFail: false,
          baseDeduction: 10,
          toolName: 'test_cors',
          owaspCategory: 'A05:2021',
          cweId: 'CWE-942',
          confidence: 'HIGH',
        })
      }
    } catch (err) {
      if ((err as Error).message.includes('url_guard')) continue
      results.push(`${tc.label}: ERROR — ${(err as Error).message}`)
    }
  }

  ctx.findings.push(...findings)
  return `test_cors on ${targetUrl}:\n${results.join('\n')}\nFindings: ${findings.length}`
}
