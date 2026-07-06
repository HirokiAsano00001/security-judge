import { request } from 'undici'
import { type JudgeContext, type EndpointInfo, type Finding, CONCURRENCY_LIMIT } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'
import pLimit from 'p-limit'

export const TEST_SSTI_SCHEMA = {
  type: 'object',
  properties: {
    authToken: {
      type: 'string',
      description: 'Bearer token (optional)',
    },
  },
  required: [],
}

interface SstiPayload {
  payload: string
  expected: string
  confirmPayload: string
  confirmExpected: string
  engine: string
}

const SSTI_PAYLOADS: SstiPayload[] = [
  { payload: '{{7*7}}', expected: '49', confirmPayload: '{{6*6}}', confirmExpected: '36', engine: 'Jinja2/Twig/Pebble/Nunjucks' },
  { payload: '${7*7}', expected: '49', confirmPayload: '${6*6}', confirmExpected: '36', engine: 'Freemarker/Thymeleaf/Velocity' },
  { payload: '#{7*7}', expected: '49', confirmPayload: '#{6*6}', confirmExpected: '36', engine: 'Pebble/Groovy' },
  { payload: '{{7*"7"}}', expected: '7777777', confirmPayload: '{{6*"6"}}', confirmExpected: '6666666', engine: 'Jinja2' },
  { payload: '<%= 7*7 %>', expected: '49', confirmPayload: '<%= 6*6 %>', confirmExpected: '36', engine: 'ERB/JSP-EL' },
  { payload: '${{7*7}}', expected: '49', confirmPayload: '${{6*6}}', confirmExpected: '36', engine: 'Tornado/Mako' },
  { payload: '{7*7}', expected: '49', confirmPayload: '{6*6}', confirmExpected: '36', engine: 'Smarty' },
]

const REFLECTION_PROBE = 'xQz7SstiPrb123'

function isStringParam(ep: EndpointInfo): boolean {
  return ep.parameters.some(p => p.type === 'string' && (p.in === 'query' || p.in === 'body'))
}

async function testEndpoint(
  endpoint: EndpointInfo,
  targetUrl: string,
  headers: Record<string, string>,
  ctx: JudgeContext,
  findings: Finding[],
): Promise<void> {
  const stringParam = endpoint.parameters.find(p => p.type === 'string' && (p.in === 'query' || p.in === 'body'))
  const paramName = stringParam?.name ?? 'q'

  const buildUrl = (value: string) =>
    endpoint.method === 'GET'
      ? `${targetUrl}?${new URLSearchParams({ [paramName]: value })}`
      : targetUrl

  const buildBody = (value: string) =>
    endpoint.method !== 'GET' ? JSON.stringify({ [paramName]: value }) : undefined

  try {
    assertAllowedUrl(buildUrl(REFLECTION_PROBE), ctx.allowedUrls)
    const probeRes = await request(buildUrl(REFLECTION_PROBE), {
      method: endpoint.method,
      headers,
      body: buildBody(REFLECTION_PROBE),
    })
    const probeBody = await probeRes.body.text()
    if (!probeBody.includes(REFLECTION_PROBE)) return
  } catch {
    return
  }

  for (const sp of SSTI_PAYLOADS) {
    try {
      const url = buildUrl(sp.payload)
      assertAllowedUrl(url, ctx.allowedUrls)
      const res = await request(url, {
        method: endpoint.method,
        headers,
        body: buildBody(sp.payload),
      })
      const body = await res.body.text()

      if (body.includes(sp.expected)) {
        // Differential confirmation: send a second distinct computation to eliminate false positives
        // e.g., {{6*6}} must return '36' to confirm {{7*7}}='49' was actually evaluated
        try {
          const confirmUrl = buildUrl(sp.confirmPayload)
          assertAllowedUrl(confirmUrl, ctx.allowedUrls)
          const confirmRes = await request(confirmUrl, {
            method: endpoint.method,
            headers,
            body: buildBody(sp.confirmPayload),
          })
          const confirmBody = await confirmRes.body.text()
          if (!confirmBody.includes(sp.confirmExpected)) continue
        } catch {
          continue
        }

        findings.push({
          severity: 'CRITICAL',
          category: 'A',
          description: `SSTI confirmed on ${endpoint.method} ${endpoint.path} (engine: ${sp.engine})`,
          evidence: `Primary: ${sp.payload} → ${sp.expected}\nConfirm: ${sp.confirmPayload} → ${sp.confirmExpected}\ncurl -X ${endpoint.method} '${url}'\nResponse snippet: ${body.slice(0, 500)}`,
          isFail: true,
          baseDeduction: 10,
          toolName: 'test_ssti',
          owaspCategory: 'A03:2021',
          cweId: 'CWE-94',
          confidence: 'HIGH',
        })
        return
      }
    } catch (err) {
      if ((err as Error).message.includes('url_guard')) return
    }
  }
}

export async function testSsti(
  input: { authToken?: string },
  ctx: JudgeContext
): Promise<string> {
  const findings: Finding[] = []
  const results: string[] = []
  const limit = pLimit(CONCURRENCY_LIMIT[ctx.persona])

  const candidates = ctx.endpoints.filter(isStringParam)
  if (candidates.length === 0) {
    return 'test_ssti: no string-parameter endpoints found'
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'User-Agent': 'security-judge/1.0',
  }
  if (input.authToken) headers['Authorization'] = `Bearer ${input.authToken}`
  if (ctx.sessionCookies) headers['Cookie'] = ctx.sessionCookies

  await Promise.allSettled(
    candidates.map(ep =>
      limit(async () => {
        const targetUrl = `${ctx.targetBaseUrl}${ep.path}`
        assertAllowedUrl(targetUrl, ctx.allowedUrls)
        await testEndpoint(ep, targetUrl, headers, ctx, findings)
        results.push(ep.path)
      })
    )
  )

  ctx.findings.push(...findings)
  return `test_ssti on ${candidates.length} endpoint(s):\n${results.join('\n')}\nFindings: ${findings.length}`
}
