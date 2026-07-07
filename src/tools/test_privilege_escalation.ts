import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const TEST_PRIVILEGE_ESCALATION_SCHEMA = {
  type: 'object',
  properties: {
    endpoint: {
      type: 'string',
      description: 'Endpoint to test (e.g., /api/users/me). Use a NON-privileged user resource so escalation is observable.',
    },
    token: {
      type: 'string',
      description: 'Normal (non-admin) user token',
    },
  },
  required: ['endpoint', 'token'],
}

const ESCALATION_PAYLOADS = [
  { body: { isAdmin: true }, desc: 'isAdmin=true body injection' },
  { body: { role: 'admin' }, desc: 'role=admin body injection' },
  { body: { admin: 1, is_admin: true, isAdmin: true }, desc: 'admin flag bulk injection' },
  { query: '?isAdmin=true', desc: 'isAdmin=true query param' },
  { query: '?role=admin', desc: 'role=admin query param' },
]

function tryParseJson(str: string): Record<string, unknown> | null {
  try {
    return JSON.parse(str)
  } catch {
    return null
  }
}

function isElevated(body: string): boolean {
  const o = tryParseJson(body)
  return !!o && (o.isAdmin === true || o.role === 'admin' || o.admin === true)
}

export async function testPrivilegeEscalation(
  input: { endpoint: string; token: string },
  ctx: JudgeContext
): Promise<string> {
  const findings: Finding[] = []
  const results: string[] = []
  const baseUrl = `${ctx.targetBaseUrl}${input.endpoint}`
  const headers = {
    'Authorization': `Bearer ${input.token}`,
    'Content-Type': 'application/json',
  }

  // Baseline: a benign request carrying NO escalation fields. The response tells us
  // the user's current privilege state, so we can attribute any later elevation to
  // our injected payload (differential oracle) instead of merely echoing back "admin".
  let baselineElevated = false
  try {
    assertAllowedUrl(baseUrl, ctx.allowedUrls)
    const res = await request(baseUrl, { method: 'PUT', headers, body: JSON.stringify({ _probe: 'baseline' }) })
    const body = await res.body.text()
    if (res.statusCode >= 200 && res.statusCode < 300) baselineElevated = isElevated(body)
    results.push(`[baseline]: ${res.statusCode}${baselineElevated ? ' (already elevated — inconclusive)' : ''}`)
  } catch (err) {
    if ((err as Error).message.includes('url_guard')) {
      return `test_privilege_escalation on ${input.endpoint}: blocked by url_guard`
    }
    results.push(`[baseline]: ERROR`)
  }

  if (baselineElevated) {
    // The endpoint reports elevated privileges even without an escalation payload,
    // so we cannot attribute elevation to injection. Do NOT emit a finding.
    return `test_privilege_escalation on ${input.endpoint}:\n${results.join('\n')}\nBaseline already elevated — inconclusive (no finding).`
  }

  for (const payload of ESCALATION_PAYLOADS) {
    try {
      const url = `${baseUrl}${payload.query ?? ''}`
      assertAllowedUrl(url, ctx.allowedUrls)

      const res = await request(url, {
        method: 'PUT',
        headers,
        body: payload.body ? JSON.stringify(payload.body) : undefined,
      })

      const body = await res.body.text()
      results.push(`[${payload.desc}]: ${res.statusCode}`)

      if (res.statusCode >= 200 && res.statusCode < 300 && isElevated(body)) {
        findings.push({
          severity: 'CRITICAL',
          category: 'B',
          description: `Privilege escalation: ${payload.desc} elevated a non-privileged user to admin (baseline was not elevated)`,
          evidence: `curl -X PUT '${url}' -H 'Authorization: Bearer ${input.token}' -d '${JSON.stringify(payload.body ?? {})}'\nResponse: ${body.slice(0, 500)}`,
          isFail: true,
          baseDeduction: 10,
          toolName: 'test_privilege_escalation',
          owaspCategory: 'A01:2021',
          cweId: 'CWE-269',
          confidence: 'HIGH',
        })
        // One finding per endpoint — the remaining payloads exploit the same flaw.
        break
      }
    } catch (err) {
      if ((err as Error).message.includes('url_guard')) continue
      results.push(`[${payload.desc}]: ERROR`)
    }
  }

  ctx.findings.push(...findings)
  return `test_privilege_escalation on ${input.endpoint}:\n${results.join('\n')}\nFindings: ${findings.length}`
}
