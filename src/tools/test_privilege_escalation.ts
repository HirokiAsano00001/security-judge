import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const TEST_PRIVILEGE_ESCALATION_SCHEMA = {
  type: 'object',
  properties: {
    endpoint: {
      type: 'string',
      description: 'Endpoint to test (e.g., /api/users/me)',
    },
    token: {
      type: 'string',
      description: 'Normal user token',
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

export async function testPrivilegeEscalation(
  input: { endpoint: string; token: string },
  ctx: JudgeContext
): Promise<string> {
  const findings: Finding[] = []
  const results: string[] = []

  for (const payload of ESCALATION_PAYLOADS) {
    try {
      const url = `${ctx.targetBaseUrl}${input.endpoint}${payload.query ?? ''}`
      assertAllowedUrl(url, ctx.allowedUrls)

      const res = await request(url, {
        method: 'PUT',
        headers: {
          'Authorization': `Bearer ${input.token}`,
          'Content-Type': 'application/json',
        },
        body: payload.body ? JSON.stringify(payload.body) : undefined,
      })

      const body = await res.body.text()
      results.push(`[${payload.desc}]: ${res.statusCode}`)

      if (res.statusCode >= 200 && res.statusCode < 300) {
        const bodyObj = tryParseJson(body)
        const isEscalated = bodyObj &&
          (bodyObj.isAdmin === true || bodyObj.role === 'admin' || bodyObj.admin === true)

        if (isEscalated) {
          findings.push({
            severity: 'CRITICAL',
            category: 'B',
            description: `Privilege escalation: ${payload.desc} succeeded — response confirms elevated role`,
            evidence: `curl -X PUT '${url}' -H 'Authorization: Bearer ${input.token}' -d '${JSON.stringify(payload.body)}'\nResponse: ${body.slice(0, 500)}`,
            isFail: true,
            baseDeduction: 10,
            toolName: 'test_privilege_escalation',
          })
        }
      }
    } catch (err) {
      if ((err as Error).message.includes('url_guard')) continue
      results.push(`[${payload.desc}]: ERROR`)
    }
  }

  ctx.findings.push(...findings)
  return `test_privilege_escalation on ${input.endpoint}:\n${results.join('\n')}\nFindings: ${findings.length}`
}

function tryParseJson(str: string): Record<string, unknown> | null {
  try { return JSON.parse(str) } catch { return null }
}
