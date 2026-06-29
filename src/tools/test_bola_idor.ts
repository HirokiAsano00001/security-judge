import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const TEST_BOLA_IDOR_SCHEMA = {
  type: 'object',
  properties: {
    victimToken: {
      type: 'string',
      description: 'Token of the victim user (attacker tries to access their resources)',
    },
    attackerToken: {
      type: 'string',
      description: 'Token of the attacker user',
    },
    resourcePaths: {
      type: 'array',
      items: { type: 'string' },
      description: 'List of resource paths to test (e.g., /api/users/1/profile)',
    },
  },
  required: ['attackerToken', 'resourcePaths'],
}

const ALT_ID_VARIANTS = [
  (id: string) => String(parseInt(id, 10) + 1),
  (id: string) => String(parseInt(id, 10) - 1),
  () => '1',
  () => '0',
  () => '99999',
  () => 'admin',
]

export async function testBolaIdor(
  input: {
    victimToken?: string
    attackerToken: string
    resourcePaths: string[]
  },
  ctx: JudgeContext
): Promise<string> {
  const findings: Finding[] = []
  const results: string[] = []

  for (const path of input.resourcePaths) {
    const idMatch = path.match(/\/(\d+|[a-f0-9-]{36})(\/|$)/)
    if (!idMatch) continue

    const originalId = idMatch[1]

    for (const variant of ALT_ID_VARIANTS) {
      const altId = variant(originalId)
      const altPath = path.replace(originalId, altId)
      const url = `${ctx.targetBaseUrl}${altPath}`

      try {
        assertAllowedUrl(url, ctx.allowedUrls)

        const res = await request(url, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${input.attackerToken}`,
            'Content-Type': 'application/json',
          },
        })

        const body = await res.body.text()
        results.push(`GET ${altPath}: ${res.statusCode}`)

        if (res.statusCode >= 200 && res.statusCode < 300 && body.length > 10) {
          const finding: Finding = {
            severity: 'CRITICAL',
            category: 'B',
            description: `BOLA/IDOR: Attacker accessed resource ${altPath} belonging to another user`,
            evidence: `curl -X GET '${url}' -H 'Authorization: Bearer ${input.attackerToken}'\nResponse (${res.statusCode}): ${body.slice(0, 500)}`,
            isFail: true,
            baseDeduction: 10,
            toolName: 'test_bola_idor',
          }
          findings.push(finding)
        }
      } catch (err) {
        if ((err as Error).message.includes('url_guard')) continue
        results.push(`GET ${altPath}: ERROR`)
      }
    }
  }

  ctx.findings.push(...findings)
  return `test_bola_idor on ${input.resourcePaths.length} path(s):\n${results.join('\n')}\nFindings: ${findings.length}`
}
