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

function jaccardSimilarity(a: string, b: string): number {
  const setA = new Set(a.split(/\s+/).filter(Boolean))
  const setB = new Set(b.split(/\s+/).filter(Boolean))
  if (setA.size === 0 && setB.size === 0) return 1
  const intersection = [...setA].filter(x => setB.has(x)).length
  const union = new Set([...setA, ...setB]).size
  return union === 0 ? 1 : intersection / union
}

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

    let victimBody: string | null = null
    if (input.victimToken) {
      const victimUrl = `${ctx.targetBaseUrl}${path}`
      try {
        assertAllowedUrl(victimUrl, ctx.allowedUrls)
        const victimRes = await request(victimUrl, {
          method: 'GET',
          headers: { 'Authorization': `Bearer ${input.victimToken}`, 'Content-Type': 'application/json' },
        })
        if (victimRes.statusCode >= 200 && victimRes.statusCode < 300) {
          victimBody = await victimRes.body.text()
        } else {
          await victimRes.body.text()
        }
      } catch {
        // victim token check failed — continue with attacker-only test
      }
    }

    for (const variant of ALT_ID_VARIANTS) {
      const altId = variant(originalId)
      if (altId === originalId) continue
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
          const hasVictimConfirmation = victimBody !== null && jaccardSimilarity(body, victimBody) > 0.3

          const finding: Finding = {
            severity: hasVictimConfirmation ? 'CRITICAL' : 'HIGH',
            category: 'B',
            description: hasVictimConfirmation
              ? `BOLA/IDOR confirmed: Attacker accessed victim's resource at ${altPath}`
              : `Possible BOLA/IDOR (unconfirmed): Attacker accessed ${altPath} — provide victimToken to confirm`,
            evidence: `curl -X GET '${url}' -H 'Authorization: Bearer ${input.attackerToken}'\nResponse (${res.statusCode}): ${body.slice(0, 500)}`,
            isFail: hasVictimConfirmation,
            baseDeduction: 10,
            toolName: 'test_bola_idor',
            owaspCategory: 'A01:2021',
            cweId: 'CWE-639',
            confidence: hasVictimConfirmation ? 'HIGH' : 'MEDIUM',
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
