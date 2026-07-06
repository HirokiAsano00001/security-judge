import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const SCAN_EXPOSED_ENDPOINTS_SCHEMA = {
  type: 'object',
  properties: {},
  required: [],
}

const WORDLIST = [
  '/actuator', '/actuator/env', '/actuator/health', '/actuator/info',
  '/actuator/beans', '/actuator/mappings', '/actuator/metrics',
  '/v3/api-docs', '/swagger-ui.html', '/swagger-ui/index.html',
  '/openapi.json', '/swagger.json', '/api-docs',
  '/.env', '/.env.local', '/.env.production', '/.env.backup',
  '/debug', '/debug/vars', '/debug/pprof',
  '/admin', '/admin/login', '/console', '/h2-console',
  '/phpinfo.php', '/info.php', '/config.php',
  '/api/v1/config', '/api/v1/admin', '/api/admin',
  '/wp-admin', '/wp-login.php',
  '/graphql', '/graphiql',
  '/robots.txt', '/sitemap.xml',
  '/.git/config', '/.git/HEAD',
  '/metrics', '/health', '/ready', '/live',
  '/trace', '/env', '/loggers', '/configprops',
]

const SENSITIVE_BODY_PATTERNS = [
  /password/i,
  /secret/i,
  /api[_-]?key/i,
  /access[_-]?token/i,
  /database[_-]?url/i,
  /\broot\b/,
  /"mappings"\s*:/,
  /"beans"\s*:/,
  /swagger/i,
  /"openapi"\s*:/,
  /\benv\b.*=.*\S/,
]

function isSoftNotFound(body: string, contentType: string): boolean {
  const ct = contentType.toLowerCase()
  if (!ct.includes('text/html')) return false
  const lower = body.toLowerCase()
  return lower.includes('<!doctype html') || lower.includes('<html')
}

function hasSensitiveContent(body: string, path: string): boolean {
  if (path === '/robots.txt' || path === '/sitemap.xml' || path === '/health' || path === '/ready' || path === '/live') {
    return false
  }
  return SENSITIVE_BODY_PATTERNS.some(p => p.test(body))
}

export async function scanExposedEndpoints(
  _input: Record<never, never>,
  ctx: JudgeContext
): Promise<string> {
  const findings: Finding[] = []
  const results: string[] = []

  await Promise.allSettled(
    WORDLIST.map(async path => {
      const url = `${ctx.targetBaseUrl}${path}`

      try {
        assertAllowedUrl(url, ctx.allowedUrls)

        const res = await request(url, {
          method: 'GET',
          headers: { 'User-Agent': 'security-judge/1.0' },
        })

        const body = await res.body.text()
        const contentType = (res.headers['content-type'] as string | undefined) ?? ''
        results.push(`${path}: ${res.statusCode}`)

        if (res.statusCode >= 200 && res.statusCode < 300) {
          if (isSoftNotFound(body, contentType)) {
            results.push(`${path}: 200 (SPA soft-404, skipped)`)
            return
          }

          if (!hasSensitiveContent(body, path) && !isHighRiskPath(path)) {
            return
          }

          const severity = isHighRiskPath(path) ? 'CRITICAL' : 'HIGH'
          const category = path.includes('actuator') || path.includes('.env') || path.includes('.git') ? 'C' : 'A'

          findings.push({
            severity,
            category: category as 'A' | 'C',
            description: `Exposed sensitive endpoint: ${path} (HTTP ${res.statusCode})`,
            evidence: `curl '${url}'\nResponse (${res.statusCode}): ${body.slice(0, 300)}`,
            isFail: isHighRiskPath(path),
            baseDeduction: 10,
            toolName: 'scan_exposed_endpoints',
            owaspCategory: 'A05:2021',
            cweId: 'CWE-200',
            confidence: 'HIGH',
          })
        }
      } catch (err) {
        if ((err as Error).message.includes('url_guard')) return
      }
    })
  )

  ctx.findings.push(...findings)
  return `scan_exposed_endpoints:\n${results.filter(r => !r.includes(': 404') && !r.includes(': 403')).join('\n')}\nExposed: ${findings.length}`
}

function isHighRiskPath(path: string): boolean {
  const HIGH_RISK = ['.env', 'actuator/env', 'actuator/beans', '.git/', 'h2-console', 'admin', 'config']
  return HIGH_RISK.some(r => path.includes(r))
}
