import { request } from 'undici'
import { type EndpointInfo } from '../types/index.js'

const SCRIPT_SRC_REGEX = /<script[^>]+src=["']([^"']+\.js)["']/gi
const API_URL_REGEX = /['"`](\/api\/[^'"`\s]+)['"`]/g
const FETCH_REGEX = /fetch\s*\(\s*['"`]([^'"`]+)['"`]/g
const AXIOS_REGEX = /axios\.(?:get|post|put|patch|delete)\s*\(\s*['"`]([^'"`]+)['"`]/g

export async function scanJsBundle(baseUrl: string): Promise<EndpointInfo[]> {
  const endpoints: EndpointInfo[] = []

  try {
    const { body, statusCode } = await request(`${baseUrl}/`, { method: 'GET' })
    if (statusCode !== 200) return endpoints

    const html = await body.text()
    const scriptUrls: string[] = []

    let m: RegExpExecArray | null
    const scriptRegex = new RegExp(SCRIPT_SRC_REGEX.source, 'gi')
    while ((m = scriptRegex.exec(html)) !== null) {
      const src = m[1]
      scriptUrls.push(src.startsWith('http') ? src : `${baseUrl}${src.startsWith('/') ? '' : '/'}${src}`)
    }

    await Promise.allSettled(
      scriptUrls.slice(0, 5).map(async url => {
        try {
          const { body: jsBody, statusCode: jsStatus } = await request(url, { method: 'GET' })
          if (jsStatus !== 200) return

          const js = await jsBody.text()
          const patterns = [API_URL_REGEX, FETCH_REGEX, AXIOS_REGEX]

          for (const pattern of patterns) {
            const regex = new RegExp(pattern.source, 'g')
            let match: RegExpExecArray | null
            while ((match = regex.exec(js)) !== null) {
              const path = match[1]
              if (path.startsWith('/api/') || path.includes('/api/')) {
                if (!endpoints.some(e => e.path === path)) {
                  endpoints.push({
                    method: 'GET',
                    path,
                    parameters: [],
                    authRequired: false,
                    sourceLanguage: 'javascript',
                  })
                }
              }
            }
          }
        } catch { /* skip unreachable JS */ }
      })
    )
  } catch { /* skip if target unreachable */ }

  return endpoints
}

export async function fetchOpenApiEndpoints(baseUrl: string): Promise<EndpointInfo[]> {
  const candidates = ['/openapi.json', '/swagger.json', '/v3/api-docs', '/api-docs']
  const endpoints: EndpointInfo[] = []

  for (const path of candidates) {
    try {
      const { body, statusCode } = await request(`${baseUrl}${path}`, { method: 'GET' })
      if (statusCode !== 200) continue

      const json = await body.json() as Record<string, unknown>
      const paths = (json.paths as Record<string, unknown>) ?? {}

      for (const [apiPath, methods] of Object.entries(paths)) {
        for (const [method] of Object.entries(methods as Record<string, unknown>)) {
          endpoints.push({
            method: method.toUpperCase(),
            path: apiPath,
            parameters: [],
            authRequired: false,
            sourceLanguage: 'unknown',
          })
        }
      }

      break
    } catch { /* try next */ }
  }

  return endpoints
}
