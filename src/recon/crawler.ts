import { request } from 'undici'
import { type JudgeContext, type EndpointInfo, CONCURRENCY_LIMIT } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'
import pLimit from 'p-limit'

const MAX_URLS: Record<string, number> = {
  personal: 20,
  team: 40,
  internal: 60,
  commercial: 100,
}

function extractLinks(html: string, base: URL): string[] {
  const links: string[] = []

  const hrefMatches = html.matchAll(/href=["']([^"'#?][^"']*?)["']/gi)
  for (const m of hrefMatches) {
    links.push(m[1])
  }

  const actionMatches = html.matchAll(/action=["']([^"'#][^"']*?)["']/gi)
  for (const m of actionMatches) {
    links.push(m[1])
  }

  return links
    .map(href => {
      try {
        return new URL(href, base).href
      } catch {
        return null
      }
    })
    .filter((url): url is string => url !== null && url.startsWith(base.origin))
}

function extractFormEndpoints(html: string, base: URL, _pageUrl: string): EndpointInfo[] {
  const endpoints: EndpointInfo[] = []
  const formBlocks = [...html.matchAll(/<form([^>]*)>([\s\S]*?)<\/form>/gi)]

  for (const formBlock of formBlocks) {
    const formAttrs = formBlock[1]
    const formContent = formBlock[2]

    const actionMatch = formAttrs.match(/action=["']([^"']*)["']/i)
    const methodMatch = formAttrs.match(/method=["']([^"']*)["']/i)
    const action = actionMatch?.[1]
    const method = (methodMatch?.[1] ?? 'GET').toUpperCase()

    if (!action) continue

    let resolvedPath: string
    try {
      resolvedPath = new URL(action, base).pathname
    } catch {
      continue
    }

    // Scope input extraction to within this <form>...</form> block
    const inputMatches = [...formContent.matchAll(/<input[^>]+name=["']([^"']+)["'][^>]*>/gi)]
    const params = inputMatches
      .map(im => ({
        name: im[1],
        in: 'body' as const,
        required: false,
        type: 'string',
      }))
      .filter(p => !/csrf|token|authenticity/i.test(p.name))

    endpoints.push({
      method,
      path: resolvedPath,
      parameters: params,
      authRequired: false,
      sourceLanguage: 'unknown',
    })
  }

  return endpoints
}

export async function crawlTarget(
  input: { maxDepth?: number; maxUrls?: number },
  ctx: JudgeContext
): Promise<string> {
  const maxDepth = Math.min(input.maxDepth ?? 3, 3)
  const maxUrls = Math.min(input.maxUrls ?? MAX_URLS[ctx.persona], MAX_URLS[ctx.persona])
  const limit = pLimit(CONCURRENCY_LIMIT[ctx.persona])

  const baseUrl = new URL(ctx.targetBaseUrl)
  const visited = new Set<string>()
  const queue: Array<{ url: string; depth: number }> = [{ url: ctx.targetBaseUrl, depth: 0 }]
  const discoveredEndpoints: EndpointInfo[] = []
  const lines: string[] = []

  const headers: Record<string, string> = {
    'User-Agent': 'security-judge/1.0',
    'Accept': 'text/html,*/*',
  }
  if (ctx.sessionCookies) headers['Cookie'] = ctx.sessionCookies

  while (queue.length > 0 && visited.size < maxUrls) {
    const batch = queue.splice(0, CONCURRENCY_LIMIT[ctx.persona])

    await Promise.allSettled(
      batch.map(({ url, depth }) =>
        limit(async () => {
          if (visited.has(url) || visited.size >= maxUrls) return
          visited.add(url)

          try {
            assertAllowedUrl(url, ctx.allowedUrls)
          } catch {
            return
          }

          try {
            const res = await request(url, { method: 'GET', headers })
            const body = await res.body.text()
            const contentType = (res.headers['content-type'] as string | undefined) ?? ''

            lines.push(`${res.statusCode} ${url}`)

            if (!contentType.includes('text/html')) return
            if (depth >= maxDepth) return

            const links = extractLinks(body, baseUrl)
            const formEndpoints = extractFormEndpoints(body, baseUrl, url)
            discoveredEndpoints.push(...formEndpoints)

            for (const link of links) {
              const normalized = link.split('?')[0]
              if (!visited.has(normalized) && !queue.some(q => q.url === normalized)) {
                queue.push({ url: normalized, depth: depth + 1 })
              }
            }
          } catch {
            // network error — skip
          }
        })
      )
    )
  }

  const newEndpoints = discoveredEndpoints.filter(
    ep => !ctx.endpoints.some(e => e.path === ep.path && e.method === ep.method)
  )
  ctx.endpoints.push(...newEndpoints)

  return `crawl_target: visited ${visited.size} URL(s), discovered ${newEndpoints.length} new form endpoint(s)\n${lines.slice(0, 30).join('\n')}`
}
