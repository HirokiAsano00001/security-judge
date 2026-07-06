import { request } from 'undici'
import { type JudgeContext, type Finding } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const CHECK_SECURITY_HEADERS_SCHEMA = {
  type: 'object',
  properties: {},
  required: [],
}

interface HeaderCheck {
  header: string
  description: string
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  cweId: string
  check: (value: string | undefined) => boolean
  failMessage: string
}

const HEADER_CHECKS: HeaderCheck[] = [
  {
    header: 'strict-transport-security',
    description: 'HTTP Strict Transport Security (HSTS)',
    severity: 'MEDIUM',
    cweId: 'CWE-319',
    check: v => !v || !v.includes('max-age='),
    failMessage: 'HSTS header missing or max-age not set — HTTPS downgrade attacks possible',
  },
  {
    header: 'content-security-policy',
    description: 'Content Security Policy (CSP)',
    severity: 'HIGH',
    cweId: 'CWE-79',
    check: v => !v,
    failMessage: "CSP header missing — XSS attacks not mitigated by browser",
  },
  {
    header: 'x-content-type-options',
    description: 'X-Content-Type-Options',
    severity: 'MEDIUM',
    cweId: 'CWE-430',
    check: v => !v || v.toLowerCase() !== 'nosniff',
    failMessage: 'X-Content-Type-Options not set to nosniff — MIME-type sniffing attacks possible',
  },
  {
    header: 'x-frame-options',
    description: 'X-Frame-Options / CSP frame-ancestors',
    severity: 'MEDIUM',
    cweId: 'CWE-1021',
    check: (v) => !v,
    failMessage: 'X-Frame-Options missing — clickjacking protection absent',
  },
  {
    header: 'referrer-policy',
    description: 'Referrer-Policy',
    severity: 'LOW',
    cweId: 'CWE-116',
    check: v => !v,
    failMessage: 'Referrer-Policy not set — sensitive URL parameters may leak via Referer header',
  },
  {
    header: 'permissions-policy',
    description: 'Permissions-Policy',
    severity: 'LOW',
    cweId: 'CWE-16',
    check: v => !v,
    failMessage: 'Permissions-Policy not set — browser features not restricted',
  },
]

const INFO_LEAK_HEADERS = ['server', 'x-powered-by', 'x-aspnet-version', 'x-aspnetmvc-version']

export async function checkSecurityHeaders(
  _input: Record<never, never>,
  ctx: JudgeContext
): Promise<string> {
  const url = ctx.targetBaseUrl
  assertAllowedUrl(url, ctx.allowedUrls)

  const findings: Finding[] = []
  const lines: string[] = []

  const res = await request(url, {
    method: 'GET',
    headers: { 'User-Agent': 'security-judge/1.0' },
  })
  await res.body.text()

  const responseHeaders = res.headers as Record<string, string | string[] | undefined>

  const getHeader = (name: string): string | undefined => {
    const val = responseHeaders[name]
    return Array.isArray(val) ? val[0] : val
  }

  for (const check of HEADER_CHECKS) {
    const value = getHeader(check.header)
    if (check.check(value)) {
      lines.push(`[MISSING] ${check.header}: ${check.failMessage}`)
      findings.push({
        severity: check.severity,
        category: 'C',
        description: check.failMessage,
        evidence: `GET ${url}\nHeader "${check.header}" = ${value ?? '(not present)'}`,
        isFail: false,
        baseDeduction: 10,
        toolName: 'check_security_headers',
        owaspCategory: 'A05:2021',
        cweId: check.cweId,
        confidence: 'HIGH',
      })
    } else {
      lines.push(`[OK] ${check.header}: ${getHeader(check.header)}`)
    }
  }

  for (const leakHeader of INFO_LEAK_HEADERS) {
    const value = getHeader(leakHeader)
    if (value) {
      lines.push(`[INFO LEAK] ${leakHeader}: ${value}`)
      findings.push({
        severity: 'LOW',
        category: 'C',
        description: `Server info leaked via "${leakHeader}" header: ${value}`,
        evidence: `GET ${url}\n${leakHeader}: ${value}`,
        isFail: false,
        baseDeduction: 5,
        toolName: 'check_security_headers',
        owaspCategory: 'A05:2021',
        cweId: 'CWE-200',
        confidence: 'HIGH',
      })
    }
  }

  const acao = getHeader('access-control-allow-origin')
  const acac = getHeader('access-control-allow-credentials')
  if (acao === '*' && acac?.toLowerCase() === 'true') {
    findings.push({
      severity: 'CRITICAL',
      category: 'A',
      description: 'CORS misconfiguration: ACAO=* combined with ACAC=true — any origin can make credentialed requests',
      evidence: `GET ${url}\naccess-control-allow-origin: *\naccess-control-allow-credentials: true`,
      isFail: true,
      baseDeduction: 10,
      toolName: 'check_security_headers',
      owaspCategory: 'A01:2021',
      cweId: 'CWE-942',
      confidence: 'HIGH',
    })
  }

  ctx.findings.push(...findings)
  return `check_security_headers on ${url}:\n${lines.join('\n')}\nFindings: ${findings.length}`
}
