import { request } from 'undici'
import { type JudgeContext } from '../types/index.js'
import { assertAllowedUrl } from '../safety/url_guard.js'

export const LOGIN_AND_CAPTURE_SCHEMA = {
  type: 'object',
  properties: {
    loginUrl: {
      type: 'string',
      description: 'URL of the login endpoint (e.g., /auth/login or /login)',
    },
    username: {
      type: 'string',
      description: 'Username or email to log in with',
    },
    password: {
      type: 'string',
      description: 'Password to log in with',
    },
    usernameField: {
      type: 'string',
      description: 'Form field name for username (default: "username")',
    },
    passwordField: {
      type: 'string',
      description: 'Form field name for password (default: "password")',
    },
    submitAsJson: {
      type: 'boolean',
      description: 'Submit credentials as JSON body instead of form (default: true)',
    },
  },
  required: ['loginUrl', 'username', 'password'],
}

function extractCsrfFromHtml(html: string): { token: string; fieldName: string } | null {
  // Input-based patterns: capture both fieldName and token value
  const inputPatterns: Array<{ pattern: RegExp; nameGroup: number; valueGroup: number }> = [
    {
      pattern: /<input[^>]+name=["'](_csrf|csrf_token|authenticity_token|_token)[^>]+value=["']([^"']+)["']/i,
      nameGroup: 1, valueGroup: 2,
    },
    {
      pattern: /<input[^>]+value=["']([^"']+)["'][^>]+name=["'](_csrf|csrf_token|authenticity_token|_token)["']/i,
      nameGroup: 2, valueGroup: 1,
    },
  ]

  for (const { pattern, nameGroup, valueGroup } of inputPatterns) {
    const match = html.match(pattern)
    if (match) {
      return { token: match[valueGroup], fieldName: match[nameGroup] }
    }
  }

  // Meta-tag patterns: token value only — use Rails/Django default field name
  const metaPatterns = [
    /<meta\s+name=["']csrf-?token["']\s+content=["']([^"']+)["']/i,
    /<meta\s+content=["']([^"']+)["']\s+name=["']csrf-?token["']/i,
  ]
  for (const pat of metaPatterns) {
    const match = html.match(pat)
    if (match) {
      return { token: match[1], fieldName: 'authenticity_token' }
    }
  }

  return null
}

function extractCookieString(setCookieHeaders: string | string[] | undefined): string {
  if (!setCookieHeaders) return ''
  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders]
  return cookies.map(c => c.split(';')[0]).join('; ')
}

function extractCsrfFromCookie(cookieString: string): string | null {
  const match = cookieString.match(/(?:^|;\s*)(?:csrf[-_]token|xsrf-token|_csrf)=([^;]+)/i)
  return match ? match[1] : null
}

export async function loginAndCapture(
  input: {
    loginUrl: string
    username: string
    password: string
    usernameField?: string
    passwordField?: string
    submitAsJson?: boolean
  },
  ctx: JudgeContext
): Promise<string> {
  const { username, password } = input
  const usernameField = input.usernameField ?? 'username'
  const passwordField = input.passwordField ?? 'password'
  const submitAsJson = input.submitAsJson !== false

  const loginUrl = input.loginUrl.startsWith('http')
    ? input.loginUrl
    : `${ctx.targetBaseUrl}${input.loginUrl}`

  assertAllowedUrl(loginUrl, ctx.allowedUrls)

  let csrfToken: string | null = null
  let csrfFieldName = '_csrf'
  let initialCookies = ''

  try {
    const getRes = await request(loginUrl, {
      method: 'GET',
      headers: { 'User-Agent': 'security-judge/1.0', 'Accept': 'text/html,application/json' },
    })
    const html = await getRes.body.text()
    const rawSetCookie = getRes.headers['set-cookie']
    initialCookies = extractCookieString(rawSetCookie as string | string[] | undefined)

    const csrfResult = extractCsrfFromHtml(html)
    if (csrfResult) {
      csrfToken = csrfResult.token
      csrfFieldName = csrfResult.fieldName
    } else {
      csrfToken = extractCsrfFromCookie(initialCookies)
    }
  } catch {
    // GET failed — try POST without CSRF token
  }

  const postHeaders: Record<string, string> = {
    'User-Agent': 'security-judge/1.0',
    'Accept': 'application/json, text/html',
  }
  if (initialCookies) postHeaders['Cookie'] = initialCookies

  let postBody: string
  if (submitAsJson) {
    postHeaders['Content-Type'] = 'application/json'
    const payload: Record<string, string> = { [usernameField]: username, [passwordField]: password }
    if (csrfToken) payload[csrfFieldName] = csrfToken
    postBody = JSON.stringify(payload)
  } else {
    postHeaders['Content-Type'] = 'application/x-www-form-urlencoded'
    const params = new URLSearchParams({ [usernameField]: username, [passwordField]: password })
    if (csrfToken) params.set(csrfFieldName, csrfToken)
    postBody = params.toString()
  }

  const postRes = await request(loginUrl, {
    method: 'POST',
    headers: postHeaders,
    body: postBody,
  })
  const responseBody = await postRes.body.text()
  const rawSetCookie = postRes.headers['set-cookie']
  const sessionCookies = extractCookieString(rawSetCookie as string | string[] | undefined)

  const mergedCookies = [initialCookies, sessionCookies].filter(Boolean).join('; ')
  const deduped = [...new Map(
    mergedCookies.split(';').map(c => c.trim()).filter(Boolean).map(c => [c.split('=')[0], c])
  ).values()].join('; ')

  if (postRes.statusCode >= 200 && postRes.statusCode < 400 && deduped) {
    ctx.sessionCookies = deduped
    return `login_and_capture: SUCCESS (HTTP ${postRes.statusCode})\nCookies captured: ${deduped.split(';').length} cookie(s)\nStored in ctx.sessionCookies`
  }

  const errorSnippet = responseBody.slice(0, 200)
  return `login_and_capture: FAILED (HTTP ${postRes.statusCode}) — ${errorSnippet}\n${csrfToken ? '' : 'Hint: CSRF token not found — try setting submitAsJson=false or check usernameField/passwordField'}`
}
