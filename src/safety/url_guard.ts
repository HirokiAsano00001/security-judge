import { URL } from 'url'

// Private / loopback / link-local ranges. These are ALLOWED as targets when they
// match ctx.allowedUrls (operator = target owner, local-CLI threat model), but are
// never reachable unless explicitly designated as the target.
const PRIVATE_IP_PATTERNS = [
  /^10\.\d+\.\d+\.\d+$/,
  /^172\.(1[6-9]|2\d|3[01])\.\d+\.\d+$/,
  /^192\.168\.\d+\.\d+$/,
  /^127\.\d+\.\d+\.\d+$/,
  /^169\.254\.\d+\.\d+$/,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i,
  /^fd00:/i,
]

// Cloud metadata endpoints. These are PERMANENTLY blocked from direct fetch by
// security-judge itself — even if present in allowedUrls — so the tool can never
// be turned into an SSRF pivot toward instance credentials. (Note: SSRF *payloads*
// sent as request-body values to the target never pass through assertAllowedUrl.)
const CLOUD_METADATA_IPS = [
  '169.254.169.254',
  '100.100.100.200',
  'metadata.google.internal',
  'fd00:ec2::254',
]

// Normalize obfuscated IP representations to dotted-decimal so pattern checks work.
// Handles: decimal integer (2130706433), hex (0x7f000001), octal parts (0177.0.0.1),
// IPv4-in-IPv6 (::ffff:169.254.169.254), IPv6 hex pairs (::ffff:a9fe:a9fe).
function expandIp(host: string): string {
  // Strip IPv6 brackets: [::1] → ::1
  const h = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host

  // Decimal integer IP: 2130706433 → 127.0.0.1
  if (/^\d+$/.test(h)) {
    const n = parseInt(h, 10)
    if (n >= 0 && n <= 0xffffffff) {
      return [n >>> 24 & 0xff, n >>> 16 & 0xff, n >>> 8 & 0xff, n & 0xff].join('.')
    }
  }

  // Hex IP: 0x7f000001 → 127.0.0.1
  if (/^0x[0-9a-f]+$/i.test(h)) {
    const n = parseInt(h, 16)
    if (!isNaN(n) && n >= 0 && n <= 0xffffffff) {
      return [n >>> 24 & 0xff, n >>> 16 & 0xff, n >>> 8 & 0xff, n & 0xff].join('.')
    }
  }

  // Octal parts: 0177.0.0.1 → 127.0.0.1
  if (/^0\d/.test(h) && h.includes('.')) {
    const parts = h.split('.')
    const dec = parts.map(p => parseInt(p, p.startsWith('0') && p.length > 1 ? 8 : 10))
    if (dec.length === 4 && dec.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
      return dec.join('.')
    }
  }

  // IPv4-mapped IPv6 with dotted decimal: ::ffff:169.254.169.254
  const v4mapped = h.match(/^(?:(?:0{0,4}:)+)(?:ffff:)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/i)
  if (v4mapped) return v4mapped[1]

  // IPv4-mapped IPv6 with hex pairs: ::ffff:a9fe:a9fe → 169.254.169.254
  const v4hex = h.match(/^(?:(?:0{0,4}:)+)(?:ffff:)?([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i)
  if (v4hex) {
    const hi = parseInt(v4hex[1], 16)
    const lo = parseInt(v4hex[2], 16)
    return [hi >> 8 & 0xff, hi & 0xff, lo >> 8 & 0xff, lo & 0xff].join('.')
  }

  return h
}

const DEFAULT_PORTS: Record<string, string> = {
  'http:': '80',
  'https:': '443',
}

function effectivePort(u: URL): string {
  return u.port !== '' ? u.port : (DEFAULT_PORTS[u.protocol] ?? '')
}

/**
 * True if the URL's host is a known cloud-metadata endpoint. Used to permanently
 * block direct fetches regardless of allowedUrls.
 */
export function isCloudMetadataUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr)
    const rawHost = u.hostname.toLowerCase()
    const host = expandIp(rawHost)
    return CLOUD_METADATA_IPS.some(ip => host === ip || rawHost === ip)
  } catch {
    return true
  }
}

/**
 * True if the URL's host is a private / loopback / link-local address.
 * Informational only (e.g. report annotations); NOT used as a block decision,
 * since private targets are legitimate under the local-CLI threat model.
 */
export function isPrivateUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr)
    const rawHost = u.hostname.toLowerCase()
    const host = expandIp(rawHost)
    return PRIVATE_IP_PATTERNS.some(p => p.test(host) || p.test(rawHost))
  } catch {
    return true
  }
}

/**
 * True if the URL exactly matches one of the operator-designated targets.
 * Match is on parsed protocol + normalized host + effective port — NOT string
 * prefix — so userinfo tricks and suffix/prefix look-alikes cannot pass.
 */
function matchesAllowed(u: URL, allowedUrls: string[]): boolean {
  const host = expandIp(u.hostname.toLowerCase())
  const port = effectivePort(u)
  return allowedUrls.some(base => {
    let b: URL
    try {
      b = new URL(base)
    } catch {
      return false
    }
    return (
      u.protocol === b.protocol &&
      host === expandIp(b.hostname.toLowerCase()) &&
      port === effectivePort(b)
    )
  })
}

/**
 * Guard every URL that security-judge fetches directly.
 *
 * Order (local-CLI threat model — operator == target owner):
 *   1. Parse. Unparseable → block.
 *   2. Cloud-metadata host → block permanently (allowedUrls cannot override).
 *   3. Exact host:port match against allowedUrls → allow (this membership IS the
 *      operator's explicit opt-in; private/loopback targets are thus reachable).
 *   4. Otherwise → block.
 */
export function assertAllowedUrl(urlStr: string, allowedUrls: string[]): void {
  let u: URL
  try {
    u = new URL(urlStr)
  } catch {
    throw new Error(`[url_guard] Blocked: ${urlStr} is not a valid URL.`)
  }

  if (isCloudMetadataUrl(urlStr)) {
    throw new Error(
      `[url_guard] Blocked: ${urlStr} is a cloud-metadata endpoint. ` +
      `security-judge must never fetch it directly (SSRF payloads are sent to the target as data instead).`
    )
  }

  if (!matchesAllowed(u, allowedUrls)) {
    throw new Error(
      `[url_guard] Blocked: ${urlStr} is not the designated target. Allowed: ${allowedUrls.join(', ') || '(none)'}`
    )
  }
}

export function extractBaseUrl(urlStr: string): string {
  try {
    const u = new URL(urlStr)
    return `${u.protocol}//${u.host}`
  } catch {
    throw new Error(`Invalid URL: ${urlStr}`)
  }
}
