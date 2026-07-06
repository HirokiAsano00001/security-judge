import { URL } from 'url'

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

export function isPrivateOrMetadataUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr)
    const rawHost = u.hostname.toLowerCase()
    const host = expandIp(rawHost)

    if (CLOUD_METADATA_IPS.some(ip => host === ip || rawHost === ip)) return true

    for (const pattern of PRIVATE_IP_PATTERNS) {
      if (pattern.test(host) || pattern.test(rawHost)) return true
    }

    return false
  } catch {
    return true
  }
}

export function assertAllowedUrl(urlStr: string, allowedUrls: string[]): void {
  if (isPrivateOrMetadataUrl(urlStr)) {
    throw new Error(`[url_guard] Blocked: ${urlStr} is a private/metadata IP. security-judge itself must not send requests there.`)
  }

  const isAllowed = allowedUrls.some(base => urlStr.startsWith(base))
  if (!isAllowed) {
    throw new Error(`[url_guard] Blocked: ${urlStr} is not in allowedUrls. Allowed: ${allowedUrls.join(', ')}`)
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
