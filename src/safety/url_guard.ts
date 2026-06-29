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
]

const CLOUD_METADATA_IPS = [
  '169.254.169.254',
  '100.100.100.200',
  'metadata.google.internal',
]

export function isPrivateOrMetadataUrl(urlStr: string): boolean {
  try {
    const u = new URL(urlStr)
    const host = u.hostname.toLowerCase()

    if (CLOUD_METADATA_IPS.some(ip => host === ip)) return true

    for (const pattern of PRIVATE_IP_PATTERNS) {
      if (pattern.test(host)) return true
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
