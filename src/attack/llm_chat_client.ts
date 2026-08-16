// Chat transport for LLM red-team attacks.
//
// Supports the two request shapes real chat backends use — a single message
// field (legacy: { message: "..." }) and an OpenAI/Anthropic-style messages
// array ({ messages: [{role, content}, ...] }) — plus SSE streaming responses
// (text/event-stream with `data:` deltas). Every request is gated by
// assertAllowedUrl so the client can never be pointed off-target.

import { request } from 'undici'
import { assertAllowedUrl } from '../safety/url_guard.js'

export type WireFormat = 'single-field' | 'messages'

export interface ChatTurn {
  role: 'user' | 'assistant' | 'system'
  content: string
}

export interface ChatOptions {
  wireFormat?: WireFormat
  /** Field name for the outgoing message in single-field mode (default: "message"). */
  messageField?: string
  /** Explicit field to read the reply from; falls back to common shapes if unset. */
  responseField?: string
  token?: string
  headers?: Record<string, string>
}

export interface ChatResponse {
  statusCode: number
  /** Best-effort extracted assistant text. */
  text: string
  /** Raw response body (for evidence / debugging). */
  raw: string
}

function firstString(...vals: unknown[]): string | undefined {
  for (const v of vals) if (typeof v === 'string') return v
  return undefined
}

// Concatenate the content deltas of an SSE stream (OpenAI/Anthropic-ish shapes).
function parseSse(raw: string): string {
  const chunks: string[] = []
  for (const line of raw.split(/\r?\n/)) {
    const m = line.match(/^data:\s?(.*)$/)
    if (!m) continue
    const payload = m[1].trim()
    if (payload === '' || payload === '[DONE]') continue
    try {
      const j = JSON.parse(payload) as Record<string, any>
      const delta = firstString(
        j?.choices?.[0]?.delta?.content,
        j?.choices?.[0]?.message?.content,
        j?.delta?.text,
        j?.delta?.content,
        j?.content,
        j?.text
      )
      if (delta !== undefined) chunks.push(delta)
    } catch {
      // Non-JSON data line: treat the raw payload as text.
      chunks.push(payload)
    }
  }
  return chunks.join('')
}

export function extractAssistantText(raw: string, contentType: string, responseField?: string): string {
  if (contentType.includes('text/event-stream') || /^\s*(event:|data:)/.test(raw)) {
    const sse = parseSse(raw)
    if (sse) return sse
  }

  try {
    const j = JSON.parse(raw) as Record<string, any>
    if (responseField && typeof j?.[responseField] === 'string') return j[responseField]

    const anthropicBlocks = Array.isArray(j?.content)
      ? j.content.map((c: any) => (typeof c?.text === 'string' ? c.text : '')).join('')
      : undefined

    const cand = firstString(
      j?.choices?.[0]?.message?.content,
      j?.choices?.[0]?.delta?.content,
      anthropicBlocks,
      j?.reply,
      j?.message,
      j?.response,
      j?.text,
      j?.content,
      j?.answer,
      j?.output,
      j?.result,
      j?.data
    )
    return cand ?? raw
  } catch {
    return raw
  }
}

export async function sendChat(
  url: string,
  conversation: ChatTurn[],
  opts: ChatOptions,
  allowedUrls: string[]
): Promise<ChatResponse> {
  assertAllowedUrl(url, allowedUrls)

  const wire = opts.wireFormat ?? 'single-field'
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
    ...(opts.headers ?? {}),
  }
  if (opts.token) headers['Authorization'] = `Bearer ${opts.token}`

  let body: string
  if (wire === 'messages') {
    body = JSON.stringify({ messages: conversation })
  } else {
    const lastUser = [...conversation].reverse().find((t) => t.role === 'user')
    body = JSON.stringify({ [opts.messageField ?? 'message']: lastUser?.content ?? '' })
  }

  const res = await request(url, { method: 'POST', headers, body })
  const raw = await res.body.text()
  const contentType = String(res.headers['content-type'] ?? '')
  const text = extractAssistantText(raw, contentType, opts.responseField)

  return { statusCode: res.statusCode, text, raw }
}
