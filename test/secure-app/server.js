/**
 * HARDENED counterpart of test/target-app for E2E SPECIFICITY testing.
 * Same endpoint surface as the vulnerable app, but each of the 8 vulnerability
 * classes is remediated. security-judge should produce a LOW detection score here.
 * A tool that flags this app is false-positiving.
 */
import express from 'express'
import { URL } from 'url'

const app = express()
app.use(express.json())

// Secret from environment — never hardcoded.
const API_KEY = process.env.API_KEY || ''
const PORT = process.env.PORT || 3838

// Security headers on every response.
app.use((req, res, next) => {
  res.setHeader('Strict-Transport-Security', 'max-age=63072000; includeSubDomains')
  res.setHeader('Content-Security-Policy', "default-src 'self'")
  res.setHeader('X-Content-Type-Options', 'nosniff')
  res.setHeader('X-Frame-Options', 'DENY')
  res.setHeader('Referrer-Policy', 'no-referrer')
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=()')
  next()
})

// No plaintext secrets stored on the user record (hardened).
const users = [
  { id: 1, name: 'Alice', email: 'alice@example.com', role: 'user' },
  { id: 2, name: 'Bob', email: 'bob@example.com', role: 'user' },
  { id: 99, name: 'Admin', email: 'admin@example.com', role: 'admin' },
]

const tokens = new Map([
  ['user-token-alice', 1],
  ['user-token-bob', 2],
  ['admin-token', 99],
])

function getUserFromToken(req) {
  const auth = req.headers.authorization || ''
  const token = auth.replace('Bearer ', '')
  const userId = tokens.get(token)
  return users.find(u => u.id === userId) ?? null
}

// Public view of a user — never exposes the `secret` field.
function publicView(u) {
  return { id: u.id, name: u.name, email: u.email, role: u.role }
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})

// FIXED: authentication + ownership check; no secret leak.
app.get('/api/users/:id', (req, res) => {
  const caller = getUserFromToken(req)
  if (!caller) return res.status(401).json({ error: 'Unauthorized' })

  const id = parseInt(req.params.id, 10)
  if (caller.id !== id && caller.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' })
  }
  const user = users.find(u => u.id === id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  res.json(publicView(user))
})

// FIXED: allow-list of updatable fields; role/secret can never be set from the body.
app.post('/api/users/:id/update', (req, res) => {
  const caller = getUserFromToken(req)
  if (!caller) return res.status(401).json({ error: 'Unauthorized' })
  const id = parseInt(req.params.id, 10)
  if (caller.id !== id && caller.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' })
  }
  const user = users.find(u => u.id === id)
  if (!user) return res.status(404).json({ error: 'Not found' })

  const ALLOWED = ['name', 'email']
  for (const field of ALLOWED) {
    if (typeof req.body[field] === 'string') user[field] = req.body[field]
  }
  res.json(publicView(user))
})

// FIXED: only an admin may change roles; body role/isAdmin is ignored for non-admins.
app.put('/api/users/:id/role', (req, res) => {
  const caller = getUserFromToken(req)
  if (!caller || caller.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' })
  }
  const id = parseInt(req.params.id, 10)
  const user = users.find(u => u.id === id)
  if (!user) return res.status(404).json({ error: 'Not found' })
  const nextRole = req.body.role
  if (nextRole === 'user' || nextRole === 'admin') user.role = nextRole
  res.json({ success: true, role: user.role })
})

// FIXED: constant-time-ish generic error; never leaks stack traces.
app.post('/api/login', (req, res) => {
  const { email } = req.body || {}
  if (typeof email !== 'string') {
    return res.status(400).json({ error: 'Invalid request' })
  }
  const user = users.find(u => u.email === email)
  if (!user) return res.status(401).json({ error: 'Invalid credentials' })
  res.json({ token: `user-token-${user.name.toLowerCase()}` })
})

// FIXED: SSRF egress filter — reject private/loopback/link-local/metadata WITHOUT
// attempting any outbound connection.
function isBlockedHost(hostname) {
  // Strip IPv6 brackets so [::1] is normalized to ::1 before comparison.
  const h = hostname.toLowerCase().replace(/^\[/, '').replace(/\]$/, '')
  return (
    h === 'localhost' ||
    /^127\./.test(h) ||
    /^10\./.test(h) ||
    /^192\.168\./.test(h) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    /^169\.254\./.test(h) ||
    h === '::1' ||
    h === '100.100.100.200' ||
    h === 'metadata.google.internal'
  )
}

app.post('/api/fetch', (req, res) => {
  const { url } = req.body || {}
  if (!url) return res.status(400).json({ error: 'url required' })
  let parsed
  try {
    parsed = new URL(url)
  } catch {
    return res.status(400).json({ error: 'invalid url' })
  }
  if (!/^https?:$/.test(parsed.protocol) || isBlockedHost(parsed.hostname)) {
    // Refuse without connecting — no network-level error is ever surfaced.
    return res.status(400).json({ error: 'url not allowed' })
  }
  // A real app would fetch allow-listed hosts here; for the test we simply accept.
  res.json({ status: 'ok', note: 'fetch to allow-listed host would occur' })
})

// FIXED: the assistant refuses to reveal its system prompt.
app.post('/api/chat', (req, res) => {
  const { message } = req.body || {}
  const text = typeof message === 'string' ? message : ''
  if (/system prompt|instructions|ignore (all|previous)/i.test(text)) {
    return res.json({ reply: "I can't share my configuration, but I'm happy to help with your question." })
  }
  res.json({ reply: `Echo: ${text}` })
})

app.listen(PORT, () => {
  process.stderr.write(`[secure-app] Hardened test server running on port ${PORT}\n`)
})

export { app }
