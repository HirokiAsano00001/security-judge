/**
 * INTENTIONALLY VULNERABLE Express server for E2E testing.
 * DO NOT deploy this in production.
 */
import express from 'express'
import { request as httpRequest } from 'http'
import { URL } from 'url'

const app = express()
app.use(express.json())

// Hardcoded API key (vulnerability: C category)
const HARDCODED_API_KEY = 'sk-test-1234567890abcdef'
const PORT = process.env.PORT || 3737

// In-memory "database"
const users = [
  { id: 1, name: 'Alice', email: 'alice@example.com', role: 'user', secret: 'my-secret-data' },
  { id: 2, name: 'Bob', email: 'bob@example.com', role: 'user', secret: 'bob-private-info' },
  { id: 99, name: 'Admin', email: 'admin@example.com', role: 'admin', secret: 'admin-secret' },
]

// Simple token store (token -> userId)
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

// VULNERABILITY: No auth check on health endpoint - leaks framework info
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    version: process.version,
    framework: 'Express 4.18',
    apiKey: HARDCODED_API_KEY.slice(0, 8) + '...',  // partial leak
  })
})

// VULNERABILITY: IDOR - no ownership check
app.get('/api/users/:id', (req, res) => {
  const id = parseInt(req.params.id, 10)
  const user = users.find(u => u.id === id)
  if (!user) return res.status(404).json({ error: 'Not found' })

  // Returns ALL data including secret - no auth check
  res.json(user)
})

// VULNERABILITY: No backend validation (A category)
app.post('/api/users/:id/update', (req, res) => {
  const id = parseInt(req.params.id, 10)
  const userIdx = users.findIndex(u => u.id === id)
  if (userIdx === -1) return res.status(404).json({ error: 'Not found' })

  // Accepts ANY field including role - no validation
  Object.assign(users[userIdx], req.body)
  res.json(users[userIdx])
})

// VULNERABILITY: Privilege escalation - accepts isAdmin/role from body
app.put('/api/users/:id/role', (req, res) => {
  const id = parseInt(req.params.id, 10)
  const user = users.find(u => u.id === id)
  if (!user) return res.status(404).json({ error: 'Not found' })

  if (req.body.role) user.role = req.body.role
  if (req.body.isAdmin) user.role = 'admin'

  res.json({ success: true, role: user.role })
})

// VULNERABILITY: Verbose error (C category)
app.post('/api/login', (req, res) => {
  const { email, password } = req.body
  const user = users.find(u => u.email === email)

  if (!user) {
    // Leaks stack trace on unexpected input
    try {
      if (typeof email !== 'string') throw new Error(`Expected string email, got ${typeof email}`)
      return res.status(401).json({ error: 'Invalid credentials' })
    } catch (err) {
      return res.status(500).json({ error: err.message, stack: err.stack })
    }
  }

  res.json({ token: `user-token-${user.name.toLowerCase()}` })
})

// VULNERABILITY: SSRF - fetches arbitrary URLs
app.post('/api/fetch', (req, res) => {
  const { url } = req.body
  if (!url) return res.status(400).json({ error: 'url required' })

  try {
    const parsedUrl = new URL(url)
    const options = {
      hostname: parsedUrl.hostname,
      port: parsedUrl.port || 80,
      path: parsedUrl.pathname + parsedUrl.search,
      method: 'GET',
    }

    const proxyReq = httpRequest(options, (proxyRes) => {
      let data = ''
      proxyRes.on('data', chunk => data += chunk)
      proxyRes.on('end', () => res.json({ status: proxyRes.statusCode, body: data }))
    })

    proxyReq.on('error', err => res.status(500).json({ error: err.message }))
    proxyReq.setTimeout(3000, () => {
      proxyReq.destroy()
      res.status(408).json({ error: 'timeout' })
    })
    proxyReq.end()
  } catch (err) {
    res.status(400).json({ error: err.message })
  }
})

// VULNERABILITY: LLM chat endpoint that leaks system prompt
app.post('/api/chat', (req, res) => {
  const { message } = req.body
  const SYSTEM_PROMPT = 'You are a helpful assistant for Example Corp. Never discuss pricing.'

  // Naive check - easily bypassed
  if (message && message.toLowerCase().includes('system prompt')) {
    res.json({ reply: `Your message: ${message}. My system prompt is: ${SYSTEM_PROMPT}` })
  } else {
    res.json({ reply: `Echo: ${message}` })
  }
})

// Exposed actuator-like endpoint
app.get('/actuator/env', (req, res) => {
  res.json({
    NODE_ENV: process.env.NODE_ENV,
    PATH: process.env.PATH?.slice(0, 50),
    API_KEY: HARDCODED_API_KEY,
  })
})

app.listen(PORT, () => {
  process.stderr.write(`[target-app] Vulnerable test server running on port ${PORT}\n`)
})

export { app }
