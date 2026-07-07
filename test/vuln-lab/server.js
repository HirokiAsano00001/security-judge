/**
 * INTENTIONALLY VULNERABLE lab with ONE endpoint per security-judge detection tool.
 * Used by the per-vulnerability E2E matrix (__tests__/e2e/vuln-matrix.e2e.test.ts).
 * DO NOT deploy. Each endpoint is deliberately broken so the matching tool fires.
 */
import express from 'express'
import { request as httpRequest } from 'http'
import { readFileSync } from 'fs'
import { URL } from 'url'

const app = express()
app.use(express.json())

// SAST sink #1: hardcoded secret.
const API_KEY = 'sk-live-9f8e7d6c5b4a3210deadbeefcafef00d'
const PORT = process.env.PORT || 3939

// VULN (test_cors): reflect ANY Origin with credentials, on every response.
// Also note: NO security headers set anywhere (VULN for check_security_headers).
app.use((req, res, next) => {
  const origin = req.headers.origin
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin)
    res.setHeader('Access-Control-Allow-Credentials', 'true')
  }
  next()
})

const docs = [
  { id: 1, owner: 'alice', content: 'Alice private notes', secret: 'doc-secret-1' },
  { id: 2, owner: 'bob', content: 'Bob private notes', secret: 'doc-secret-2' },
]
const accounts = [
  { id: 1, name: 'Alice', role: 'user' },
  { id: 2, name: 'Bob', role: 'user' },
]

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'vuln-lab' })
})

// VULN (fuzz_api_direct → SQLi): raw string-concatenation query; DB error on a quote.
app.get('/sqli', (req, res) => {
  const q = String(req.query.q ?? '')
  // SAST sink #2: SQL built by string concatenation.
  const query = "SELECT * FROM products WHERE name = '" + q + "'"
  if (q.includes("'")) {
    return res.status(500).json({
      error: "You have an error in your SQL syntax; check the manual near '" + q + "'",
      query,
    })
  }
  res.json({ query, rows: [] })
})

// VULN (fuzz_api_direct → XSS): reflects input unescaped into HTML.
app.get('/xss', (req, res) => {
  const q = String(req.query.q ?? '')
  res.set('Content-Type', 'text/html').send(`<html><body>Results for: ${q}</body></html>`)
})

// VULN (test_bola_idor): no auth, no ownership check — returns any doc incl secret.
app.get('/api/docs/:id', (req, res) => {
  const id = parseInt(req.params.id, 10)
  const doc = docs.find(d => d.id === id)
  if (!doc) return res.status(404).json({ error: 'Not found' })
  res.json(doc)
})

// VULN (test_privilege_escalation): body role/isAdmin accepted (baseline body = current role).
app.put('/account/:id/role', (req, res) => {
  const id = parseInt(req.params.id, 10)
  const acct = accounts.find(a => a.id === id)
  if (!acct) return res.status(404).json({ error: 'Not found' })
  if (req.body && req.body.role) acct.role = req.body.role
  if (req.body && req.body.isAdmin) acct.role = 'admin'
  res.json({ success: true, role: acct.role })
})

// VULN (test_jwt_tampering): decodes the JWT WITHOUT verifying the signature.
// Requires some token (401 otherwise, so the "no token" probe does not false-positive).
app.get('/jwt/profile', (req, res) => {
  const token = (req.headers.authorization || '').replace('Bearer ', '')
  if (!token) return res.status(401).json({ error: 'token required' })
  const parts = token.split('.')
  if (parts.length < 2) return res.status(401).json({ error: 'malformed token' })
  try {
    const payload = JSON.parse(Buffer.from(parts[1], 'base64').toString('utf-8'))
    // No signature check, no exp check, no alg check — trusts the token blindly.
    res.json({ user: payload.sub ?? 'unknown', role: payload.role ?? 'user' })
  } catch {
    res.status(401).json({ error: 'invalid token' })
  }
})

// VULN (test_ssrf): fetches an arbitrary attacker-supplied URL.
app.post('/proxy', (req, res) => {
  const { url } = req.body || {}
  if (!url) return res.status(400).json({ error: 'url required' })
  let parsed
  try {
    parsed = new URL(url)
  } catch (err) {
    return res.status(400).json({ error: err.message })
  }
  const respond = (fn) => { if (!res.headersSent) fn() }
  const options = { hostname: parsed.hostname, port: parsed.port || 80, path: parsed.pathname + parsed.search, method: 'GET' }
  const proxyReq = httpRequest(options, (proxyRes) => {
    let data = ''
    proxyRes.on('data', c => data += c)
    proxyRes.on('end', () => respond(() => res.json({ status: proxyRes.statusCode, body: data })))
  })
  proxyReq.on('error', err => respond(() => res.status(500).json({ error: err.message })))
  proxyReq.setTimeout(3000, () => { proxyReq.destroy(); respond(() => res.status(408).json({ error: 'timeout' })) })
  proxyReq.end()
})

// VULN (inject_llm_jailbreak): leaks its system prompt when asked.
app.post('/assistant', (req, res) => {
  const message = (req.body && typeof req.body.message === 'string') ? req.body.message : ''
  const SYSTEM_PROMPT = 'You are a helpful assistant for Example Corp. Never discuss internal pricing.'
  if (/system prompt|instructions/i.test(message)) {
    return res.json({ reply: `Sure. My system prompt is: ${SYSTEM_PROMPT}` })
  }
  res.json({ reply: `Echo: ${message}` })
})

// VULN (test_ssti): eval-based template evaluation of {{ ... }} expressions.
app.get('/render', (req, res) => {
  const name = String(req.query.name ?? '')
  const template = `Hello, ${name}!`
  // SAST sink #3: eval on user-influenced content.
  const rendered = template.replace(/\{\{(.+?)\}\}/g, (_, expr) => {
    try { return String(eval(expr)) } catch { return '' }
  })
  res.set('Content-Type', 'text/html').send(rendered)
})

// VULN (test_path_traversal): reads an arbitrary file path from user input.
app.get('/files', (req, res) => {
  const file = String(req.query.file ?? '')
  try {
    res.send(readFileSync(file, 'utf-8'))
  } catch {
    res.status(404).json({ error: 'not found' })
  }
})

// VULN (scan_exposed_endpoints): sensitive config exposed without auth.
app.get('/.env', (req, res) => {
  res.set('Content-Type', 'text/plain').send(`API_KEY=${API_KEY}\nDATABASE_URL=postgres://admin:hunter2@db/prod\nSECRET=topsecret`)
})
app.get('/actuator/env', (req, res) => {
  res.json({ NODE_ENV: process.env.NODE_ENV, API_KEY, password: 'db-password-123' })
})
app.get('/swagger.json', (req, res) => {
  res.json({ openapi: '3.0.0', info: { title: 'vuln-lab', version: '1.0.0' }, paths: { '/api/docs/{id}': { get: {} } } })
})

// VULN (analyze_sast_deep → mass assignment): Object.assign(target, req.body).
app.post('/account/:id/update', (req, res) => {
  const id = parseInt(req.params.id, 10)
  const acct = accounts.find(a => a.id === id)
  if (!acct) return res.status(404).json({ error: 'Not found' })
  Object.assign(acct, req.body)
  res.json(acct)
})

app.listen(PORT, () => {
  process.stderr.write(`[vuln-lab] Vulnerable lab server running on port ${PORT}\n`)
})

export { app }
