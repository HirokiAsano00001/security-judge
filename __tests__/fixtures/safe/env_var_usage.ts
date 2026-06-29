// SAFE FIXTURE - environment variable usage (no hardcoded secrets)
const apiKey = process.env.API_KEY
if (!apiKey) {
  throw new Error('API_KEY environment variable is required')
}

export function connectToService() {
  return fetch('https://api.example.com', {
    headers: { 'X-API-Key': apiKey }
  })
}
