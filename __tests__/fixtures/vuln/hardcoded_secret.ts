// VULNERABILITY FIXTURE - for testing gitleaks / SAST detection
const API_KEY = 'sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCD'
const DB_PASSWORD = 'super_secret_password_123!'
const STRIPE_KEY = 'FAKE_STRIPE_KEY_FOR_GITLEAKS_TESTING_ONLY'

export function connectToService() {
  return fetch('https://api.example.com', {
    headers: { 'X-API-Key': API_KEY }
  })
}
