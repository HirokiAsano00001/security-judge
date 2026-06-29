import { describe, it, expect } from 'vitest'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { mkdirSync, writeFileSync, rmSync } from 'fs'
import { detectLanguage } from '../../src/recon/language_detector.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const TMP = join(__dirname, '../.tmp-lang-detect')

function setupDir(files: string[]): string {
  mkdirSync(TMP, { recursive: true })
  for (const f of files) {
    const full = join(TMP, f)
    mkdirSync(dirname(full), { recursive: true })
    writeFileSync(full, `// ${f}`)
  }
  return TMP
}

function cleanup() {
  try { rmSync(TMP, { recursive: true, force: true }) } catch { /* ignore */ }
}

describe('detectLanguage', () => {
  it('detects Java via pom.xml', () => {
    const dir = setupDir(['pom.xml', 'src/Main.java'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('java')
      expect(result.confidence).toBe('high')
    } finally { cleanup() }
  })

  it('detects Go via go.mod', () => {
    const dir = setupDir(['go.mod', 'main.go'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('go')
      expect(result.confidence).toBe('high')
    } finally { cleanup() }
  })

  it('detects Ruby via Gemfile', () => {
    const dir = setupDir(['Gemfile', 'app/controllers/api.rb'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('ruby')
      expect(result.confidence).toBe('high')
    } finally { cleanup() }
  })

  it('detects Python via requirements.txt', () => {
    const dir = setupDir(['requirements.txt', 'app.py'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('python')
      expect(result.confidence).toBe('high')
    } finally { cleanup() }
  })

  it('detects TypeScript via package.json with .ts files', () => {
    const dir = setupDir(['package.json', 'src/index.ts', 'src/app.ts'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('typescript')
    } finally { cleanup() }
  })

  it('detects JavaScript via package.json with .js files', () => {
    const dir = setupDir(['package.json', 'server.js', 'utils.js'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('javascript')
    } finally { cleanup() }
  })

  it('falls back to javascript for unknown project', () => {
    const dir = setupDir(['README.md'])
    try {
      const result = detectLanguage(dir)
      expect(result.language).toBe('javascript')
      expect(result.confidence).toBe('low')
    } finally { cleanup() }
  })
})
