import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const FIXTURES = join(__dirname, '../fixtures')

vi.mock('../../src/recon/language_detector.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/recon/language_detector.js')>()
  return {
    ...actual,
    detectLanguages: vi.fn(actual.detectLanguages),
    detectLanguage: vi.fn(actual.detectLanguage),
  }
})

describe('extractEndpoints', () => {
  let extractEndpoints: typeof import('../../src/recon/endpoint_extractor.js').extractEndpoints
  let detectLanguages: ReturnType<typeof vi.fn>

  beforeEach(async () => {
    const mod = await import('../../src/recon/endpoint_extractor.js')
    extractEndpoints = mod.extractEndpoints
    const ldMod = await import('../../src/recon/language_detector.js')
    detectLanguages = vi.mocked(ldMod.detectLanguages)
  })

  afterEach(() => {
    vi.clearAllMocks()
  })

  it('returns [] when detectLanguages returns an unknown language with no analyzer', async () => {
    detectLanguages.mockReturnValue([{ language: 'cobol' as never, confidence: 'low' }])
    const result = await extractEndpoints(join(FIXTURES, 'node'))
    expect(result).toEqual([])
  })

  it('returns endpoints normally when language has an analyzer', async () => {
    detectLanguages.mockReturnValue([{ language: 'javascript', confidence: 'high' }])
    const result = await extractEndpoints(join(FIXTURES, 'node'))
    expect(result.length).toBeGreaterThan(0)
  })
})
