import { existsSync, readdirSync } from 'fs'
import { join } from 'path'
import { type SupportedLanguage } from '../types/index.js'

export interface DetectionResult {
  language: SupportedLanguage
  confidence: 'high' | 'medium' | 'low'
}

function hasFile(rootPath: string, filename: string): boolean {
  return existsSync(join(rootPath, filename))
}

function countFilesByExt(rootPath: string, ext: string): number {
  try {
    const entries = readdirSync(rootPath, { recursive: true }) as string[]
    return entries.filter(e => String(e).endsWith(ext)).length
  } catch {
    return 0
  }
}

export function detectLanguages(rootPath: string): DetectionResult[] {
  const results: DetectionResult[] = []

  if (hasFile(rootPath, 'pom.xml') || hasFile(rootPath, 'build.gradle') || hasFile(rootPath, 'build.gradle.kts')) {
    results.push({ language: 'java', confidence: 'high' })
  }

  if (hasFile(rootPath, 'go.mod')) {
    results.push({ language: 'go', confidence: 'high' })
  }

  if (hasFile(rootPath, 'Gemfile')) {
    results.push({ language: 'ruby', confidence: 'high' })
  }

  if (hasFile(rootPath, 'requirements.txt') || hasFile(rootPath, 'pyproject.toml') || hasFile(rootPath, 'setup.py')) {
    results.push({ language: 'python', confidence: 'high' })
  }

  if (hasFile(rootPath, 'package.json')) {
    const tsCount = countFilesByExt(rootPath, '.ts')
    const jsCount = countFilesByExt(rootPath, '.js')
    if (tsCount > jsCount) {
      results.push({ language: 'typescript', confidence: 'high' })
    } else {
      results.push({ language: 'javascript', confidence: 'high' })
    }
  }

  if (results.length > 0) return results

  const byExt: Array<{ lang: SupportedLanguage; ext: string }> = [
    { lang: 'java', ext: '.java' },
    { lang: 'python', ext: '.py' },
    { lang: 'go', ext: '.go' },
    { lang: 'ruby', ext: '.rb' },
    { lang: 'typescript', ext: '.ts' },
    { lang: 'javascript', ext: '.js' },
  ]

  for (const { lang, ext } of byExt) {
    if (countFilesByExt(rootPath, ext) > 0) {
      results.push({ language: lang, confidence: 'medium' })
    }
  }

  if (results.length === 0) {
    results.push({ language: 'javascript', confidence: 'low' })
  }

  return results
}

export function detectLanguage(rootPath: string): DetectionResult {
  return detectLanguages(rootPath)[0]
}
