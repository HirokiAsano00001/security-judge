import { existsSync, readdirSync } from 'fs'
import { join } from 'path'
import { type SupportedLanguage } from '../types/index.js'

interface DetectionResult {
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

export function detectLanguage(rootPath: string): DetectionResult {
  if (hasFile(rootPath, 'pom.xml') || hasFile(rootPath, 'build.gradle')) {
    return { language: 'java', confidence: 'high' }
  }

  if (hasFile(rootPath, 'go.mod')) {
    return { language: 'go', confidence: 'high' }
  }

  if (hasFile(rootPath, 'Gemfile')) {
    return { language: 'ruby', confidence: 'high' }
  }

  if (hasFile(rootPath, 'requirements.txt') || hasFile(rootPath, 'pyproject.toml')) {
    return { language: 'python', confidence: 'high' }
  }

  if (hasFile(rootPath, 'package.json')) {
    const tsCount = countFilesByExt(rootPath, '.ts')
    const jsCount = countFilesByExt(rootPath, '.js')
    if (tsCount > jsCount) {
      return { language: 'typescript', confidence: 'high' }
    }
    return { language: 'javascript', confidence: 'high' }
  }

  const javaCount = countFilesByExt(rootPath, '.java')
  if (javaCount > 0) return { language: 'java', confidence: 'medium' }

  const pyCount = countFilesByExt(rootPath, '.py')
  if (pyCount > 0) return { language: 'python', confidence: 'medium' }

  const goCount = countFilesByExt(rootPath, '.go')
  if (goCount > 0) return { language: 'go', confidence: 'medium' }

  return { language: 'javascript', confidence: 'low' }
}
