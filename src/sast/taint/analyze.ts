import { readdirSync, readFileSync, statSync } from 'fs'
import { join } from 'path'
import { type Flow } from './types.js'
import { parseSource } from './parse.js'
import { analyzeSourceFile } from './engine.js'
import { isAnalyzableExt } from './script_kind.js'

const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'target', '__pycache__', 'vendor', 'coverage', 'build'])

function extOf(name: string): string {
  return name.split('.').pop() ?? ''
}

function analyzeOneFile(full: string, flows: Flow[]): void {
  try {
    const content = readFileSync(full, 'utf-8')
    const sf = parseSource(content, full)
    flows.push(...analyzeSourceFile(sf, full))
  } catch {
    // Skip unreadable/unparseable files.
  }
}

/**
 * Analyze a TS/JS source tree — or a single TS/JS file — and collect taint flows.
 * Per-file read/parse errors are swallowed and the walk continues (matching
 * analyze_sast_deep).
 */
export function analyzeFiles(rootPath: string): Flow[] {
  const flows: Flow[] = []

  // Accept a single file path as well as a directory.
  try {
    if (statSync(rootPath).isFile()) {
      if (isAnalyzableExt(extOf(rootPath))) analyzeOneFile(rootPath, flows)
      return flows
    }
  } catch {
    return flows // non-existent path
  }

  const walk = (dir: string): void => {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of entries) {
      const full = join(dir, entry.name)
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(full)
        continue
      }
      if (!entry.isFile()) continue
      if (!isAnalyzableExt(extOf(entry.name))) continue
      analyzeOneFile(full, flows)
    }
  }

  walk(rootPath)
  return flows
}
