import { readdirSync, readFileSync } from 'fs'
import { join } from 'path'
import { type IAnalyzer, type EndpointInfo, type ParameterInfo } from '../../types/index.js'

function findNodeFiles(rootPath: string): string[] {
  const results: string[] = []
  const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage'])

  function walk(dir: string) {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name)
        if (entry.isDirectory() && !SKIP_DIRS.has(entry.name)) {
          walk(full)
        } else if (entry.isFile() && (entry.name.endsWith('.ts') || entry.name.endsWith('.js'))) {
          results.push(full)
        }
      }
    } catch { /* skip */ }
  }

  walk(rootPath)
  return results
}

const ROUTE_REGEX = /(?:app|router)\.(get|post|put|patch|delete|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi

export class NodeAnalyzer implements IAnalyzer {
  readonly language = 'typescript' as const

  async analyze(rootPath: string): Promise<EndpointInfo[]> {
    const files = findNodeFiles(rootPath)
    const endpoints: EndpointInfo[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8')
        const regex = new RegExp(ROUTE_REGEX.source, 'gi')
        let match: RegExpExecArray | null

        while ((match = regex.exec(content)) !== null) {
          const method = match[1].toUpperCase()
          const path = match[2]
          const params = extractPathParams(path)

          endpoints.push({
            method,
            path,
            parameters: params,
            authRequired: /middleware|auth|jwt|bearer/i.test(content.slice(0, match.index)),
            sourceLanguage: file.endsWith('.ts') ? 'typescript' : 'javascript',
          })
        }
      } catch { /* skip */ }
    }

    return endpoints
  }
}

function extractPathParams(path: string): ParameterInfo[] {
  const params: ParameterInfo[] = []
  const paramRegex = /:(\w+)/g
  let m: RegExpExecArray | null

  while ((m = paramRegex.exec(path)) !== null) {
    params.push({ name: m[1], in: 'path', required: true, type: 'string' })
  }

  return params
}
