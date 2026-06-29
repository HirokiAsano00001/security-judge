import { readdirSync, readFileSync } from 'fs'
import { join } from 'path'
import { type IAnalyzer, type EndpointInfo } from '../../types/index.js'

function findGoFiles(rootPath: string): string[] {
  const results: string[] = []
  const SKIP = new Set(['.git', 'vendor'])

  function walk(dir: string) {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name)
        if (entry.isDirectory() && !SKIP.has(entry.name)) walk(full)
        else if (entry.isFile() && entry.name.endsWith('.go')) results.push(full)
      }
    } catch { /* skip */ }
  }

  walk(rootPath)
  return results
}

export class GoAnalyzer implements IAnalyzer {
  readonly language = 'go' as const

  async analyze(rootPath: string): Promise<EndpointInfo[]> {
    const files = findGoFiles(rootPath)
    const endpoints: EndpointInfo[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8')

        // net/http mux style: mux.HandleFunc("/path", handler)
        // gorilla/mux: r.HandleFunc("/path", handler).Methods("GET")
        const handleRegex = /(?:r|mux|router|http)\.(?:Handle|HandleFunc)\s*\(\s*["']([^"']+)["']/g
        let m: RegExpExecArray | null

        while ((m = handleRegex.exec(content)) !== null) {
          const path = m[1]
          const methodSnippet = content.slice(m.index, m.index + 300)
          const methodMatch = methodSnippet.match(/\.Methods\s*\(\s*["'](\w+)["']\s*\)/)
          const method = methodMatch?.[1] ?? 'GET'

          endpoints.push({
            method: method.toUpperCase(),
            path,
            parameters: [],
            authRequired: /auth|middleware|jwt/i.test(methodSnippet),
            sourceLanguage: 'go' as never,
          })
        }
      } catch { /* skip */ }
    }

    return endpoints
  }
}
