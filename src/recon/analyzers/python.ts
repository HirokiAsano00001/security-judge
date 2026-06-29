import { readdirSync, readFileSync } from 'fs'
import { join } from 'path'
import { type IAnalyzer, type EndpointInfo } from '../../types/index.js'

function findPyFiles(rootPath: string): string[] {
  const results: string[] = []
  const SKIP = new Set(['.git', '__pycache__', '.venv', 'venv'])

  function walk(dir: string) {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name)
        if (entry.isDirectory() && !SKIP.has(entry.name)) walk(full)
        else if (entry.isFile() && entry.name.endsWith('.py')) results.push(full)
      }
    } catch { /* skip */ }
  }

  walk(rootPath)
  return results
}

export class PythonAnalyzer implements IAnalyzer {
  readonly language = 'python' as const

  async analyze(rootPath: string): Promise<EndpointInfo[]> {
    const files = findPyFiles(rootPath)
    const endpoints: EndpointInfo[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8')

        // Flask/FastAPI style: @app.route('/path', methods=['GET'])
        const flaskRegex = /@(?:app|bp|router)\.(?:route|get|post|put|patch|delete)\s*\(\s*['"]([^'"]+)['"]/g
        let m: RegExpExecArray | null

        while ((m = flaskRegex.exec(content)) !== null) {
          const path = m[1]
          const methodMatch = content.slice(m.index, m.index + 200).match(/methods\s*=\s*\[['"](\w+)['"]\]/)
          const method = methodMatch?.[1] ?? 'GET'

          endpoints.push({
            method: method.toUpperCase(),
            path,
            parameters: [],
            authRequired: /login_required|jwt_required|requires_auth/i.test(content.slice(m.index, m.index + 300)),
            sourceLanguage: 'python' as never,
          })
        }
      } catch { /* skip */ }
    }

    return endpoints
  }
}
