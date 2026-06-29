import { readdirSync, readFileSync } from 'fs'
import { join } from 'path'
import { type IAnalyzer, type EndpointInfo } from '../../types/index.js'

function findRubyFiles(rootPath: string): string[] {
  const results: string[] = []
  const SKIP = new Set(['.git', '.bundle', 'vendor', 'tmp'])

  function walk(dir: string) {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name)
        if (entry.isDirectory() && !SKIP.has(entry.name)) walk(full)
        else if (entry.isFile() && entry.name.endsWith('.rb')) results.push(full)
      }
    } catch { /* skip */ }
  }

  walk(rootPath)
  return results
}

export class RubyAnalyzer implements IAnalyzer {
  readonly language = 'ruby' as const

  async analyze(rootPath: string): Promise<EndpointInfo[]> {
    const files = findRubyFiles(rootPath)
    const endpoints: EndpointInfo[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8')

        // Rails routes.rb: get '/path', to: 'controller#action'
        // Sinatra: get '/path' do
        const routeRegex = /(?:get|post|put|patch|delete)\s+['"]([^'"]+)['"]/gi
        let m: RegExpExecArray | null

        while ((m = routeRegex.exec(content)) !== null) {
          const method = m[0].split(/\s/)[0].toUpperCase()
          const path = m[1]

          endpoints.push({
            method,
            path,
            parameters: [],
            authRequired: /before_action|authenticate/i.test(content),
            sourceLanguage: 'ruby' as never,
          })
        }
      } catch { /* skip */ }
    }

    return endpoints
  }
}
