import { readdirSync, readFileSync } from 'fs'
import { join } from 'path'
import { type IAnalyzer, type EndpointInfo, type ParameterInfo } from '../../types/index.js'

const HTTP_METHODS = ['GetMapping', 'PostMapping', 'PutMapping', 'DeleteMapping', 'PatchMapping', 'RequestMapping']

function findJavaFiles(rootPath: string): string[] {
  const results: string[] = []
  function walk(dir: string) {
    try {
      for (const entry of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, entry.name)
        if (entry.isDirectory() && !entry.name.startsWith('.') && entry.name !== 'target') {
          walk(full)
        } else if (entry.isFile() && entry.name.endsWith('.java')) {
          results.push(full)
        }
      }
    } catch { /* skip unreadable dirs */ }
  }
  walk(rootPath)
  return results
}

export class JavaAnalyzer implements IAnalyzer {
  readonly language = 'java' as const

  async analyze(rootPath: string): Promise<EndpointInfo[]> {
    const files = findJavaFiles(rootPath)
    const endpoints: EndpointInfo[] = []

    for (const file of files) {
      try {
        const content = readFileSync(file, 'utf-8')
        const classPathMatch = content.match(/@RequestMapping\("([^"]+)"\)/)
        const classPath = classPathMatch?.[1] ?? ''

        for (const method of HTTP_METHODS) {
          const regex = new RegExp(`@${method}\\("([^"]*)"\\)`, 'g')
          let match: RegExpExecArray | null
          while ((match = regex.exec(content)) !== null) {
            const path = classPath + match[1]
            const httpMethod = method.replace('Mapping', '').toUpperCase()
            const params = extractParams(content, match.index)

            endpoints.push({
              method: httpMethod === 'REQUEST' ? 'GET' : httpMethod,
              path,
              parameters: params,
              authRequired: content.includes('@PreAuthorize') || content.includes('@Secured'),
              sourceLanguage: 'java',
            })
          }
        }
      } catch { /* skip unreadable files */ }
    }

    return endpoints
  }
}

function extractParams(content: string, methodOffset: number): ParameterInfo[] {
  const snippet = content.slice(methodOffset, methodOffset + 500)
  const params: ParameterInfo[] = []

  const pathVarRegex = /@PathVariable(?:\([^)]*\))?\s+\w+\s+(\w+)/g
  let m: RegExpExecArray | null
  while ((m = pathVarRegex.exec(snippet)) !== null) {
    params.push({ name: m[1], in: 'path', required: true, type: 'string' })
  }

  const reqParamRegex = /@RequestParam(?:\([^)]*\))?\s+\w+\s+(\w+)/g
  while ((m = reqParamRegex.exec(snippet)) !== null) {
    params.push({ name: m[1], in: 'query', required: false, type: 'string' })
  }

  return params
}
