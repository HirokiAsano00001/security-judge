import { type EndpointInfo, type SupportedLanguage } from '../types/index.js'
import { detectLanguages } from './language_detector.js'
import { JavaAnalyzer } from './analyzers/java.js'
import { NodeAnalyzer } from './analyzers/node.js'
import { PythonAnalyzer } from './analyzers/python.js'
import { GoAnalyzer } from './analyzers/go.js'
import { RubyAnalyzer } from './analyzers/ruby.js'

const ANALYZERS: Record<SupportedLanguage, () => { analyze(path: string): Promise<EndpointInfo[]> }> = {
  java: () => new JavaAnalyzer(),
  typescript: () => new NodeAnalyzer(),
  javascript: () => new NodeAnalyzer(),
  python: () => new PythonAnalyzer(),
  go: () => new GoAnalyzer(),
  ruby: () => new RubyAnalyzer(),
}

export async function extractEndpoints(sourcePath: string): Promise<EndpointInfo[]> {
  const detections = detectLanguages(sourcePath)
  const endpointSets = await Promise.all(
    detections.map(async d => {
      const factory = ANALYZERS[d.language]
      if (!factory) return []
      return factory().analyze(sourcePath)
    })
  )

  const seen = new Set<string>()
  const merged: EndpointInfo[] = []

  for (const endpoints of endpointSets) {
    for (const ep of endpoints) {
      const key = `${ep.method}:${ep.path}`
      if (!seen.has(key)) {
        seen.add(key)
        merged.push(ep)
      }
    }
  }

  return merged
}
