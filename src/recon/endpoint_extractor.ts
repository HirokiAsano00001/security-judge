import { type EndpointInfo, type SupportedLanguage } from '../types/index.js'
import { detectLanguage } from './language_detector.js'
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
  const detection = detectLanguage(sourcePath)
  const factory = ANALYZERS[detection.language]

  if (!factory) {
    return []
  }

  const analyzer = factory()
  return analyzer.analyze(sourcePath)
}
