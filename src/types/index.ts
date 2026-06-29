export type Persona = 'personal' | 'team' | 'internal' | 'commercial'

export const PENALTY_MULTIPLIER: Record<Persona, number> = {
  personal: 0.3,
  team: 0.5,
  internal: 0.8,
  commercial: 1.0,
}

export const CONCURRENCY_LIMIT: Record<Persona, number> = {
  personal: 1,
  team: 2,
  internal: 3,
  commercial: 5,
}

export type FindingCategory = 'A' | 'B' | 'C' | 'D'
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export const BASE_DEDUCTION: Record<FindingCategory, number> = {
  A: 10,
  B: 10,
  C: 10,
  D: 5,
}

export const INSTANT_FAIL_PERSONAS: Record<FindingCategory, Persona[]> = {
  A: ['commercial'],
  B: ['commercial', 'internal'],
  C: ['commercial', 'internal'],
  D: [],
}

export interface ExtractedArtifact {
  type: 'token' | 'apiKey' | 'internalUrl' | 'stackTrace'
  value: string
  source: string
}

export interface ParameterInfo {
  name: string
  in: 'body' | 'query' | 'path' | 'header'
  required: boolean
  type: string
}

export interface EndpointInfo {
  method: string
  path: string
  parameters: ParameterInfo[]
  authRequired: boolean
  sourceLanguage: 'java' | 'typescript' | 'javascript' | 'python' | 'go' | 'ruby' | 'unknown'
}

export interface Finding {
  severity: FindingSeverity
  category: FindingCategory
  description: string
  evidence: string
  isFail: boolean
  baseDeduction: number
  toolName: string
}

export interface Remediation {
  findingCategory: FindingCategory
  filePath?: string
  lineNumber?: number
  before: string
  after: string
  description: string
}

export interface SecurityReport {
  timestamp: string
  persona: Persona
  targetBaseUrl: string
  score: number
  findings: Finding[]
  remediations: Remediation[]
}

export interface JudgeContext {
  persona: Persona
  penaltyMultiplier: number
  targetBaseUrl: string
  allowedUrls: string[]
  sourcePath?: string
  hasLlmChat: boolean
  endpoints: EndpointInfo[]
  findings: Finding[]
  extractedArtifacts: ExtractedArtifact[]
  score: number
}

export type SupportedLanguage = 'java' | 'python' | 'go' | 'ruby' | 'typescript' | 'javascript'

export interface IAnalyzer {
  language: SupportedLanguage
  analyze(rootPath: string): Promise<EndpointInfo[]>
}

export interface MutationResult {
  success: boolean
  statusCode: number
  responseBody: string
  roundNumber: number
  payload: unknown
}

export interface AttackResult {
  endpoint: EndpointInfo
  mutations: MutationResult[]
  findings: Finding[]
}

export interface GitleaksSecret {
  RuleID: string
  Match: string
  Secret: string
  File: string
  StartLine: number
  Description: string
}
