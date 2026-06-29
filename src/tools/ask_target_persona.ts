import { type JudgeContext, type Persona, PENALTY_MULTIPLIER, CONCURRENCY_LIMIT } from '../types/index.js'
import { extractBaseUrl } from '../safety/url_guard.js'

export const ASK_TARGET_PERSONA_SCHEMA = {
  type: 'object',
  properties: {
    persona: {
      type: 'string',
      enum: ['personal', 'team', 'internal', 'commercial'],
      description: 'Application purpose: personal=self-use, team=small team, internal=company internal, commercial=public product',
    },
    targetBaseUrl: {
      type: 'string',
      description: 'Target base URL (e.g., http://localhost:8080)',
    },
    sourcePath: {
      type: 'string',
      description: 'Root path of source code (optional, skip if not available)',
    },
    hasLlmChat: {
      type: 'boolean',
      description: 'Whether the app has an LLM chat feature to test jailbreak',
    },
  },
  required: ['persona', 'targetBaseUrl', 'hasLlmChat'],
}

export function askTargetPersona(
  input: {
    persona: Persona
    targetBaseUrl: string
    sourcePath?: string
    hasLlmChat: boolean
  },
  ctx: JudgeContext
): string {
  const baseUrl = extractBaseUrl(input.targetBaseUrl)
  const multiplier = PENALTY_MULTIPLIER[input.persona]
  const concurrency = CONCURRENCY_LIMIT[input.persona]

  ctx.persona = input.persona
  ctx.penaltyMultiplier = multiplier
  ctx.targetBaseUrl = baseUrl
  ctx.allowedUrls = [baseUrl]
  ctx.sourcePath = input.sourcePath
  ctx.hasLlmChat = input.hasLlmChat
  ctx.endpoints = []
  ctx.findings = []
  ctx.extractedArtifacts = []
  ctx.score = 10

  const lines = [
    `## Target configured`,
    `- Persona: **${input.persona}** (penalty multiplier: ${multiplier})`,
    `- Target: ${baseUrl}`,
    `- Source path: ${input.sourcePath ?? '(not provided — HTTP fallback mode)'}`,
    `- LLM chat: ${input.hasLlmChat ? 'Yes (inject_llm_jailbreak will run)' : 'No (skipped)'}`,
    `- Concurrency limit: ${concurrency}`,
    ``,
    `Ready to execute Phase 2 (recon) → Phase 3 (attack) → Phase 4 (score).`,
    `Run \`analyze_sast_deep\` and \`scan_exposed_endpoints\` to begin.`,
  ]

  return lines.join('\n')
}
