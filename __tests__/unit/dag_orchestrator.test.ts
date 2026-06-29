import { describe, it, expect, vi } from 'vitest'
import { runParallel, type DagTask } from '../../src/attack/dag_orchestrator.js'
import { type JudgeContext } from '../../src/types/index.js'

function makeCtx(): JudgeContext {
  return {
    persona: 'personal',
    penaltyMultiplier: 0.3,
    targetBaseUrl: 'http://localhost',
    allowedUrls: ['http://localhost'],
    hasLlmChat: false,
    endpoints: [],
    findings: [],
    extractedArtifacts: [],
    score: 10,
  }
}

describe('runParallel', () => {
  it('runs all tasks', async () => {
    const ctx = makeCtx()
    const executed: string[] = []

    const tasks: DagTask[] = [
      { id: 'a', runner: async () => { executed.push('a') } },
      { id: 'b', runner: async () => { executed.push('b') } },
      { id: 'c', runner: async () => { executed.push('c') } },
    ]

    await runParallel(tasks, ctx)
    expect(executed).toContain('a')
    expect(executed).toContain('b')
    expect(executed).toContain('c')
  })

  it('respects dependency order', async () => {
    const ctx = makeCtx()
    const order: string[] = []

    const tasks: DagTask[] = [
      { id: 'a', runner: async () => { order.push('a') } },
      { id: 'b', dependsOn: ['a'], runner: async () => { order.push('b') } },
    ]

    await runParallel(tasks, ctx)
    expect(order.indexOf('a')).toBeLessThan(order.indexOf('b'))
  })

  it('continues even if a task throws', async () => {
    const ctx = makeCtx()
    const executed: string[] = []

    const tasks: DagTask[] = [
      { id: 'fail', runner: async () => { throw new Error('task failed') } },
      { id: 'ok', runner: async () => { executed.push('ok') } },
    ]

    await expect(runParallel(tasks, ctx)).resolves.not.toThrow()
    expect(executed).toContain('ok')
  })

  it('handles empty task list', async () => {
    const ctx = makeCtx()
    await expect(runParallel([], ctx)).resolves.not.toThrow()
  })

  it('passes ctx to runners', async () => {
    const ctx = makeCtx()
    let receivedCtx: JudgeContext | undefined

    const tasks: DagTask[] = [
      { id: 'check', runner: async (c) => { receivedCtx = c } },
    ]

    await runParallel(tasks, ctx)
    expect(receivedCtx).toBe(ctx)
  })
})
