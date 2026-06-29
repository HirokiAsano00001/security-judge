import pLimit from 'p-limit'
import { type JudgeContext, CONCURRENCY_LIMIT } from '../types/index.js'

type ToolRunner = (ctx: JudgeContext) => Promise<void>

export interface DagTask {
  id: string
  runner: ToolRunner
  dependsOn?: string[]
}

export async function runParallel(tasks: DagTask[], ctx: JudgeContext): Promise<void> {
  const limit = pLimit(CONCURRENCY_LIMIT[ctx.persona])
  const completed = new Set<string>()
  const pending = [...tasks]

  const runnable = (): DagTask[] =>
    pending.filter(t =>
      !completed.has(t.id) &&
      (t.dependsOn ?? []).every(dep => completed.has(dep))
    )

  while (completed.size < tasks.length) {
    const batch = runnable()
    if (batch.length === 0) break

    await Promise.all(
      batch.map(task =>
        limit(async () => {
          try {
            await task.runner(ctx)
          } catch (err) {
            const msg = err instanceof Error ? err.message : String(err)
            console.error(`[dag] Task ${task.id} failed: ${msg}`)
          } finally {
            completed.add(task.id)
            pending.splice(pending.indexOf(task), 1)
          }
        })
      )
    )
  }
}
