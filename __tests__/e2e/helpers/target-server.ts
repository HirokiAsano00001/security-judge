import { spawn, type ChildProcess } from 'child_process'
import { request } from 'undici'
import { fileURLToPath } from 'url'
import { dirname, resolve } from 'path'
import { createServer } from 'net'

const __dirname = dirname(fileURLToPath(import.meta.url))
const APP_DIRS = {
  vulnerable: resolve(__dirname, '../../../test/target-app'),
  secure: resolve(__dirname, '../../../test/secure-app'),
} as const

export type AppKind = keyof typeof APP_DIRS

async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const srv = createServer()
    srv.on('error', rej)
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address()
      if (addr && typeof addr === 'object') {
        const port = addr.port
        srv.close(() => res(port))
      } else {
        srv.close(() => rej(new Error('could not acquire port')))
      }
    })
  })
}

export interface TargetHandle {
  baseUrl: string
  port: number
  sourcePath: string
  stop: () => Promise<void>
}

async function waitForReady(baseUrl: string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs
  while (Date.now() < deadline) {
    try {
      const res = await request(`${baseUrl}/health`, { method: 'GET' })
      await res.body.text()
      if (res.statusCode === 200) return
    } catch {
      // not up yet
    }
    await new Promise(r => setTimeout(r, 150))
  }
  throw new Error(`target-app did not become ready at ${baseUrl} within ${timeoutMs}ms`)
}

export async function startTarget(kind: AppKind = 'vulnerable'): Promise<TargetHandle> {
  const appDir = APP_DIRS[kind]
  const serverPath = resolve(appDir, 'server.js')
  const port = await freePort()
  const baseUrl = `http://127.0.0.1:${port}`
  const child: ChildProcess = spawn(process.execPath, [serverPath], {
    env: { ...process.env, PORT: String(port), NODE_ENV: 'test' },
    stdio: ['ignore', 'ignore', 'inherit'],
  })

  await waitForReady(baseUrl, 15000)

  const stop = (): Promise<void> =>
    new Promise(res => {
      if (child.exitCode !== null || child.signalCode !== null) return res()
      child.once('exit', () => res())
      child.kill('SIGTERM')
      setTimeout(() => {
        if (child.exitCode === null) child.kill('SIGKILL')
        res()
      }, 2000)
    })

  return {
    baseUrl,
    port,
    sourcePath: appDir,
    stop,
  }
}
