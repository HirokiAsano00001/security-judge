/**
 * gitleaks バイナリを bin/ に自動取得する postinstall スクリプト。
 * Node.js 標準モジュールと OS の tar/powershell のみ使用（外部パッケージ不要）。
 */

import { createWriteStream, existsSync, mkdirSync, chmodSync, unlinkSync } from 'fs'
import { pipeline } from 'stream/promises'
import { join, dirname } from 'path'
import { fileURLToPath } from 'url'
import { get } from 'https'
import { execSync } from 'child_process'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..')
const BIN_DIR = join(ROOT, 'bin')
const VERSION = '8.21.2'

const PLATFORM_MAP = {
  darwin_arm64: `gitleaks_${VERSION}_darwin_arm64.tar.gz`,
  darwin_x64: `gitleaks_${VERSION}_darwin_x64.tar.gz`,
  linux_arm64: `gitleaks_${VERSION}_linux_arm64.tar.gz`,
  linux_x64: `gitleaks_${VERSION}_linux_x64.tar.gz`,
  win32_x64: `gitleaks_${VERSION}_windows_x64.zip`,
  win32_arm64: `gitleaks_${VERSION}_windows_arm64.zip`,
}

const platform = `${process.platform}_${process.arch}`
const asset = PLATFORM_MAP[platform]

if (!asset) {
  console.warn(`[install-gitleaks] Unsupported platform: ${platform}. Install gitleaks manually.`)
  process.exit(0)
}

const binaryName = process.platform === 'win32' ? 'gitleaks.exe' : 'gitleaks'
const binaryPath = join(BIN_DIR, binaryName)

if (existsSync(binaryPath)) {
  console.log('[install-gitleaks] gitleaks already installed, skipping.')
  process.exit(0)
}

if (!existsSync(BIN_DIR)) {
  mkdirSync(BIN_DIR, { recursive: true })
}

const downloadUrl = `https://github.com/gitleaks/gitleaks/releases/download/v${VERSION}/${asset}`
console.log(`[install-gitleaks] Downloading gitleaks v${VERSION} for ${platform}...`)

function httpsGet(url, maxRedirects = 10) {
  return new Promise((resolve, reject) => {
    if (maxRedirects === 0) return reject(new Error('Too many redirects'))
    get(url, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        resolve(httpsGet(res.headers.location, maxRedirects - 1))
      } else if (res.statusCode !== 200) {
        reject(new Error(`HTTP ${res.statusCode} for ${url}`))
      } else {
        resolve(res)
      }
    }).on('error', reject)
  })
}

try {
  const res = await httpsGet(downloadUrl)
  const tmpPath = join(BIN_DIR, asset)
  await pipeline(res, createWriteStream(tmpPath))

  if (asset.endsWith('.tar.gz')) {
    execSync(`tar -xzf "${tmpPath}" -C "${BIN_DIR}" ${binaryName}`, { stdio: 'pipe' })
  } else {
    execSync(
      `powershell -Command "Expand-Archive -Path '${tmpPath}' -DestinationPath '${BIN_DIR}' -Force"`,
      { stdio: 'pipe' }
    )
  }

  try { unlinkSync(tmpPath) } catch { /* ignore */ }

  if (process.platform !== 'win32') {
    chmodSync(binaryPath, 0o755)
  }

  console.log(`[install-gitleaks] Installed -> ${binaryPath}`)
} catch (err) {
  console.warn(`[install-gitleaks] Failed: ${err.message}`)
  console.warn('[install-gitleaks] Manual install: https://github.com/gitleaks/gitleaks/releases')
  process.exit(0)
}
