/**
 * Best-effort provisioning for Semgrep (used by the analyze_sast_semgrep tool).
 *
 * Semgrep is a Python package (not a single downloadable binary like gitleaks), so this
 * script only *detects and informs* — it never blocks install. Resolution order the
 * runtime tool uses: (1) `semgrep` on PATH, (2) the `semgrep/semgrep` Docker image.
 * This script attempts a lightweight pipx/pip install when available, and otherwise
 * prints guidance. It always exits 0.
 */

import { execFileSync } from 'child_process'

function has(cmd, args = ['--version']) {
  try {
    execFileSync(cmd, args, { stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

if (has('semgrep')) {
  console.log('[install-semgrep] semgrep already on PATH, skipping.')
  process.exit(0)
}

function tryInstall(cmd, args) {
  try {
    console.log(`[install-semgrep] Attempting: ${cmd} ${args.join(' ')}`)
    execFileSync(cmd, args, { stdio: 'pipe', timeout: 180000 })
    return has('semgrep')
  } catch {
    return false
  }
}

let installed = false
if (has('pipx')) {
  installed = tryInstall('pipx', ['install', 'semgrep'])
} else if (has('pip3', ['--version'])) {
  installed = tryInstall('pip3', ['install', '--user', 'semgrep'])
} else if (has('pip', ['--version'])) {
  installed = tryInstall('pip', ['install', '--user', 'semgrep'])
}

if (installed) {
  console.log('[install-semgrep] Installed semgrep.')
} else if (has('docker')) {
  console.log('[install-semgrep] semgrep not installed, but Docker is present.')
  console.log('[install-semgrep] analyze_sast_semgrep will use the semgrep/semgrep image (auto-pulled on first run).')
} else {
  console.warn('[install-semgrep] semgrep unavailable. Install one of:')
  console.warn('[install-semgrep]   pipx install semgrep   (recommended)')
  console.warn('[install-semgrep]   pip install semgrep')
  console.warn('[install-semgrep]   or install Docker (image: semgrep/semgrep)')
  console.warn('[install-semgrep] The analyze_sast_semgrep tool will skip gracefully until then.')
}

process.exit(0)
