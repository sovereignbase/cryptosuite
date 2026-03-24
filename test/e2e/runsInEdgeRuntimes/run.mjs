import { spawn } from 'node:child_process'
import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import process from 'node:process'
import { build } from 'esbuild'

const edgeCli = resolve('node_modules/edge-runtime/dist/cli/index.js')
const entry = resolve('test/e2e/runsInEdgeRuntimes/entry.mjs')
const tempDir = await mkdtemp(join(tmpdir(), 'cryptosuite-edge-runtime-'))
const outfile = join(tempDir, 'bundle.js')

try {
  await build({
    entryPoints: [entry],
    bundle: true,
    format: 'iife',
    platform: 'browser',
    target: 'es2022',
    outfile,
  })

  const exitCode = await new Promise((resolveExit) => {
    const child = spawn(process.execPath, [edgeCli, outfile], {
      stdio: 'inherit',
      shell: false,
    })
    child.on('exit', (code) => {
      resolveExit(code ?? 1)
    })
    child.on('error', () => {
      resolveExit(1)
    })
  })

  process.exit(exitCode)
} finally {
  await rm(tempDir, { recursive: true, force: true })
}
