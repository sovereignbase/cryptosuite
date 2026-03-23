import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import process from 'node:process'
import { resolveGlobs } from '../../resolve-globs.mjs'

const cli = resolve('node_modules/playwright/cli.js')
const inputGlobs = process.argv.slice(2)
const files = inputGlobs.length > 0 ? resolveGlobs(inputGlobs) : []
if (inputGlobs.length > 0 && files.length === 0) {
  console.error(`No e2e files matched: ${inputGlobs.join(', ')}`)
  process.exit(1)
}

const child = spawn(process.execPath, [cli, 'test', ...files], {
  stdio: 'inherit',
})
child.on('exit', (code) => {
  process.exit(code ?? 1)
})
