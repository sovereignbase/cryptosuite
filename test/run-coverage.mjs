import { spawn } from 'node:child_process'
import { resolve } from 'node:path'
import process from 'node:process'
import { resolveGlobs } from './resolve-globs.mjs'

const c8Bin = resolve('node_modules/c8/bin/c8.js')
const defaultGlobs = [
  'test/unit/**/*.test.mjs',
  'test/integration/**/*.test.mjs',
]
const inputGlobs = process.argv.slice(2)
const globs = inputGlobs.length > 0 ? inputGlobs : defaultGlobs
const testFiles = resolveGlobs(globs)

if (testFiles.length === 0) {
  console.error(`No test files matched: ${globs.join(', ')}`)
  process.exit(1)
}

const args = [
  '--check-coverage',
  '--99',
  '--reporter=text',
  '--reporter=lcov',
  '--reporter=json-summary',
  '--all',
  '--src=src',
  '--exclude-after-remap',
  '--exclude=dist/**',
  '--exclude=src/**/.core/types/**',
  '--exclude=test/**',
  '--exclude=benchmark/**',
  '--exclude=coverage/**',
  '--exclude=node_modules/**',
  process.execPath,
  '--import',
  'tsx',
  '--test',
  ...testFiles,
]

const child = spawn(process.execPath, [c8Bin, ...args], {
  stdio: 'inherit',
})
child.on('exit', (code) => {
  process.exit(code ?? 1)
})
