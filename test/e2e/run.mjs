import { spawn, spawnSync } from 'node:child_process'
import { resolve } from 'node:path'
import process from 'node:process'

function hasCommand(command) {
  const result = spawnSync(command, ['--version'], {
    stdio: 'ignore',
    shell: process.platform === 'win32',
  })
  return result.status === 0
}

function run(command, args) {
  return new Promise((resolveRun) => {
    const child = spawn(command, args, {
      stdio: 'inherit',
      shell: process.platform === 'win32',
    })
    child.on('exit', (code) => {
      resolveRun(code ?? 1)
    })
    child.on('error', () => {
      resolveRun(1)
    })
  })
}

const edgeCli = resolve('node_modules/edge-runtime/dist/cli/index.js')
const sections = [
  {
    title: 'Node E2E',
    tasks: [
      {
        command: process.execPath,
        args: ['test/e2e/runsInNode/esm.mjs'],
      },
      {
        command: process.execPath,
        args: ['test/e2e/runsInNode/cjs.cjs'],
      },
    ],
  },
  {
    title: 'Bun E2E',
    tasks: hasCommand('bun')
      ? [
          {
            command: 'bun',
            args: ['test/e2e/runsInBun/esm.mjs'],
          },
          {
            command: 'bun',
            args: ['test/e2e/runsInBun/cjs.cjs'],
          },
        ]
      : [
          {
            skipped: 'bun not found',
          },
        ],
  },
  {
    title: 'Deno E2E',
    tasks: hasCommand('deno')
      ? [
          {
            command: 'deno',
            args: ['run', '--allow-read', 'test/e2e/runsInDeno/esm.mjs'],
          },
        ]
      : [
          {
            skipped: 'deno not found',
          },
        ],
  },
  {
    title: 'Edge Runtimes E2E',
    tasks: [
      {
        command: process.execPath,
        args: ['test/e2e/runsInEdgeRuntimes/run.mjs'],
      },
    ],
  },
  {
    title: 'Browsers E2E',
    tasks: [
      {
        command: process.execPath,
        args: ['test/e2e/runsInBrowsers/run.mjs'],
      },
    ],
  },
]

let failed = false

for (const section of sections) {
  console.log(`\n=== ${section.title} ===`)
  for (const task of section.tasks) {
    if (task.skipped) {
      console.log(task.skipped)
      continue
    }

    const code = await run(task.command, task.args)
    if (code !== 0) {
      failed = true
    }
  }
}

if (failed) {
  process.exit(1)
}

console.log('\nAll end-to-end runtime suites passed.')
