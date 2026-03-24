import {
  assertRuntimeSummary,
  formatRuntimeSummary,
  runCryptosuiteRuntimeSuite,
} from '../runtime-suite.mjs'

const { Cryptographic } = await import(
  new URL('../../../dist/index.js', import.meta.url)
)

const label = 'bun esm'
const summary = await runCryptosuiteRuntimeSuite(Cryptographic)
console.log(formatRuntimeSummary(label, summary))
assertRuntimeSummary(label, summary)
