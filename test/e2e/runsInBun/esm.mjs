import { Cryptographic } from '../../../dist/index.js'
import {
  assertRuntimeSummary,
  formatRuntimeSummary,
  runCryptosuiteRuntimeSuite,
} from '../runtime-suite.mjs'

const label = 'bun esm'
const summary = await runCryptosuiteRuntimeSuite(Cryptographic)
console.log(formatRuntimeSummary(label, summary))
assertRuntimeSummary(label, summary)
