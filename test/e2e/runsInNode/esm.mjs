import { webcrypto } from 'node:crypto'
import { Cryptographic } from '../../../dist/index.js'
import {
  assertRuntimeSummary,
  formatRuntimeSummary,
  runCryptosuiteRuntimeSuite,
} from '../runtime-suite.mjs'

if (!globalThis.crypto) {
  globalThis.crypto = webcrypto
}

const label = 'node esm'
const summary = await runCryptosuiteRuntimeSuite(Cryptographic)
console.log(formatRuntimeSummary(label, summary))
assertRuntimeSummary(label, summary)
