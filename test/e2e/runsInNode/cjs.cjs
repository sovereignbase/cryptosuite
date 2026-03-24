;(async () => {
  const { webcrypto } = require('node:crypto')
  const { Cryptographic } = require('../../../dist/index.cjs')
  const {
    assertRuntimeSummary,
    formatRuntimeSummary,
    runCryptosuiteRuntimeSuite,
  } = await import('../runtime-suite.mjs')

  if (!globalThis.crypto) {
    globalThis.crypto = webcrypto
  }

  const label = 'node cjs'
  const summary = await runCryptosuiteRuntimeSuite(Cryptographic)
  console.log(formatRuntimeSummary(label, summary))
  assertRuntimeSummary(label, summary)
})()
