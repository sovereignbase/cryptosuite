;(async () => {
  const { Cryptographic } = require('../../../dist/index.cjs')
  const {
    assertRuntimeSummary,
    formatRuntimeSummary,
    runCryptosuiteRuntimeSuite,
  } = await import('../runtime-suite.mjs')

  const label = 'bun cjs'
  const summary = await runCryptosuiteRuntimeSuite(Cryptographic)
  console.log(formatRuntimeSummary(label, summary))
  assertRuntimeSummary(label, summary)
})()
