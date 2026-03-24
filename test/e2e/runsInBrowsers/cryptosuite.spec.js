import { test, expect } from '@playwright/test'

test('cryptosuite browser suite', async ({ page }) => {
  await page.goto('/')
  const summary = await page.evaluate(async () => {
    const { Cryptographic } = await import('/dist/index.js')
    const { runCryptosuiteRuntimeSuite } =
      await import('/test/e2e/runtime-suite.mjs')
    return await runCryptosuiteRuntimeSuite(Cryptographic)
  })

  expect(summary.failed).toBe(0)
  expect(summary.passed).toBe(summary.total)
})
