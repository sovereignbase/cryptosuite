import { defineConfig, devices } from '@playwright/test'

const baseURL = process.env.PLAYWRIGHT_BASE_URL

if (!baseURL) {
  throw new Error(
    'PLAYWRIGHT_BASE_URL is required. Run node test/e2e/runsInBrowsers/run.mjs.'
  )
}

export default defineConfig({
  testDir: 'test/e2e/runsInBrowsers',
  timeout: 30000,
  use: {
    baseURL,
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
    {
      name: 'firefox',
      use: { browserName: 'firefox' },
    },
    {
      name: 'webkit',
      use: { browserName: 'webkit' },
    },
    {
      name: 'mobile-chrome',
      use: { ...devices['Pixel 5'] },
    },
    {
      name: 'mobile-safari',
      use: { ...devices['iPhone 12'] },
    },
  ],
})
