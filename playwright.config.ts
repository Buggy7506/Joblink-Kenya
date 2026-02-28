import { defineConfig, devices } from '@playwright/test';

/**
 * Read environment variables from file (optional)
 * Uncomment if you use a local .env
 */
// import dotenv from 'dotenv';
// import path from 'path';
// dotenv.config({ path: path.resolve(__dirname, '.env') });

export default defineConfig({
  testDir: './tests',
  testMatch: '*.spec.ts',

  /* Run tests in files in parallel */
  fullyParallel: true,

  /* Fail the build on CI if you accidentally left test.only in the source code. */
  forbidOnly: !!process.env.CI,

  /* Retry on CI only */
  retries: process.env.CI ? 2 : 0,

  /* Opt out of parallel tests on CI. */
  workers: process.env.CI ? 1 : undefined,

  /* Reporter */
  reporter: 'html',

  /* Shared settings for all projects */
  use: {
    /* Base URL for Django dev server (HTTP) */
    baseURL: 'http://127.0.0.1:9000',

    /* Collect trace when retrying the failed test */
    trace: 'on-first-retry',

    /* Always capture screenshots so runs consistently produce artifacts */
    screenshot: 'on',
  },

  /* Configure projects for major browsers */
  projects:
    process.env.PW_TEST_BROWSERS === 'all'
      ? [
          {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
          },
          {
            name: 'firefox',
            use: { ...devices['Desktop Firefox'] },
          },
          {
            name: 'webkit',
            use: { ...devices['Desktop Safari'] },
          },
        ]
      : [
          {
            name: 'chromium',
            use: { ...devices['Desktop Chrome'] },
          },
        ],

  /* Auto-start Django dev server before tests */
  webServer: {
    command: 'python manage.py runserver 127.0.0.1:9000 --noreload --nothreading',
    url: 'http://127.0.0.1:9000',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000, // wait up to 60s for server
  },

  /* Output folder for screenshots, videos, and traces */
  outputDir: 'test-results',
});
