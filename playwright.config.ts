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
    baseURL: 'http://127.0.0.1:8000',

    /* Collect trace when retrying the failed test */
    trace: 'on-first-retry',

    /* Automatically capture screenshots on failure */
    screenshot: 'only-on-failure',
  },

  /* Configure projects for major browsers */
  projects: [
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
  ],

  /* Auto-start Django dev server before tests */
  webServer: {
    command: 'python manage.py runserver',
    url: 'http://127.0.0.1:8000',
    reuseExistingServer: true, // won't start if already running
    timeout: 60_000, // wait up to 60s for server
  },

  /* Output folder for screenshots, videos, and traces */
  outputDir: 'test-results',
});
