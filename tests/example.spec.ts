import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

// Ensure test-results folder exists
const screenshotDir = path.resolve(__dirname, '../test-results');
if (!fs.existsSync(screenshotDir)) {
  fs.mkdirSync(screenshotDir, { recursive: true });
}

test('Auth page phone input UI screenshot', async ({ page }) => {
  await page.goto('/Sign-In-OR-Sign-Up/', {
    waitUntil: 'domcontentloaded',
  });

  // Target radio by label text to avoid brittle attribute selectors.
  await page.getByLabel('SMS').click();

  const phoneInput = page.locator('#phoneInput');
  await expect(phoneInput).toBeVisible();
  await expect(phoneInput).toBeEnabled();

  const countrySelect = page.locator('#countrySelect');
  await expect(countrySelect).toBeVisible();
  await expect(countrySelect).toBeEnabled();

  await page.screenshot({
    path: path.join(screenshotDir, 'auth-phone-input.png'),
    fullPage: true,
  });
});
