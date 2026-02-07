import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

// Ensure test-results folder exists
const screenshotDir = path.resolve(__dirname, '../test-results');
if (!fs.existsSync(screenshotDir)) {
  fs.mkdirSync(screenshotDir, { recursive: true });
}

test('Auth page phone input UI screenshot', async ({ page }) => {
  // Go to your Django auth page (local dev server)
  await page.goto('/Sign-In-OR-Sign-Up/', {
    waitUntil: 'networkidle',
  });

  // Ensure phone input is visible
  const phoneInput = page.locator('input[type="tel"]');
  await expect(phoneInput).toBeVisible();

  // Ensure country selector is visible
  const countrySelect = page.locator('.country-select'); // adjust class if different
  await expect(countrySelect).toBeVisible();

  // Take a full-page screenshot
  await page.screenshot({
    path: path.join(screenshotDir, 'auth-phone-input.png'),
    fullPage: true,
  });
});
