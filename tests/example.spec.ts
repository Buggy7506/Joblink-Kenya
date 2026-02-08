import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

// Ensure test-results folder exists
const screenshotDir = path.resolve(__dirname, '../test-results');
if (!fs.existsSync(screenshotDir)) {
  fs.mkdirSync(screenshotDir, { recursive: true });
}

test('Auth page phone input UI screenshot', async ({ page }) => {
  // Go to auth page
  await page.goto('/Sign-In-OR-Sign-Up/', {
    waitUntil: 'networkidle',
  });

  // 🔹 Select SMS or WhatsApp to reveal phone input
  await page.check('input[name="channel"][value="sms"]');

  // 🔹 Phone input should now be visible and enabled
  const phoneInput = page.locator('#phoneInput');
  await expect(phoneInput).toBeVisible();
  await expect(phoneInput).toBeEnabled();

  // 🔹 Country selector should also be visible
  const countrySelect = page.locator('.country-select');
  await expect(countrySelect).toBeVisible();

  // 🔹 Take screenshot AFTER correct UI state
  await page.screenshot({
    path: path.join(screenshotDir, 'auth-phone-input.png'),
    fullPage: true,
  });
});
