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

  // Radios are visually hidden; click the visible label text instead.
  await page.locator('.channel-group label.sms span').click();
  await expect(page.locator('input[name="channel"][value="sms"]')).toBeChecked();

  const phoneInput = page.locator('#phoneInput');
  await expect(phoneInput).toBeVisible();
  await expect(phoneInput).toBeEnabled();

    const countryTrigger = page.locator('#countryTrigger');
  await expect(countryTrigger).toBeVisible();
  await expect(countryTrigger).toBeEnabled();

  // The native select is intentionally hidden in favor of the custom trigger/menu UI.
  const countrySelect = page.locator('#countrySelect');
   await expect(countrySelect).toBeHidden();
  await expect(countrySelect).toBeEnabled();

  await page.screenshot({
    path: path.join(screenshotDir, 'auth-phone-input.png'),
    fullPage: true,
  });
});
