import { test, expect } from '@playwright/test';

test('Auth page phone input UI screenshot', async ({ page }, testInfo) => {
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

  const screenshotPath = testInfo.outputPath('auth-phone-input.png');
  await page.screenshot({ path: screenshotPath, fullPage: true });
  await testInfo.attach('auth-phone-input', {
    path: screenshotPath,
    contentType: 'image/png',
  });
});
