import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Automatic LTV Flow', () => {
    test('should timestamp automatically using AI Moda (CORS)', async ({ page }) => {
        await page.goto('/');

        // Switch to 'Add Timestamp with LTV' tab
        await page.getByTestId('tab-manual-ltv').click();

        // Upload the test PDF
        const filePath = path.resolve('test.pdf');
        await page.setInputFiles('input[type="file"]', filePath);

        // Step 1: Default should be AI Moda
        await expect(page.locator('select')).toHaveValue('https://rfc3161.ai.moda/tsa');

        // Generate Request
        await page.getByTestId('btn-generate-tsq').click();

        // Step 2: Should show automatic fetch button
        await expect(page.getByTestId('btn-automatic-fetch')).toBeVisible();

        // Click it!
        await page.getByTestId('btn-automatic-fetch').click();

        // Should move to Step 3&4 automatically
        await expect(page.locator('h3:has-text("Step 3 & 4")')).toBeVisible({ timeout: 15000 });

        // Finalize
        await page.getByTestId('btn-finalize-ltv').click();

        // Verify success
        await expect(page.getByTestId('ltv-success-message')).toBeVisible();
    });
});
