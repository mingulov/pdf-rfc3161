import { test, expect } from '@playwright/test';
import path from 'path';

test.describe('Validator UI Logic', () => {
    test('should show "No Timestamps Found" for a clean PDF', async ({ page }) => {
        await page.goto('/');

        // Switch to Validator tab
        await page.getByTestId('tab-verify').click();

        // Upload the clean test.pdf
        const filePath = path.resolve('test.pdf');
        await page.setInputFiles('input[type="file"]', filePath);

        // Check for "No Timestamps Found" message
        await expect(page.getByTestId('no-timestamps-message')).toBeVisible();
        await expect(page.locator('text=This PDF does not appear to have any RFC 3161 timestamp signatures')).toBeVisible();

        // Ensure DSS section is NOT visible
        await expect(page.getByTestId('dss-section')).not.toBeVisible();
    });
});
