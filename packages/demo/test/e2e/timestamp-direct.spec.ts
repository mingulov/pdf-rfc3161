import { test, expect } from '@playwright/test';
import path from 'path';
import fs from 'fs';

test.describe('Add Timestamp - Direct Mode', () => {
    test('should timestamp automatically using AI Moda (CORS)', async ({ page }) => {
        await page.goto('/');

        // Switch to "Add Timestamp" tab
        await page.getByTestId('tab-timestamp').click();

        // Ensure we are on the "Add Timestamp" tab
        // Check for specific element unique to this tab
        await expect(page.getByTestId('timestamp-pdf-drop')).toBeVisible();

        // Upload the test PDF
        const filePath = path.resolve('test.pdf');
        await page.setInputFiles('input[type="file"]', filePath);

        // Select AI Moda (should be default, but let's be explicit if possible or check value)
        // value for AI Moda is 'https://rfc3161.ai.moda/tsa'
        await page.locator('select').selectOption('https://rfc3161.ai.moda/tsa');

        // Click Sign PDF
        await page.getByTestId('btn-direct-sign').click();

        // Wait for success message
        await expect(page.getByTestId('timestamp-success-message')).toBeVisible({ timeout: 15000 });

        // Verify download availability
        const downloadPromise = page.waitForEvent('download');
        await page.getByTestId('btn-download-final-pdf').click();
        const download = await downloadPromise;

        // Save to temp file
        const timestampedPath = path.resolve('test-results', 'timestamped-direct.pdf');
        await download.saveAs(timestampedPath);
        expect(fs.existsSync(timestampedPath)).toBeTruthy();

        // Optional: Upload to validation tab to verify?
        // The user asked to "upload that file to 'Validation and Inspect' tab - check result etc"

        await page.goto('/');
        await page.getByTestId('tab-verify').click();
        await page.setInputFiles('input[type="file"]', timestampedPath);

        // Check for validation results
        // Looking for the timestamp result item
        await expect(page.getByTestId('timestamp-result').first()).toBeVisible();
    });
});
