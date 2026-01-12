import { test, expect, request } from '@playwright/test';
import path from 'path';
import fs from 'fs';
import crypto from 'crypto';

// Helper to perform the "curl" action in Node.js
async function fetchTsr(tsaUrl: string, tsqPath: string): Promise<Buffer> {
    const tsq = fs.readFileSync(tsqPath);
    const context = await request.newContext();
    const response = await context.post(tsaUrl, {
        headers: {
            'Content-Type': 'application/timestamp-query',
        },
        data: tsq,
    });
    expect(response.status()).toBe(200);
    return await response.body();
}

function getUniquePath(baseDir: string, filename: string): string {
    if (!fs.existsSync(baseDir)) {
        fs.mkdirSync(baseDir, { recursive: true });
    }
    const ext = path.extname(filename);
    const name = path.basename(filename, ext);
    const suffix = crypto.randomBytes(4).toString('hex');
    return path.join(baseDir, `${name}-${suffix}${ext}`);
}

test.describe('Add Timestamp - Manual Mode', () => {

    test('should timestamp via Manual File Upload (curl simulation)', async ({ page }) => {
        page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
        await page.goto('/');

        // Switch to "Add Timestamp" tab
        await page.getByTestId('tab-timestamp').click();

        // Upload PDF
        const filePath = path.resolve('test.pdf');
        await page.getByTestId('timestamp-pdf-drop').locator('input[type="file"]').setInputFiles(filePath);

        // Select Manual Mode
        await page.getByTestId('mode-manual').click();

        // Use FreeTSA. URL: https://freetsa.org/tsr
        const tsaUrl = 'https://freetsa.org/tsr';
        await page.getByTestId('tsa-url-manual').fill(tsaUrl);

        // Generate Request
        await page.getByTestId('btn-generate-tsq').click();

        // Step 2 appears
        await expect(page.getByText('Step 2: Send Request')).toBeVisible();

        // Download TSQ
        const downloadPromise = page.waitForEvent('download');
        await page.getByRole('button', { name: /Download request\.tsq/i }).click();
        const download = await downloadPromise;
        const tsqPath = getUniquePath('test-results', 'manual.tsq');
        await download.saveAs(tsqPath);

        // Simulate "curl" (fetch TSR from TSA)
        const tsrBuffer = await fetchTsr(tsaUrl, tsqPath);
        const tsrPath = getUniquePath('test-results', 'response.tsr');
        fs.writeFileSync(tsrPath, tsrBuffer);

        // Upload TSR
        await page.getByTestId('tsr-dropzone').locator('input[type="file"]').setInputFiles(tsrPath);

        // Wait for success
        await expect(page.getByTestId('timestamp-success-message')).toBeVisible({ timeout: 15000 });

        // Verify download
        const finalDownloadPromise = page.waitForEvent('download');
        await page.getByTestId('btn-download-final-pdf').click();
        const finalDownload = await finalDownloadPromise;
        const finalPath = path.resolve('test-results', 'timestamped-manual-file.pdf');
        await finalDownload.saveAs(finalPath);
        expect(fs.existsSync(finalPath)).toBeTruthy();
    });

    test('should timestamp via Base64 Paste (Console Script)', async ({ page }) => {
        page.on('console', msg => console.log('BROWSER LOG:', msg.text()));
        await page.goto('/');

        // Switch to "Add Timestamp" tab
        await page.getByTestId('tab-timestamp').click();

        // Upload PDF
        const filePath = path.resolve('test.pdf');
        await page.getByTestId('timestamp-pdf-drop').locator('input[type="file"]').setInputFiles(filePath);

        // Select Manual Mode
        await page.getByTestId('mode-manual').click();

        // Enable Advanced Console Scripts
        await page.getByTestId('checkbox-advanced-console').click();

        // Use FreeTSA for consistency
        const tsaUrl = 'https://freetsa.org/tsr';
        await page.getByTestId('tsa-url-manual').fill(tsaUrl);

        // Generate Request
        await page.getByTestId('btn-generate-tsq').click();

        // Download TSQ (needed to get bytes for our simulation)
        const downloadPromise = page.waitForEvent('download');
        await page.getByRole('button', { name: /Download request\.tsq/i }).click();
        const download = await downloadPromise;
        const tsqPath = getUniquePath('test-results', 'manual-b64.tsq');
        await download.saveAs(tsqPath);

        // Simulate "curl" and get Buffer
        const tsrBuffer = await fetchTsr(tsaUrl, tsqPath);

        // Convert to Base64
        const tsrBase64 = tsrBuffer.toString('base64');

        // Paste into Base64 Input
        await page.getByTestId('input-tsr-base64').fill(tsrBase64);

        // Click Load
        await page.getByTestId('btn-load-base64').click();

        // Wait for success, but show error if it happens
        const success = page.getByTestId('timestamp-success-message');
        const error = page.locator('.error');
        await expect(success.or(error)).toBeVisible({ timeout: 15000 });

        if (await error.isVisible()) {
            const errorText = await error.innerText();
            throw new Error(`Timestamp failed with error: ${errorText}`);
        }

        await expect(success).toBeVisible();
    });

});
