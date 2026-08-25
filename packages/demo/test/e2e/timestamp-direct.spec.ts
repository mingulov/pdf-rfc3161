import { test, expect, type Route } from '@playwright/test';
import path from 'path';
import fs from 'fs';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import {
    createLocalTsa,
    createTimestampResponse,
} from '../../../tests/scripts/local-tsa-fixture';

const LOCAL_TSA_URL = 'https://offline-timestamp.test.invalid/tsa';
const CORS_HEADERS = {
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'POST, OPTIONS',
    'access-control-allow-origin': 'http://127.0.0.1:5173',
};

test.describe('Add Timestamp - Direct Mode', () => {
    test('should timestamp automatically using the offline TSA fixture', async ({ page }) => {
        const tsaDirectory = mkdtempSync(join(tmpdir(), 'pdf-rfc3161-demo-tsa-'));
        let handleTsaRequest: ((route: Route) => Promise<void>) | undefined;

        try {
            const localTsa = createLocalTsa(tsaDirectory);
            const routeHandler = async (route: Route) => {
                const request = route.request();
                if (request.method() === 'OPTIONS') {
                    await route.fulfill({ status: 204, headers: CORS_HEADERS });
                    return;
                }
                if (request.method() !== 'POST') {
                    await route.abort();
                    throw new Error(`Unexpected TSA method: ${request.method()}`);
                }

                const requestBody = request.postDataBuffer();
                if (requestBody === null) {
                    await route.abort();
                    throw new Error('TSA request body is missing');
                }

                try {
                    const response = createTimestampResponse(
                        tsaDirectory,
                        localTsa.config,
                        requestBody
                    );
                    await route.fulfill({
                        status: 200,
                        headers: {
                            ...CORS_HEADERS,
                            'content-type': 'application/timestamp-reply',
                        },
                        body: Buffer.from(response),
                    });
                } catch (error: unknown) {
                    await route.abort();
                    throw error;
                }
            };
            handleTsaRequest = routeHandler;
            await page.route(LOCAL_TSA_URL, routeHandler);
            await page.goto('/');

            // Switch to "Add Timestamp" tab
            await page.getByTestId('tab-timestamp').click();

            // Ensure we are on the "Add Timestamp" tab
            // Check for specific element unique to this tab
            await expect(page.getByTestId('timestamp-pdf-drop')).toBeVisible();

            // Upload the test PDF
            const filePath = path.resolve('test.pdf');
            await page.setInputFiles('input[type="file"]', filePath);

            // Use a local mocked URL; Playwright serves its response without a network hop.
            await page.locator('select').selectOption('custom');
            await page.locator('#tsa-url-custom').fill(LOCAL_TSA_URL);

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

            // Upload the result to "Validation and Inspect" and check the timestamp result.
            await page.goto('/');
            await page.getByTestId('tab-verify').click();
            await page.setInputFiles('input[type="file"]', timestampedPath);

            // Check for validation results
            const timestampResult = page.getByTestId('timestamp-result').first();
            await expect(timestampResult).toBeVisible();
            await expect(timestampResult).toHaveAttribute('data-validation-status', 'valid');
        } finally {
            if (handleTsaRequest !== undefined) {
                await page.unroute(LOCAL_TSA_URL, handleTsaRequest);
            }
            rmSync(tsaDirectory, { force: true, recursive: true });
        }
    });
});
