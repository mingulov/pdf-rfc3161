import { test, expect, type Route } from '@playwright/test';
import path from 'path';
import fs from 'fs';
import { mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import * as asn1js from 'asn1js';
import * as pkijs from 'pkijs';
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
const SHA256_OID = '2.16.840.1.101.3.4.2.1';

test.describe('Add Timestamp - Direct Mode', () => {
    test('should timestamp automatically using the offline TSA fixture', async ({ page }, testInfo) => {
        const tsaDirectory = mkdtempSync(join(tmpdir(), 'pdf-rfc3161-demo-tsa-'));
        let handleTsaRequest: ((route: Route) => Promise<void>) | undefined;
        const capturedTsq: Buffer[] = [];

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
                capturedTsq.push(requestBody);

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

            // Save to the per-test output directory: the shared
            // test-results/ path races when projects run in parallel workers.
            const timestampedPath = testInfo.outputPath('timestamped-direct.pdf');
            await download.saveAs(timestampedPath);
            expect(fs.existsSync(timestampedPath)).toBeTruthy();

            // The TSA receives a message imprint, never the PDF: every
            // captured request must be a small decodable TimeStampReq with
            // a SHA-256 imprint and a nonce, without PDF bytes.
            expect(capturedTsq.length).toBeGreaterThan(0);
            for (const body of capturedTsq) {
                expect(body.length).toBeLessThan(1024);
                expect(body.includes(Buffer.from('%PDF'))).toBe(false);
                const parsed = asn1js.fromBER(new Uint8Array(body).buffer as ArrayBuffer);
                expect(parsed.offset).toBe(body.length);
                const tsq = new pkijs.TimeStampReq({ schema: parsed.result });
                expect(tsq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA256_OID);
                expect(tsq.messageImprint.hashedMessage.valueBlock.valueHexView.byteLength).toBe(32);
                expect(tsq.nonce).toBeDefined();
            }

            // The signed download preserves the original PDF prefix.
            const originalBytes = fs.readFileSync(filePath);
            const signedBytes = fs.readFileSync(timestampedPath);
            expect(signedBytes.length).toBeGreaterThan(originalBytes.length);
            expect(
                Buffer.from(signedBytes.subarray(0, originalBytes.length)).equals(originalBytes)
            ).toBe(true);

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
