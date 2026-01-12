import { test, expect, request } from '@playwright/test';
import path from 'path';
import fs from 'fs';

// Helper to perform the "curl" action in Node.js for TSR
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

// Helper to fetch OCSP
async function fetchOcsp(url: string, reqPath: string): Promise<Buffer> {
    const reqData = fs.readFileSync(reqPath);
    const context = await request.newContext();
    const response = await context.post(url, {
        headers: { 'Content-Type': 'application/ocsp-request' },
        data: reqData
    });
    // OCSP might fail or return success. If fail, we still return buffer?
    // Usually status 200.
    return await response.body();

}

// Helper to fetch CRL/Cert
async function fetchUrl(url: string): Promise<Buffer> {
    const context = await request.newContext();
    const response = await context.get(url);
    return await response.body();
}

test.describe('Add Timestamp with LTV - Manual Flow', () => {
    test('should perform full manual LTV workflow with AI Moda', async ({ page }) => {
        // Increase timeout for this long test
        test.setTimeout(60000);

        await page.goto('/');
        await page.getByTestId('tab-manual-ltv').click();

        // Upload PDF
        const filePath = path.resolve('test.pdf');
        await page.setInputFiles('input[type="file"]', filePath);

        // Step 1: Generate TSQ
        // Select DigiCert.
        const digicertUrl = 'http://timestamp.digicert.com';
        await page.locator('select').selectOption(digicertUrl);
        await page.getByTestId('btn-generate-tsq').click();

        // Step 2: Download TSQ
        const downloadPromise = page.waitForEvent('download');
        await page.getByTestId('btn-download-tsq').click();
        const download = await downloadPromise;
        const tsqPath = path.resolve('test-results', 'ltv-manual.tsq');
        await download.saveAs(tsqPath);

        // Simulate Fetch TSR
        const tsrBuffer = await fetchTsr(digicertUrl, tsqPath);
        const tsrPath = path.resolve('test-results', 'ltv-manual.tsr');
        fs.writeFileSync(tsrPath, tsrBuffer);

        // Click "Analyze" (Step 3) - Wait, in manual flow we upload TSR first.
        // "Step 2: Get Timestamp Response" -> "C. Upload Response (.tsr)"
        // There is a FileDrop in section C.
        // It's inside data-testid="upload-response-section"
        const dropZone = page.getByTestId('upload-response-section');
        await dropZone.locator('input[type="file"]').setInputFiles(tsrPath);

        // Step 3&4 should appear: "Fetch & Upload Validation Data"
        await expect(page.getByTestId('ltv-step-4')).toBeVisible({ timeout: 15000 });

        // Iterate over commands to fetch validation data
        // We look for .cmd-item
        const commandItems = page.locator('.cmd-item');
        const count = await commandItems.count();
        const fetchedFiles: string[] = [];

        for (let i = 0; i < count; ++i) {
            const item = commandItems.nth(i);
            const typeText = await item.locator('.badge').innerText();
            const url = await item.locator('.text-xs.gray').innerText();

            if (typeText === 'OCSP') {
                // Download request if button exists
                const btn = item.getByRole('button', { name: /Download/ });
                if (await btn.count() > 0) {
                    const dlPromise = page.waitForEvent('download');
                    await btn.click();
                    const dl = await dlPromise;
                    const reqPath = path.resolve('test-results', `ocsp_req_${i}.der`);
                    await dl.saveAs(reqPath);

                    // Fetch OCSP
                    try {
                        const ocspResp = await fetchOcsp(url, reqPath);
                        const respPath = path.resolve('test-results', `ocsp_resp_${i}.der`);
                        fs.writeFileSync(respPath, ocspResp);
                        fetchedFiles.push(respPath);
                    } catch (e) {
                        console.warn(`Failed to fetch OCSP from ${url}`, e);
                    }
                }
            } else if (typeText === 'CRL' || typeText === 'CERT') {
                try {
                    const data = await fetchUrl(url);
                    const fname = typeText === 'CRL' ? `crl_${i}.crl` : `cert_${i}.cer`;
                    const fpath = path.resolve('test-results', fname);
                    fs.writeFileSync(fpath, data);
                    fetchedFiles.push(fpath);
                } catch (e) {
                    console.warn(`Failed to fetch ${typeText} from ${url}`, e);
                }
            }
        }

        // Upload fetched files
        if (fetchedFiles.length > 0) {
            // "Upload Fetched Files" section
            // input[type="file"] multiple inside .upload-section
            const uploadInput = page.locator('.upload-section input[type="file"]');
            await uploadInput.setInputFiles(fetchedFiles);

            // Allow some time for processing
            await page.waitForTimeout(1000);
        }

        // Finalize
        await page.getByTestId('btn-finalize-ltv').click();

        // Verify success
        await expect(page.getByTestId('ltv-success-message')).toBeVisible({ timeout: 30000 });

        // Download result
        const finalDlPromise = page.waitForEvent('download');
        await page.getByTestId('btn-download-final-ltv').click();
        const finalDl = await finalDlPromise;
        const finalPath = path.resolve('test-results', 'timestamped-ltv-manual.pdf');
        await finalDl.saveAs(finalPath);
        expect(fs.existsSync(finalPath)).toBeTruthy();
    });
});
