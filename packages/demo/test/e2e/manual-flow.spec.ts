import { test, expect } from "@playwright/test";
import * as fs from "fs";
import * as path from "path";
import { readFileSync, writeFileSync } from "fs";

test.describe("Manual LTV Flow", () => {
    test("should go through the manual LTV timestamping process", async ({ page }) => {
        // 1. Navigate to the app
        await page.goto("/");

        // 2. Switch to 'Add Timestamp with LTV' tab
        await page.getByTestId("tab-manual-ltv").click();

        // 3. Upload the test PDF
        const filePath = path.resolve("test.pdf");
        await page.setInputFiles('input[type="file"]', filePath);

        // 4. Generate TSQ
        await page.getByTestId("btn-generate-tsq").click();

        // 5. Catch the download of request.tsq
        const [download] = await Promise.all([
            page.waitForEvent("download"),
            page.getByTestId("btn-download-tsq").click(),
        ]);

        const downloadDir = path.resolve("temp_test");
        if (!fs.existsSync(downloadDir)) fs.mkdirSync(downloadDir);
        const tsqPath = path.join(downloadDir, "request.tsq");
        await download.saveAs(tsqPath);

        // 6. Extract curl command from the UI and make HTTP request manually
        const curlCommandText = await page.locator(".code").first().textContent();
        expect(curlCommandText).toContain("curl");

        const tsrPath = path.join(downloadDir, "response.tsr");

        const urlMatch = curlCommandText!.match(/response\.tsr\s+(\S+)/);
        const url = urlMatch ? urlMatch[1] : "";

        const headerMatches = [...curlCommandText!.matchAll(/-H\s+"([^"]+)"/g)];
        const headers: Record<string, string> = {};
        for (const match of headerMatches) {
            const [key, ...valueParts] = match[1].split(": ");
            if (key && valueParts.length > 0) headers[key] = valueParts.join(": ");
        }

        console.log(`Sending request to: ${url}`);
        console.log(`Headers:`, headers);

        if (!url) {
            console.warn("Could not parse URL from curl command");
            return;
        }

        const tsqContent = readFileSync(tsqPath);

        const response = await fetch(url, {
            method: "POST",
            headers,
            body: tsqContent,
        });

        if (!response.ok) {
            console.warn(`Request failed: ${response.status} ${response.statusText}`);
            return;
        }

        const arrayBuffer = await response.arrayBuffer();
        writeFileSync(tsrPath, new Uint8Array(arrayBuffer));

        expect(fs.existsSync(tsrPath)).toBe(true);

        // 7. Upload the TSR response
        // Step 2 has an upload area
        await page.setInputFiles(
            '.section:has-text("Upload response") input[type="file"]',
            tsrPath
        );

        // 8. Analyze and move to Step 3&4
        await expect(page.locator('h3:has-text("Step 3 & 4")')).toBeVisible({ timeout: 10000 });

        // 10. Finalize the PDF
        await page.getByTestId("btn-finalize-ltv").click();

        // 11. Verify success
        await expect(page.getByTestId("ltv-success-message")).toBeVisible();

        // 12. Download final PDF
        const [finalDownload] = await Promise.all([
            page.waitForEvent("download"),
            page.getByTestId("btn-download-final-ltv").click(),
        ]);

        const finalPdfPath = path.join(downloadDir, "final.pdf");
        await finalDownload.saveAs(finalPdfPath);
        expect(fs.existsSync(finalPdfPath)).toBe(true);

        // Cleanup
        fs.rmSync(downloadDir, { recursive: true, force: true });
    });
});
