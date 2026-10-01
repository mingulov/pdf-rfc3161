import { test, expect, type Route } from "@playwright/test";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
    createLocalTsa,
    createTimestampResponse,
} from "../../../tests/scripts/local-tsa-fixture";

// The manual LTV tab ships AI Moda as its default TSA and shows the
// automatic-fetch button for it. Intercepting that URL keeps this journey
// offline and deterministic while driving the real UI path.
const AIMODA_TSA_URL = "https://rfc3161.ai.moda/tsa";
const CORS_HEADERS = {
    "access-control-allow-headers": "content-type",
    "access-control-allow-methods": "POST, OPTIONS",
    "access-control-allow-origin": "http://127.0.0.1:5173",
};
const SHA256_OID = "2.16.840.1.101.3.4.2.1";

/** The TSA receives a message imprint, never the PDF. */
function assertTsqShape(body: Buffer): void {
    expect(body.length).toBeLessThan(1024);
    expect(body.includes(Buffer.from("%PDF"))).toBe(false);
    const parsed = asn1js.fromBER(new Uint8Array(body).buffer as ArrayBuffer);
    expect(parsed.offset).toBe(body.length);
    const tsq = new pkijs.TimeStampReq({ schema: parsed.result });
    expect(tsq.messageImprint.hashAlgorithm.algorithmId).toBe(SHA256_OID);
    expect(tsq.messageImprint.hashedMessage.valueBlock.valueHexView.byteLength).toBe(32);
    expect(tsq.nonce).toBeDefined();
}

/**
 * Structural download check, independent of any cryptographic oracle:
 * the signed PDF extends the original bytes and carries a document
 * timestamp dictionary.
 */
function assertSignedPdf(originalPath: string, signedPath: string): void {
    const originalBytes = readFileSync(originalPath);
    const signedBytes = readFileSync(signedPath);
    expect(signedBytes.length).toBeGreaterThan(originalBytes.length);
    expect(Buffer.from(signedBytes.subarray(0, originalBytes.length)).equals(originalBytes)).toBe(
        true
    );
    expect(signedBytes.includes(Buffer.from("DocTimeStamp"))).toBe(true);
}

test.describe("Manual LTV Flow", () => {
    test("should go through the manual LTV timestamping process", async ({ page }) => {
        // Fully offline: the downloaded TSQ is signed by the local TSA
        // fixture instead of a public server, so this journey is
        // deterministic and uses per-test temporary paths only.
        const workDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-demo-manual-"));
        const tsaDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-demo-manual-tsa-"));
        try {
            const localTsa = createLocalTsa(tsaDirectory);

            await page.goto("/");
            await page.getByTestId("tab-manual-ltv").click();

            const filePath = resolve("test.pdf");
            await page.setInputFiles('input[type="file"]', filePath);

            // TSQ generation: the UI must reach step 2 and offer the download.
            await page.getByTestId("btn-generate-tsq").click();
            await expect(page.getByTestId("ltv-step-2")).toBeVisible({ timeout: 15000 });
            const curlHint = await page.locator(".code").first().textContent();
            expect(curlHint).toContain("curl");

            const [tsqDownload] = await Promise.all([
                page.waitForEvent("download"),
                page.getByTestId("btn-download-tsq").click(),
            ]);
            const tsqPath = join(workDirectory, "request.tsq");
            await tsqDownload.saveAs(tsqPath);
            const tsqBytes = readFileSync(tsqPath);
            assertTsqShape(tsqBytes);

            // Local signed response fixture: replaces the curl-to-public-TSA step.
            const tsrBytes = createTimestampResponse(tsaDirectory, localTsa.config, tsqBytes);
            expect(tsrBytes.length).toBeGreaterThan(tsqBytes.length);
            const parsedTsr = asn1js.fromBER(new Uint8Array(tsrBytes).buffer as ArrayBuffer);
            expect(parsedTsr.offset).toBe(tsrBytes.length);
            const tsrPath = join(workDirectory, "response.tsr");
            writeFileSync(tsrPath, tsrBytes);

            // Response import: uploading the TSR must reach step 3 & 4.
            const dropZone = page.getByTestId("upload-response-section");
            await dropZone.locator('input[type="file"]').setInputFiles(tsrPath);
            await expect(page.getByTestId("ltv-step-4")).toBeVisible({ timeout: 15000 });
            // The fixture TSA chain carries no AIA/OCSP/CRL endpoints.
            await expect(page.locator("text=No external validation sources")).toBeVisible();

            // Verification: finalizing must report success.
            await page.getByTestId("btn-finalize-ltv").click();
            await expect(page.getByTestId("ltv-success-message")).toBeVisible();

            // Download: the final PDF preserves the original and carries a timestamp.
            const [finalDownload] = await Promise.all([
                page.waitForEvent("download"),
                page.getByTestId("btn-download-final-ltv").click(),
            ]);
            const finalPdfPath = join(workDirectory, "final.pdf");
            await finalDownload.saveAs(finalPdfPath);
            assertSignedPdf(filePath, finalPdfPath);
        } finally {
            rmSync(workDirectory, { force: true, recursive: true });
            rmSync(tsaDirectory, { force: true, recursive: true });
        }
    });

    test("should complete the manual LTV flow against the offline TSA fixture", async ({
        page,
    }) => {
        const tsaDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-demo-manual-tsa-"));
        const workDirectory = mkdtempSync(join(tmpdir(), "pdf-rfc3161-demo-manual-"));
        let handleTsaRequest: ((route: Route) => Promise<void>) | undefined;
        const capturedTsq: Buffer[] = [];

        try {
            const localTsa = createLocalTsa(tsaDirectory);
            const routeHandler = async (route: Route) => {
                const request = route.request();
                if (request.method() === "OPTIONS") {
                    await route.fulfill({ status: 204, headers: CORS_HEADERS });
                    return;
                }
                if (request.method() !== "POST") {
                    await route.abort();
                    throw new Error(`Unexpected TSA method: ${request.method()}`);
                }
                const requestBody = request.postDataBuffer();
                if (requestBody === null) {
                    await route.abort();
                    throw new Error("TSA request body is missing");
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
                            "content-type": "application/timestamp-reply",
                        },
                        body: Buffer.from(response),
                    });
                } catch (error: unknown) {
                    await route.abort();
                    throw error;
                }
            };
            handleTsaRequest = routeHandler;
            await page.route(AIMODA_TSA_URL, routeHandler);
            await page.goto("/");

            await page.getByTestId("tab-manual-ltv").click();

            const filePath = resolve("test.pdf");
            await page.setInputFiles('input[type="file"]', filePath);

            await expect(page.locator("select")).toHaveValue(AIMODA_TSA_URL);
            await page.getByTestId("btn-generate-tsq").click();

            await expect(page.getByTestId("btn-automatic-fetch")).toBeVisible();
            await page.getByTestId("btn-automatic-fetch").click();

            await expect(page.locator('h3:has-text("Step 3 & 4")')).toBeVisible({
                timeout: 15000,
            });
            // The fixture TSA chain carries no AIA/OCSP/CRL endpoints.
            await expect(page.locator("text=No external validation sources")).toBeVisible();

            await page.getByTestId("btn-finalize-ltv").click();
            await expect(page.getByTestId("ltv-success-message")).toBeVisible();

            const [finalDownload] = await Promise.all([
                page.waitForEvent("download"),
                page.getByTestId("btn-download-final-ltv").click(),
            ]);
            const finalPdfPath = join(workDirectory, "final.pdf");
            await finalDownload.saveAs(finalPdfPath);

            expect(capturedTsq.length).toBeGreaterThan(0);
            for (const body of capturedTsq) {
                assertTsqShape(body);
            }
            assertSignedPdf(filePath, finalPdfPath);
        } finally {
            if (handleTsaRequest !== undefined) {
                await page.unroute(AIMODA_TSA_URL, handleTsaRequest);
            }
            rmSync(workDirectory, { force: true, recursive: true });
            rmSync(tsaDirectory, { force: true, recursive: true });
        }
    });
});
