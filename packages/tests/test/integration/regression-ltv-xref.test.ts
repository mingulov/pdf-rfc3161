import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";
import { INCOMPATIBLE_TSA_URLS } from "../../src/tsa-compatibility.js";
import { assertQpdfCheck } from "../../src/qpdf-check.js";
import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";

// Helper to check if a command exists
const commandExists = (cmd: string) => {
    try {
        execSync(`command -v ${cmd}`, { stdio: "ignore" });
        return true;
    } catch {
        return false;
    }
};

/**
 * Regression test for LTV xref corruption issue.
 *
 * Bug: When adding LTV data after timestamping, the DSS increment was using
 * a stale PDFDocument instance whose snapshot had incorrect xref offsets.
 * This caused the /Prev pointer in the final xref to point to the wrong location,
 * making the PDF unreadable by Adobe Acrobat and flagged as "damaged" by qpdf.
 *
 * Fixed by: Always reloading the PDFDocument from the current bytes before
 * performing incremental saves, rather than reusing a stale pdfDoc instance.
 *
 * Note: These tests call real TSA servers. Set LIVE_TSA_TESTS=true to run them.
 * Some TSA servers are known to be incompatible (see INCOMPATIBLE_TSA_URLS).
 * Tests with incompatible servers will pass but skip the actual timestamp assertion.
 */
describe("Regression: LTV xref corruption", () => {
    const hasQpdf = commandExists("qpdf");
    const hasLiveTsa = process.env.LIVE_TSA_TESTS === "true";
    const tmpDir = os.tmpdir();

    const shouldRun = hasQpdf && hasLiveTsa;
    const itLive = shouldRun ? it : it.skip;

    itLive("should produce valid PDF structure with LTV enabled", async () => {
        const testPdfPath = path.join(tmpDir, `regression-ltv-xref-${Date.now().toString()}.pdf`);

        try {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            // Check if this TSA is known to be incompatible
            const tsaUrl = KNOWN_TSA_URLS.DIGICERT;
            if (INCOMPATIBLE_TSA_URLS.has(tsaUrl)) {
                // Skip assertion but verify the function handles the error gracefully
                try {
                    await timestampPdf({
                        pdf: pdfBytes,
                        tsa: { url: tsaUrl },
                        enableLTV: true,
                    });
                } catch (error) {
                    // Expected: TimestampError from incompatible TSA
                    expect((error as Error).name).toBe("TimestampError");
                }
                return; // Skip further assertions for incompatible TSAs
            }

            // This was failing before the fix - the LTV increment had wrong /Prev
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { url: tsaUrl },
                enableLTV: true,
            });

            fs.writeFileSync(testPdfPath, result.pdf);

            // Status 3 is accepted only for nonstructural qpdf warnings.
            assertQpdfCheck(testPdfPath);

            // Verify the PDF is also loadable
            const loaded = await PDFDocument.load(result.pdf);
            expect(loaded.getPageCount()).toBe(1);
        } finally {
            if (fs.existsSync(testPdfPath)) {
                fs.unlinkSync(testPdfPath);
            }
        }
    });

    itLive("should have correct xref chain with multiple incremental saves", async () => {
        const testPdfPath = path.join(tmpDir, `regression-xref-chain-${Date.now().toString()}.pdf`);

        try {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const tsaUrl = KNOWN_TSA_URLS.DIGICERT;
            if (INCOMPATIBLE_TSA_URLS.has(tsaUrl)) {
                try {
                    await timestampPdf({
                        pdf: pdfBytes,
                        tsa: { url: tsaUrl },
                        enableLTV: true,
                    });
                } catch (error) {
                    expect((error as Error).name).toBe("TimestampError");
                }
                return;
            }

            // Timestamp with LTV - this does: original -> timestamp increment -> DSS increment
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { url: tsaUrl },
                enableLTV: true,
            });

            fs.writeFileSync(testPdfPath, result.pdf);

            // qpdf --show-xref shows entries like "1/0: compressed; stream = 5, index = 0"
            const xrefOutput = execSync(`qpdf --show-xref ${testPdfPath}`, {
                encoding: "utf8",
            });

            // Should have xref entries (format: "N/G: type; ...")
            expect(xrefOutput).toContain("/0:");

            // Status 3 is accepted only for nonstructural qpdf warnings.
            assertQpdfCheck(testPdfPath);
        } finally {
            if (fs.existsSync(testPdfPath)) {
                fs.unlinkSync(testPdfPath);
            }
        }
    });
});
