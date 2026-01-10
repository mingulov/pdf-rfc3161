import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { timestampPdf, KNOWN_TSA_URLS } from "../../src/index.js";
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
 */
describe("Regression: LTV xref corruption", () => {
    const hasQpdf = commandExists("qpdf");
    const tmpDir = os.tmpdir();

    it.skipIf(!hasQpdf)("should produce valid PDF structure with LTV enabled", async () => {
        const testPdfPath = path.join(tmpDir, `regression-ltv-xref-${Date.now().toString()}.pdf`);

        try {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            // This was failing before the fix - the LTV increment had wrong /Prev
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: { url: KNOWN_TSA_URLS.DIGICERT },
                enableLTV: true,
            });

            fs.writeFileSync(testPdfPath, result.pdf);

            // Check with qpdf - should not have xref errors (exit code 3)
            try {
                execSync(`qpdf --check ${testPdfPath}`, { stdio: "ignore" });
            } catch (e: unknown) {
                const error = e as { status?: number };
                // Status 2 is warnings (acceptable), Status 3 is errors (fail)
                if (error.status === 3) {
                    // Get detailed error
                    let details = "";
                    try {
                        details = execSync(`qpdf --check ${testPdfPath} 2>&1`, {
                            encoding: "utf8",
                        });
                    } catch (e2: unknown) {
                        const err2 = e2 as { stdout?: string; stderr?: string };
                        details = err2.stdout ?? err2.stderr ?? "";
                    }
                    throw new Error(
                        `PDF has structural errors (qpdf exit code 3).\n` +
                            `This may indicate the /Prev xref pointer bug has regressed.\n` +
                            `Details: ${details}`
                    );
                }
            }

            // Verify the PDF is also loadable
            const loaded = await PDFDocument.load(result.pdf);
            expect(loaded.getPageCount()).toBe(1);
        } finally {
            if (fs.existsSync(testPdfPath)) {
                fs.unlinkSync(testPdfPath);
            }
        }
    });

    it.skipIf(!hasQpdf)(
        "should have correct xref chain with multiple incremental saves",
        async () => {
            const testPdfPath = path.join(
                tmpDir,
                `regression-xref-chain-${Date.now().toString()}.pdf`
            );

            try {
                const doc = await PDFDocument.create();
                doc.addPage([100, 100]);
                const pdfBytes = await doc.save();

                // Timestamp with LTV - this does: original -> timestamp increment -> DSS increment
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: { url: KNOWN_TSA_URLS.DIGICERT },
                    enableLTV: true,
                });

                fs.writeFileSync(testPdfPath, result.pdf);

                // qpdf --show-xref shows entries like "1/0: compressed; stream = 5, index = 0"
                const xrefOutput = execSync(`qpdf --show-xref ${testPdfPath}`, {
                    encoding: "utf8",
                });

                // Should have xref entries (format: "N/G: type; ...")
                expect(xrefOutput).toContain("/0:");

                // Verify no "damaged" warnings when loading
                const checkOutput = execSync(`qpdf --check ${testPdfPath} 2>&1`, {
                    encoding: "utf8",
                });
                expect(checkOutput).not.toContain("file is damaged");
                expect(checkOutput).not.toContain("xref not found");
            } finally {
                if (fs.existsSync(testPdfPath)) {
                    fs.unlinkSync(testPdfPath);
                }
            }
        }
    );
});
