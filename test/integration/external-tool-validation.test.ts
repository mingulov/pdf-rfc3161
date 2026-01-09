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

describe("External Tool Validation", () => {
    // Only run these tests if the tools are available
    const hasQpdf = commandExists("qpdf");
    const hasPdfSig = commandExists("pdfsig");

    const tmpDir = os.tmpdir();
    const testPdfPath = path.join(tmpDir, `test-validation-${Date.now().toString()}.pdf`);

    // Cleanup after tests
    const cleanup = () => {
        if (fs.existsSync(testPdfPath)) {
            fs.unlinkSync(testPdfPath);
        }
    };

    it.skipIf(!hasQpdf)("should pass qpdf validation (No LTV)", async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        const result = await timestampPdf({
            pdf: pdfBytes,
            tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        });

        fs.writeFileSync(testPdfPath, result.pdf);

        try {
            // qpdf --check returns exit code 0 on success, 2 on warning, 3 on error
            // We accept warnings (exit code 2) as passing for basic structure
            // But ideally we want 0.
            execSync(`qpdf --check ${testPdfPath}`, { stdio: "ignore" });
        } catch (e: any) {
            // Check exit code
            // Status 2 is warnings (acceptable), Status 3 is errors (fail)
            expect(e.status).not.toBe(3);
        }
        cleanup();
    });

    it.skipIf(!hasQpdf)("should pass qpdf validation (With LTV)", async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        const result = await timestampPdf({
            pdf: pdfBytes,
            tsa: { url: KNOWN_TSA_URLS.DIGICERT },
            enableLTV: true,
        });

        fs.writeFileSync(testPdfPath, result.pdf);

        try {
            execSync(`qpdf --check ${testPdfPath}`, { stdio: "ignore" });
        } catch (e: any) {
            // Status 2 is warnings (acceptable), Status 3 is errors (fail)
            expect(e.status).not.toBe(3);
        }
        cleanup();
    });

    it.skipIf(!hasPdfSig)("should be parsable by pdfsig (No LTV)", async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        const result = await timestampPdf({
            pdf: pdfBytes,
            tsa: { url: KNOWN_TSA_URLS.DIGICERT },
        });

        fs.writeFileSync(testPdfPath, result.pdf);

        try {
            const output = execSync(`pdfsig ${testPdfPath}`, { encoding: "utf8" });
            // Should find a signature
            expect(output).toContain("Signature #1");
            // Should verify structure even if signature itself isn't supported
            expect(output).not.toContain("Syntax Error");
        } catch (e: any) {
            // pdfsig returns non-zero if signature is invalid (which is expected for timestamp)
            // But we want to ensure stdout contains signature info
            if (e.stdout) {
                expect(e.stdout).toContain("Signature #1");
            } else {
                // If pure syntax error, it might fail completely
                // But pdfsig often returns 0 even on 'Unable to validate'
                // Re-throwing if no output is safer
                throw e;
            }
        }
        cleanup();
    });
});
