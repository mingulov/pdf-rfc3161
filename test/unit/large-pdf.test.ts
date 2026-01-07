import { describe, it, expect } from "vitest";
import { preparePdfForTimestamp } from "../../src/pdf/prepare.js";
import { PDFDocument } from "pdf-lib-incremental-save";

describe("Large PDF Handling", () => {
    it("should find signature placeholder in a large PDF", async () => {
        // Create a large PDF
        const pdfDoc = await PDFDocument.create();

        // Add many pages to generate a large xref table and pushes the signature dict further back
        // relative to the end of the file
        for (let i = 0; i < 500; i++) {
            const p = pdfDoc.addPage();
            p.drawText(`Page ${String(i)} - ${"Random content ".repeat(20)}`);
        }

        const largeBytes = await pdfDoc.save({ useObjectStreams: false });
        // Verify it is actually large
        expect(largeBytes.length).toBeGreaterThan(200 * 1024);
        console.log(`Generated test PDF size: ${(largeBytes.length / 1024).toFixed(2)} KB`);

        // Attempt to prepare it (this used to fail if search buffer was too small)
        const result = await preparePdfForTimestamp(largeBytes, {
            signatureSize: 8192,
        });

        expect(result).toBeDefined();
        expect(result.contentsPlaceholderLength).toBe(16384);
        expect(result.contentsOffset).toBeGreaterThan(0);
    }, 60000); // Increase timeout for large PDF generation
});
