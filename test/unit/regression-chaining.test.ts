import { describe, it, expect } from "vitest";
import { preparePdfForTimestamp } from "../../src/pdf/prepare.js";
import { PDFDocument } from "pdf-lib-incremental-save";

describe("Regression Tests - Timestamp Chaining", () => {
    it("should detect existing signatures and avoid rewriting PDF (LTA chaining)", async () => {
        // 1. Create base PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // 2. Prepare first timestamp (creates first signature)
        const prep1 = await preparePdfForTimestamp(pdfBytes);
        const pdf1 = prep1.bytes;

        // 3. Prepare second timestamp (should preserve first)
        // This validates the fix where we check for existing signatures
        const prep2 = await preparePdfForTimestamp(pdf1);
        const pdf2 = prep2.bytes;

        // 4. Verify incremental update
        // The second PDF should contain the entire first PDF as a prefix
        const pdf1Buffer = Buffer.from(pdf1);
        const pdf2Buffer = Buffer.from(pdf2);

        expect(pdf2Buffer.indexOf(pdf1Buffer)).toBe(0);

        // Also verify size increased due to appended signature
        expect(pdf2Buffer.length).toBeGreaterThan(pdf1Buffer.length);
    });
});
