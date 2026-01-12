import { describe, it, expect } from "vitest";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
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

    it("should use correct ByteRange for second signature (search window regression)", async () => {
        /**
         * Regression test for the ByteRange search window fix.
         *
         * Problem: When adding a second timestamp to a PDF, the search logic
         * for finding the ByteRange placeholder would sometimes match the FIRST
         * signature's ByteRange instead of the newly added one. Since the first
         * ByteRange was already compacted (e.g., 27 chars), trying to write a
         * larger value (29 chars) would fail with "ByteRange placeholder too small".
         *
         * Fix: The search window now starts at the dictionary hint offset
         * (provided by calculateByteRanges), ensuring we only search within
         * the CURRENT signature's dictionary, not previous ones.
         */

        // 1. Create base PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // 2. First timestamp
        const prep1 = await preparePdfForTimestamp(pdfBytes);
        const pdf1 = prep1.bytes;

        // 3. Second timestamp - this used to fail with "ByteRange placeholder too small"
        // because the search incorrectly matched the first signature's ByteRange
        const prep2 = await preparePdfForTimestamp(pdf1);
        const pdf2 = prep2.bytes;

        // 4. Verify both ByteRanges are valid (4 numbers, no placeholders)
        const pdfString = new TextDecoder("latin1").decode(pdf2);
        const byteRangePattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/g;

        const matches = [...pdfString.matchAll(byteRangePattern)];

        // Should have exactly 2 ByteRange entries (one per signature)
        expect(matches.length).toBe(2);

        // Both should have valid numeric values (no placeholder '111111111111' values)
        for (const match of matches) {
            const values = [match[1], match[2], match[3], match[4]];
            for (const val of values) {
                expect(val).toBeDefined();
                expect(val).not.toBe("111111111111");
                expect(Number(val)).toBeGreaterThanOrEqual(0);
            }
        }
    });
});
