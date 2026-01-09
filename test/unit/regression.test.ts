import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../src/pdf/prepare.js";

describe("Regression Tests", () => {
    describe("PDF Structure Integrity (Fix for Invalid Object Refs)", () => {
        it("should generate a valid PDF that can be re-loaded after preparation", async () => {
            // 1. Create a minimal PDF
            const doc = await PDFDocument.create();
            doc.addPage([500, 500]);
            const originalBytes = await doc.save();

            // 2. Prepare it for timestamping (this triggered the byte insertion bug)
            const prepared = await preparePdfForTimestamp(originalBytes);

            // 3. Verify specifically that pdf-lib can load it back without error
            // The bug caused "Invalid object ref" here due to broken xref table
            let loadedDoc: PDFDocument | undefined;
            try {
                loadedDoc = await PDFDocument.load(prepared.bytes, { ignoreEncryption: true });
            } catch (e) {
                throw new Error(
                    `Regression: Generated PDF is malformed! ${e instanceof Error ? e.message : String(e)}`
                );
            }

            expect(loadedDoc).toBeDefined();
            expect(loadedDoc.getPageCount()).toBe(1);

            // 4. Verify ByteRange matches actual file size logic
            // ByteRange = [start1, len1, start2, len2]
            // range1 covers 0 to start of signature
            // range2 covers end of signature to EOF
            // So len1 + len2 should equal total bytes - signature_placeholder_length (and delimiters <>)
            // But checking exact offsets is safer.
            const [start1, len1, start2, len2] = prepared.byteRange;

            expect(start1).toBe(0);
            // range 1 ends where range 2 starts minus the hole
            // start2 should be (start1 + len1) + hole_length (placeholder approx 8192)
            expect(start2).toBeGreaterThan(len1);

            // The covered length should match file size minus the hole
            const holeSize = start2 - (start1 + len1);
            const totalCovered = len1 + len2;
            expect(totalCovered).toBe(prepared.bytes.length - holeSize);

            // Check that ranges cover the file ends
            expect(start2 + len2).toBe(prepared.bytes.length);
        });

        it("should not contain placeholder values 111111111111 in final PDF", async () => {
            // Regression test: Placeholder values were not being replaced due to regex mismatch
            const doc = await PDFDocument.create();
            doc.addPage([500, 500]);
            const originalBytes = await doc.save();

            const prepared = await preparePdfForTimestamp(originalBytes);

            // Convert to string to check for placeholder values
            const pdfString = new TextDecoder("latin1").decode(prepared.bytes);

            // The placeholder value 111111111111 should NOT appear in final PDF
            expect(pdfString).not.toContain("111111111111");
        });

        it("should have ByteRange with exactly 4 valid values", async () => {
            // Regression test: ByteRange must have format [a b c d], not 6 placeholder values
            const doc = await PDFDocument.create();
            doc.addPage([500, 500]);
            const originalBytes = await doc.save();

            const prepared = await preparePdfForTimestamp(originalBytes);

            const pdfString = new TextDecoder("latin1").decode(prepared.bytes);

            // Find ByteRange in the PDF
            const testByteRangePattern = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/;
            const byteRangeMatch = testByteRangePattern.exec(pdfString);
            expect(byteRangeMatch).not.toBeNull();

            if (byteRangeMatch) {
                const [, v1, v2, v3, v4] = byteRangeMatch;
                // First value should be 0
                expect(Number(v1)).toBe(0);
                // All values should be reasonable (not placeholder)
                expect(Number(v2)).toBeLessThan(1000000000);
                expect(Number(v3)).toBeLessThan(1000000000);
                expect(Number(v4)).toBeLessThan(1000000000);
            }
        });
    });
});
