import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";

describe("ByteRange Compatibility Tests", () => {
    /**
     * Test that ByteRange is calculated correctly for Adobe Reader compatibility.
     * The ByteRange should:
     * 1. Exclude the opening '<' bracket (hole starts at '<')
     * 2. Exclude the closing '>' bracket (hole ends at '>')
     * 3. Have ByteRange appear BEFORE Contents in the dictionary
     */
    it("should calculate ByteRange to exclude < and > brackets", async () => {
        // Create a minimal PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // Prepare for timestamp
        const prepared = await preparePdfForTimestamp(pdfBytes);
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Extract ByteRange from the PDF
        const byteRangeRegex = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/;
        const byteRangeMatch = byteRangeRegex.exec(pdfStr);
        expect(byteRangeMatch).not.toBeNull();
        if (!byteRangeMatch) return;

        const offset1 = parseInt(byteRangeMatch[1] ?? "0", 10);
        const length1 = parseInt(byteRangeMatch[2] ?? "0", 10);
        const offset2 = parseInt(byteRangeMatch[3] ?? "0", 10);
        const length2 = parseInt(byteRangeMatch[4] ?? "0", 10);

        // Verify basic structure
        expect(offset1).toBe(0);
        expect(length1).toBeGreaterThan(0);
        expect(offset2).toBeGreaterThan(length1);
        expect(length2).toBeGreaterThan(0);

        // The character at position length1 should be '<' (start of hole)
        const charAtHoleStart = pdfStr.charAt(length1);
        expect(charAtHoleStart).toBe("<");

        // The character at position offset2 - 1 should be '>' (end of hole)
        const charAtHoleEnd = pdfStr.charAt(offset2 - 1);
        expect(charAtHoleEnd).toBe(">");

        // Verify total coverage equals file size
        const totalCoverage = length1 + (offset2 - length1) + length2;
        expect(totalCoverage).toBe(prepared.bytes.length);
    });

    it("should place ByteRange before Contents in signature dictionary", async () => {
        // Create a minimal PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // Prepare for timestamp
        const prepared = await preparePdfForTimestamp(pdfBytes);
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Find positions of ByteRange and Contents in the signature dictionary
        const byteRangePos = pdfStr.indexOf("/ByteRange");
        const contentsPos = pdfStr.indexOf("/Contents");

        expect(byteRangePos).toBeGreaterThan(-1);
        expect(contentsPos).toBeGreaterThan(-1);

        // ByteRange should appear BEFORE Contents
        expect(byteRangePos).toBeLessThan(contentsPos);
    });

    it("should use zero padding in Contents hex string", async () => {
        // Create a minimal PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // Prepare for timestamp
        const prepared = await preparePdfForTimestamp(pdfBytes);
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Find Contents hex string
        const contentsRegex = /\/Contents\s*<([0-9A-Fa-f]+)>/;
        const contentsMatch = contentsRegex.exec(pdfStr);
        expect(contentsMatch).not.toBeNull();
        if (!contentsMatch) return;

        const hexContent = contentsMatch[1] ?? "";
        // Should be all zeros (placeholder)
        expect(hexContent).toMatch(/^0+$/);
    });

    it("should return correct ByteRange in PreparedPdfResult", async () => {
        // Create a minimal PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // Prepare for timestamp
        const prepared = await preparePdfForTimestamp(pdfBytes);

        // Verify the returned byteRange matches what's in the PDF
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);
        const byteRangeRegex = /\/ByteRange\s*\[\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*\]/;
        const byteRangeMatch = byteRangeRegex.exec(pdfStr);
        expect(byteRangeMatch).not.toBeNull();
        if (!byteRangeMatch) return;

        expect(prepared.byteRange[0]).toBe(parseInt(byteRangeMatch[1] ?? "0", 10));
        expect(prepared.byteRange[1]).toBe(parseInt(byteRangeMatch[2] ?? "0", 10));
        expect(prepared.byteRange[2]).toBe(parseInt(byteRangeMatch[3] ?? "0", 10));
        expect(prepared.byteRange[3]).toBe(parseInt(byteRangeMatch[4] ?? "0", 10));
    });
});
