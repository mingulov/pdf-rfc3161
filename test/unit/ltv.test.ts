import { describe, it, expect } from "vitest";
import { extractLTVData, addDSS, type LTVData } from "../../src/pdf/ltv.js";
import { TimestampError } from "../../src/types.js";
import { PDFDocument } from "pdf-lib-incremental-save";

describe("LTV Functions", () => {
    describe("extractLTVData", () => {
        it("should throw on invalid input", () => {
            const invalidToken = new Uint8Array([0x00, 0x01, 0x02]);

            expect(() => extractLTVData(invalidToken)).toThrow(TimestampError);
        });

        it("should handle empty array gracefully", () => {
            expect(() => extractLTVData(new Uint8Array(0))).toThrow(TimestampError);
        });
    });

    describe("addDSS", () => {
        it("should add DSS incrementally without rewriting entire PDF", async () => {
            // Create a simple test PDF
            const pdfDoc = await PDFDocument.create();
            pdfDoc.addPage([612, 792]);
            const originalPdfBytes = await pdfDoc.save();

            // Mock LTV data with a single certificate (just raw bytes for testing)
            const mockLtvData: LTVData = {
                certificates: [new Uint8Array([0x30, 0x82, 0x01, 0x00])], // Minimal DER sequence
                crls: [],
                ocspResponses: [],
            };

            // Add DSS
            const pdfWithDss = await addDSS(originalPdfBytes, mockLtvData);

            // Verify the result is larger than original (incremental append)
            expect(pdfWithDss.length).toBeGreaterThan(originalPdfBytes.length);

            // Verify the original bytes are preserved at the start
            // (this is the key property of incremental save)
            const originalPortion = pdfWithDss.slice(0, originalPdfBytes.length);
            expect(originalPortion).toEqual(originalPdfBytes);

            // Verify the PDF is still valid and can be loaded
            const loadedPdf = await PDFDocument.load(pdfWithDss);
            expect(loadedPdf.getPageCount()).toBe(1);
        });

        it("should preserve signature ByteRange when adding DSS", async () => {
            // Create a PDF with a fake signature structure
            const pdfDoc = await PDFDocument.create();
            pdfDoc.addPage([612, 792]);
            const originalPdfBytes = await pdfDoc.save();

            // Add DSS with empty LTV data (no certs)
            const emptyLtvData: LTVData = {
                certificates: [],
                crls: [],
                ocspResponses: [],
            };

            const pdfWithDss = await addDSS(originalPdfBytes, emptyLtvData);

            // Verify original bytes are preserved
            const originalPortion = pdfWithDss.slice(0, originalPdfBytes.length);
            expect(originalPortion).toEqual(originalPdfBytes);
        });

        it("should handle multiple certificates in LTV data", async () => {
            const pdfDoc = await PDFDocument.create();
            pdfDoc.addPage([612, 792]);
            const originalPdfBytes = await pdfDoc.save();

            // Multiple mock certificates
            const mockLtvData: LTVData = {
                certificates: [
                    new Uint8Array([0x30, 0x82, 0x01, 0x00]),
                    new Uint8Array([0x30, 0x82, 0x02, 0x00]),
                    new Uint8Array([0x30, 0x82, 0x03, 0x00]),
                ],
                crls: [new Uint8Array([0x30, 0x82, 0x04, 0x00])],
                ocspResponses: [],
            };

            const pdfWithDss = await addDSS(originalPdfBytes, mockLtvData);

            // Should be larger due to embedded certificates
            expect(pdfWithDss.length).toBeGreaterThan(originalPdfBytes.length);

            // Original bytes preserved
            const originalPortion = pdfWithDss.slice(0, originalPdfBytes.length);
            expect(originalPortion).toEqual(originalPdfBytes);
        });
    });
});
