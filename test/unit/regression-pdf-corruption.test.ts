/**
 * Regression test for PDF corruption issue.
 *
 * This test ensures that timestamped PDFs remain structurally valid
 * and can be opened by PDF readers (i.e., they have pages).
 *
 * The bug was caused by `useObjectStreams: true` in pdf-lib-incremental-save
 * which corrupted object streams in certain PDF versions/structures.
 */
import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../src/pdf/prepare.js";

describe("PDF Corruption Regression", () => {
    it("should preserve page count after preparing PDF for timestamp", async () => {
        // Create a simple multi-page PDF
        const originalDoc = await PDFDocument.create();
        originalDoc.addPage([595.28, 841.89]); // A4
        originalDoc.addPage([595.28, 841.89]);
        originalDoc.addPage([595.28, 841.89]);
        const originalBytes = await originalDoc.save();

        // Reload to get accurate page count
        const originalLoaded = await PDFDocument.load(originalBytes);
        const originalPageCount = originalLoaded.getPageCount();
        expect(originalPageCount).toBe(3);

        // Prepare for timestamp (this is where corruption could occur)
        const prepared = await preparePdfForTimestamp(new Uint8Array(originalBytes));

        // Verify the prepared PDF can be loaded and has the same page count
        let preparedDoc: PDFDocument;
        try {
            preparedDoc = await PDFDocument.load(prepared.bytes, { ignoreEncryption: true });
        } catch (e) {
            throw new Error(
                `Regression: Prepared PDF is malformed and cannot be loaded: ${e instanceof Error ? e.message : String(e)}`
            );
        }

        const preparedPageCount = preparedDoc.getPageCount();
        expect(preparedPageCount).toBe(originalPageCount);
    });

    it("should produce a valid PDF structure after preparation", async () => {
        // Create a PDF with content
        const doc = await PDFDocument.create();
        const page = doc.addPage();
        page.drawText("This is a test page for corruption regression", {
            x: 50,
            y: 700,
            size: 12,
        });
        const originalBytes = await doc.save();

        // Prepare for timestamp
        const prepared = await preparePdfForTimestamp(new Uint8Array(originalBytes));

        // Verify the PDF structure is valid by checking essential elements
        const preparedDoc = await PDFDocument.load(prepared.bytes, { ignoreEncryption: true });

        // Check that catalog exists
        const catalog = preparedDoc.catalog;
        expect(catalog).toBeDefined();

        // Check that pages exist
        const pages = preparedDoc.getPages();
        expect(pages.length).toBeGreaterThan(0);

        // Check that the first page has a valid reference
        const firstPage = pages[0];
        expect(firstPage).toBeDefined();
        expect(firstPage?.ref).toBeDefined();
    });
});
