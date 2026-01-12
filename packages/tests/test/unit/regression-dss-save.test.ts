import { describe, it, expect } from "vitest";
import { PDFDocument, PDFName, PDFArray, PDFRef, PDFDict } from "pdf-lib-incremental-save";

/**
 * Regression test for DSS (Document Security Store) saving.
 *
 * Issue: DSS objects added to the catalog were not being properly saved
 * in incremental updates because the objects needed to be marked for save.
 *
 * The fix ensures that:
 * 1. The DSS dictionary reference is marked for save
 * 2. All certificate/CRL/OCSP stream references are marked for save
 * 3. The catalog reference is marked so the DSS entry is included
 */
describe("Regression: DSS Saving", () => {
    it("should save DSS to catalog via incremental update", async () => {
        // Create a minimal PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // Load the PDF
        const doc2 = await PDFDocument.load(pdfBytes, { updateMetadata: false });
        const snapshot = doc2.takeSnapshot();
        const context = doc2.context;

        // Create a DSS dictionary with a Certs array
        const certsArray = PDFArray.withContext(context);
        const dssDict = context.obj({
            Certs: certsArray,
        });
        const dssRef = context.register(dssDict);

        // Add to catalog
        doc2.catalog.set(PDFName.of("DSS"), dssRef);

        // Mark refs for save
        snapshot.markRefForSave(dssRef);
        const catalogRef = context.trailerInfo.Root;
        if (catalogRef instanceof PDFRef) {
            snapshot.markRefForSave(catalogRef);
        }

        // Save incrementally
        const incrementalBytes = await doc2.saveIncremental(snapshot);
        const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
        finalBytes.set(pdfBytes, 0);
        finalBytes.set(incrementalBytes, pdfBytes.length);

        // Verify by reloading
        const doc3 = await PDFDocument.load(finalBytes);
        expect(doc3.catalog.has(PDFName.of("DSS"))).toBe(true);

        const dssValue = doc3.catalog.get(PDFName.of("DSS"));
        expect(dssValue).toBeInstanceOf(PDFRef);
    });

    it("should save DSS with certificate streams via incremental update", async () => {
        // Create a minimal PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        // Load the PDF
        const doc2 = await PDFDocument.load(pdfBytes, { updateMetadata: false });
        const snapshot = doc2.takeSnapshot();
        const context = doc2.context;

        // Create a fake certificate stream
        const fakeCertData = new Uint8Array([0x30, 0x82, 0x01, 0x00, 0x00, 0x00]);
        const { PDFRawStream } = await import("pdf-lib-incremental-save");
        const certStream = PDFRawStream.of(PDFDict.withContext(context), fakeCertData);
        const certRef = context.register(certStream);

        // Create DSS with the certificate
        const certsArray = PDFArray.withContext(context);
        certsArray.push(certRef);

        const dssDict = context.obj({
            Certs: certsArray,
        });
        const dssRef = context.register(dssDict);

        // Add to catalog
        doc2.catalog.set(PDFName.of("DSS"), dssRef);

        // Mark refs for save
        snapshot.markRefForSave(dssRef);
        snapshot.markRefForSave(certRef);
        const catalogRef = context.trailerInfo.Root;
        if (catalogRef instanceof PDFRef) {
            snapshot.markRefForSave(catalogRef);
        }

        // Save incrementally
        const incrementalBytes = await doc2.saveIncremental(snapshot);
        const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
        finalBytes.set(pdfBytes, 0);
        finalBytes.set(incrementalBytes, pdfBytes.length);

        // Verify by reloading
        const doc3 = await PDFDocument.load(finalBytes);
        expect(doc3.catalog.has(PDFName.of("DSS"))).toBe(true);

        // Verify the DSS contains the Certs array
        const dssValue = doc3.catalog.lookup(PDFName.of("DSS"));
        expect(dssValue).toBeDefined();

        if (dssValue instanceof PDFDict) {
            const certs = dssValue.get(PDFName.of("Certs"));
            expect(certs).toBeInstanceOf(PDFArray);
            if (certs instanceof PDFArray) {
                expect(certs.size()).toBe(1);
            }
        }
    });
});
