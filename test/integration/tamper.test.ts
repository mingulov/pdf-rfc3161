import { test, expect, describe } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { timestampPdf } from "../../src/index.js";
import { extractTimestamps, verifyTimestamp } from "../../src/pdf/extract.js";

describe("Tamper Detection", () => {
    // Only run if live tests are enabled, otherwise skip
    const testLive = process.env.LIVE_TSA_TESTS ? test : test.skip;

    testLive(
        "should fail verification if document is modified after timestamping",
        async () => {
            // Create a fresh PDF
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            // 1. Timestamp the PDF
            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: "https://freetsa.org/tsr",
                },
                signatureFieldName: "TestSignature",
            });

            const timestampedPdf = result.pdf;

            // 2. Verify it is valid initially
            const extracted = await extractTimestamps(timestampedPdf);
            expect(extracted.length).toBe(1);

            const initial = extracted[0];
            if (!initial) throw new Error("No timestamp extracted");
            const verifiedInitial = await verifyTimestamp(initial, { pdf: timestampedPdf });
            expect(verifiedInitial.verified).toBe(true);
            expect(verifiedInitial.verificationError).toBeUndefined();

            // 3. Tamper with the PDF
            const tamperedPdf = new Uint8Array(timestampedPdf);

            // Toggle PDF version minor digit (usually at index 7)
            tamperedPdf[7] = tamperedPdf[7] === 55 ? 56 : 55;

            // 4. Verify it fails now
            const extractedTampered = await extractTimeStamps(tamperedPdf);
            expect(extractedTampered.length).toBe(1);

            const tampered = extractedTampered[0];
            if (!tampered) throw new Error("No timestamp extracted from tampered PDF");
            const verifiedTampered = await verifyTimestamp(tampered, {
                pdf: tamperedPdf,
            });
            expect(verifiedTampered.verified).toBe(false);
            expect(verifiedTampered.verificationError).toContain("Document hash mismatch");
        },
        30000
    );

    testLive(
        "should verify correctly without hash check if pdf bytes are not provided",
        async () => {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const result = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: "https://freetsa.org/tsr",
                },
            });

            const timestampedPdf = result.pdf;
            const extracted = await extractTimestamps(timestampedPdf);

            // Tamper
            const tamperedPdf = new Uint8Array(timestampedPdf);
            tamperedPdf[7] = tamperedPdf[7] === 55 ? 56 : 55;

            // Verify WITHOUT pdf bytes -> should pass cryptographic check of the TOKEN itself
            const first = extracted[0];
            if (!first) throw new Error("No timestamp extracted");
            const verifiedNoPdf = await verifyTimestamp(first);
            expect(verifiedNoPdf.verified).toBe(true);
        },
        30000
    );
});

// Helper for type safety in test
async function extractTimeStamps(pdf: Uint8Array) {
    return extractTimestamps(pdf);
}
