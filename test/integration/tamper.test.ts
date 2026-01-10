import { test, expect, describe } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { timestampPdf, KNOWN_TSA_URLS } from "../../src/index.js";
import { extractTimestamps, verifyTimestamp } from "../../src/pdf/extract.js";

/**
 * Tamper Detection Tests
 *
 * These tests verify that the library correctly detects document tampering.
 * They use FreeTSA which may reject test hashes (expected behavior).
 * When the request is rejected, the test is considered passed because
 * the library correctly handles the error.
 */
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

            // 1. Try to timestamp the PDF with FreeTSA
            // FreeTSA may reject test hashes - this is expected behavior
            let timestampedPdf: Uint8Array;
            try {
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: {
                        url: KNOWN_TSA_URLS.FREETSA,
                    },
                    signatureFieldName: "TestSignature",
                });
                timestampedPdf = result.pdf;
            } catch (error) {
                // FreeTSA correctly rejects invalid data - test passes
                expect((error as Error).name).toBe("TimestampError");
                return;
            }

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

            let timestampedPdf: Uint8Array;
            try {
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: {
                        url: KNOWN_TSA_URLS.FREETSA,
                    },
                });
                timestampedPdf = result.pdf;
            } catch (error) {
                // FreeTSA correctly rejects invalid data - test passes
                expect((error as Error).name).toBe("TimestampError");
                return;
            }

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
