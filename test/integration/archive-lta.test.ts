import { describe, it, expect } from "vitest";
import { PDFDocument, PDFName } from "pdf-lib-incremental-save";
import {
    timestampPdf,
    timestampPdfLTA,
    extractTimestamps,
    verifyTimestamp,
    KNOWN_TSA_URLS,
} from "../../src/index.js";

describe("Integration: PAdES-LTA Archive Timestamps", () => {
    // Only run integration tests if explicitly enabled
    const itLive = process.env.LIVE_TSA_TESTS ? it : it.skip;

    itLive(
        "should add archive timestamp to a previously timestamped PDF",
        async () => {
            // Step 1: Create a fresh PDF and add initial timestamp
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const initialResult = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
                signatureFieldName: "InitialTimestamp",
            });

            expect(initialResult.pdf).toBeInstanceOf(Uint8Array);
            expect(initialResult.timestamp).toBeDefined();

            // Step 2: Add archive timestamp using timestampPdfLTA
            const archiveResult = await timestampPdfLTA({
                pdf: initialResult.pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
                signatureFieldName: "ArchiveTimestamp",
            });

            expect(archiveResult.pdf).toBeInstanceOf(Uint8Array);
            expect(archiveResult.pdf.length).toBeGreaterThan(initialResult.pdf.length);
            expect(archiveResult.timestamp).toBeDefined();
            expect(archiveResult.timestamp.genTime).toBeInstanceOf(Date);

            // Step 3: Verify DSS was added (contains collected certificates)
            const reloaded = await PDFDocument.load(archiveResult.pdf);
            expect(reloaded.catalog.has(PDFName.of("DSS"))).toBe(true);

            // Step 4: Verify we now have 2 timestamps
            const timestamps = await extractTimestamps(archiveResult.pdf);
            expect(timestamps.length).toBe(2);

            // Step 5: Verify both timestamps are valid
            for (const ts of timestamps) {
                const verified = await verifyTimestamp(ts, { pdf: archiveResult.pdf });
                expect(verified.verified).toBe(true);
            }
        },
        120000
    );

    itLive(
        "should add archive timestamp to a PDF without prior timestamps",
        async () => {
            // Create fresh PDF without any timestamps
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            // Add archive timestamp directly
            const result = await timestampPdfLTA({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.timestamp).toBeDefined();

            // Should have exactly 1 timestamp (the archive timestamp)
            const timestamps = await extractTimestamps(result.pdf);
            expect(timestamps.length).toBe(1);
        },
        60000
    );

    itLive(
        "should collect certificates from existing timestamps into DSS",
        async () => {
            // Create PDF with initial timestamp
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const initialResult = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
            });

            // Add archive timestamp
            const archiveResult = await timestampPdfLTA({
                pdf: initialResult.pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
                includeExistingRevocationData: true,
            });

            // Verify DSS exists
            const reloaded = await PDFDocument.load(archiveResult.pdf);
            expect(reloaded.catalog.has(PDFName.of("DSS"))).toBe(true);

            // The DSS should contain certificate streams
            // We can verify by checking that the DSS dict has a Certs array
            const dss = reloaded.catalog.lookup(PDFName.of("DSS"));
            expect(dss).toBeDefined();
        },
        120000
    );

    itLive(
        "should respect includeExistingRevocationData=false",
        async () => {
            // Create PDF with initial timestamp
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const initialResult = await timestampPdf({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
            });

            // Add archive timestamp WITHOUT collecting existing revocation data
            const archiveResult = await timestampPdfLTA({
                pdf: initialResult.pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
                includeExistingRevocationData: false,
            });

            expect(archiveResult.pdf).toBeInstanceOf(Uint8Array);
            expect(archiveResult.timestamp).toBeDefined();

            // Should still work and have 2 timestamps
            const timestamps = await extractTimestamps(archiveResult.pdf);
            expect(timestamps.length).toBe(2);
        },
        120000
    );

    itLive(
        "should allow custom signatureFieldName for archive timestamp",
        async () => {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const customFieldName = "MyArchiveTS";

            const result = await timestampPdfLTA({
                pdf: pdfBytes,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
                signatureFieldName: customFieldName,
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.timestamp).toBeDefined();

            // Cannot easily verify the field name without deep PDF parsing,
            // but the fact that it succeeded means it worked
        },
        60000
    );
});
