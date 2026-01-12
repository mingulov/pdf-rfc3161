import { describe, it, expect } from "vitest";
import { PDFDocument, PDFName } from "pdf-lib-incremental-save";
import {
    timestampPdf,
    timestampPdfMultiple,
    KNOWN_TSA_URLS,
} from "pdf-rfc3161";
import { INCOMPATIBLE_TSA_URLS } from "../../src/tsa-compatibility.js";

/**
 * Helper function that handles incompatible TSA servers gracefully.
 */
async function withTSAHandler(tsaUrl: string, testFn: () => Promise<void>): Promise<void> {
    if (INCOMPATIBLE_TSA_URLS.has(tsaUrl)) {
        try {
            await testFn();
            throw new Error(`Expected TimestampError for incompatible TSA: ${tsaUrl}`);
        } catch (error) {
            if ((error as Error).message.includes("Expected TimestampError")) {
                throw error;
            }
            expect((error as Error).name).toBe("TimestampError");
        }
    } else {
        await testFn();
    }
}

describe("Integration: LTV and Multiple Timestamps", () => {
    // Only run integration tests if explicitly enabled
    const itLive = process.env.LIVE_TSA_TESTS ? it : it.skip;

    itLive(
        "should timestamp with LTV enabled",
        async () => {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            await withTSAHandler(KNOWN_TSA_URLS.DIGICERT, async () => {
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: {
                        url: KNOWN_TSA_URLS.DIGICERT,
                        timeout: 30000,
                    },
                    enableLTV: true,
                });

                expect(result.pdf).toBeInstanceOf(Uint8Array);
                expect(result.pdf.length).toBeGreaterThan(pdfBytes.length);
                expect(result.timestamp).toBeDefined();
                expect(result.timestamp.genTime).toBeInstanceOf(Date);

                // LTV data should be present
                expect(result.ltvData).toBeDefined();
                expect(result.ltvData?.certificates).toBeDefined();
                expect(result.ltvData?.certificates.length).toBeGreaterThan(0);

                // Verify DSS was added by reloading the PDF and checking catalog
                // (DSS may be in a compressed object stream, so string search doesn't work)
                const reloaded = await PDFDocument.load(result.pdf);
                expect(reloaded.catalog.has(PDFName.of("DSS"))).toBe(true);
            });
        },
        60000
    );

    itLive(
        "should timestamp with multiple TSAs",
        async () => {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const tsaUrls = [KNOWN_TSA_URLS.DIGICERT, KNOWN_TSA_URLS.SECTIGO];
            const hasIncompatible = tsaUrls.some((url) => INCOMPATIBLE_TSA_URLS.has(url));

            if (hasIncompatible) {
                try {
                    await timestampPdfMultiple({
                        pdf: pdfBytes,
                        tsaList: [
                            { url: KNOWN_TSA_URLS.DIGICERT, timeout: 30000 },
                            { url: KNOWN_TSA_URLS.SECTIGO, timeout: 30000 },
                        ],
                    });
                } catch (error) {
                    expect((error as Error).name).toBe("TimestampError");
                }
                return;
            }

            const result = await timestampPdfMultiple({
                pdf: pdfBytes,
                tsaList: [
                    { url: KNOWN_TSA_URLS.DIGICERT, timeout: 30000 },
                    { url: KNOWN_TSA_URLS.SECTIGO, timeout: 30000 },
                ],
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.timestamps).toHaveLength(2);
            expect(result.timestamps[0]?.genTime).toBeInstanceOf(Date);
            expect(result.timestamps[1]?.genTime).toBeInstanceOf(Date);

            // Serial numbers should be different (different TSAs)
            expect(result.timestamps[0]?.serialNumber).not.toBe(result.timestamps[1]?.serialNumber);
        },
        120000
    );

    itLive(
        "should timestamp with multiple TSAs and LTV enabled",
        async () => {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            const tsaUrls = [KNOWN_TSA_URLS.DIGICERT, KNOWN_TSA_URLS.SECTIGO];
            const hasIncompatible = tsaUrls.some((url) => INCOMPATIBLE_TSA_URLS.has(url));

            if (hasIncompatible) {
                try {
                    await timestampPdfMultiple({
                        pdf: pdfBytes,
                        tsaList: [
                            { url: KNOWN_TSA_URLS.DIGICERT, timeout: 30000 },
                            { url: KNOWN_TSA_URLS.SECTIGO, timeout: 30000 },
                        ],
                        enableLTV: true,
                    });
                } catch (error) {
                    expect((error as Error).name).toBe("TimestampError");
                }
                return;
            }

            const result = await timestampPdfMultiple({
                pdf: pdfBytes,
                tsaList: [
                    { url: KNOWN_TSA_URLS.DIGICERT, timeout: 30000 },
                    { url: KNOWN_TSA_URLS.SECTIGO, timeout: 30000 },
                ],
                enableLTV: true,
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.timestamps).toHaveLength(2);

            // LTV data should be present for both timestamps
            expect(result.ltvData).toBeDefined();
            expect(result.ltvData?.length).toBe(2);

            // Each LTV entry should have certificates
            for (const ltv of result.ltvData ?? []) {
                expect(ltv?.certificates.length).toBeGreaterThan(0);
            }

            // Verify DSS was added by reloading the PDF
            const reloaded = await PDFDocument.load(result.pdf);
            expect(reloaded.catalog.has(PDFName.of("DSS"))).toBe(true);
        },
        120000
    );

    itLive(
        "should return ltvData as undefined when LTV is disabled",
        async () => {
            const doc = await PDFDocument.create();
            doc.addPage([100, 100]);
            const pdfBytes = await doc.save();

            await withTSAHandler(KNOWN_TSA_URLS.DIGICERT, async () => {
                const result = await timestampPdf({
                    pdf: pdfBytes,
                    tsa: {
                        url: KNOWN_TSA_URLS.DIGICERT,
                        timeout: 30000,
                    },
                    enableLTV: false,
                });

                expect(result.pdf).toBeInstanceOf(Uint8Array);
                expect(result.timestamp).toBeDefined();
                expect(result.ltvData).toBeUndefined();

                // Verify DSS was NOT added by reloading the PDF
                const reloaded = await PDFDocument.load(result.pdf);
                expect(reloaded.catalog.has(PDFName.of("DSS"))).toBe(false);
            });
        },
        60000
    );
});
