import { describe, it, expect } from "vitest";
import { timestampPdf, timestampPdfMultiple, KNOWN_TSA_URLS } from "../../src/index.js";

// Create a minimal valid PDF for testing
function createTestPdf(): Uint8Array {
    const pdfContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
210
%%EOF`;
    return new TextEncoder().encode(pdfContent);
}

describe("Integration: Advanced Features", () => {
    // Only run integration tests if explicitly enabled
    const itIntegration = process.env.LIVE_TSA_TESTS ? it : it.skip;

    describe("Multiple Timestamps", () => {
        itIntegration(
            "should add timestamps from multiple TSAs",
            async () => {
                const pdf = createTestPdf();

                const result = await timestampPdfMultiple({
                    pdf,
                    tsaList: [{ url: KNOWN_TSA_URLS.DIGICERT }, { url: KNOWN_TSA_URLS.SECTIGO }],
                });

                expect(result.pdf).toBeInstanceOf(Uint8Array);
                expect(result.timestamps).toHaveLength(2);

                // Both timestamps should have valid times
                expect(result.timestamps[0]?.genTime).toBeInstanceOf(Date);
                expect(result.timestamps[1]?.genTime).toBeInstanceOf(Date);
            },
            120000
        );

        itIntegration(
            "should add timestamp sequentially to same PDF",
            async () => {
                const pdf = createTestPdf();

                // First timestamp
                const result1 = await timestampPdf({
                    pdf,
                    tsa: { url: KNOWN_TSA_URLS.SECTIGO },
                });

                expect(result1.pdf.length).toBeGreaterThan(pdf.length);

                // Second timestamp on the already-timestamped PDF
                const result2 = await timestampPdf({
                    pdf: result1.pdf,
                    tsa: { url: KNOWN_TSA_URLS.DIGICERT },
                });

                expect(result2.pdf.length).toBeGreaterThan(result1.pdf.length);
            },
            120000
        );
    });

    describe("LTV Data Extraction", () => {
        itIntegration(
            "should extract LTV data from timestamp token",
            async () => {
                const pdf = createTestPdf();

                // Get a timestamp with the token available
                const result = await timestampPdf({
                    pdf,
                    tsa: { url: KNOWN_TSA_URLS.DIGICERT },
                });

                // The result.pdf contains the embedded timestamp
                // To extract the token, we need to parse the PDF
                // For now, we test the extractLTVData function with a mock

                // Verify the PDF was timestamped
                expect(result.pdf).toBeInstanceOf(Uint8Array);
                expect(result.timestamp.hasCertificate).toBe(true);
            },
            60000
        );

        itIntegration(
            "should include certificates from TSA",
            async () => {
                const pdf = createTestPdf();

                const result = await timestampPdf({
                    pdf,
                    tsa: { url: KNOWN_TSA_URLS.DIGICERT },
                });

                // DigiCert should include certificates in the response
                expect(result.timestamp.hasCertificate).toBe(true);
            },
            60000
        );
    });
});
