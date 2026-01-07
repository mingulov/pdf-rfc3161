import { describe, it, expect } from "vitest";
import { timestampPdf, KNOWN_TSA_URLS } from "../../src/index.js";

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

describe("Integration: Basic Timestamping", () => {
    // Only run integration tests if explicitly enabled
    const itIntegration = process.env.LIVE_TSA_TESTS ? it : it.skip;

    itIntegration(
        "should timestamp a PDF with DigiCert TSA",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    timeout: 30000,
                },
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.pdf.length).toBeGreaterThan(pdf.length);

            expect(result.timestamp).toBeDefined();
            expect(result.timestamp.genTime).toBeInstanceOf(Date);
            expect(result.timestamp.policy).toBeTruthy();
            expect(result.timestamp.serialNumber).toBeTruthy();
            expect(result.timestamp.hashAlgorithm).toBe("SHA-256");

            // Verify we got a valid timestamped PDF
            const pdfString = new TextDecoder("latin1").decode(result.pdf);
            expect(pdfString.startsWith("%PDF-")).toBe(true);
            expect(pdfString).toContain("ETSI.RFC3161");
        },
        60000
    );

    itIntegration(
        "should timestamp with SHA-384",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.DIGICERT,
                    hashAlgorithm: "SHA-384",
                    timeout: 30000,
                },
            });

            expect(result.timestamp.hashAlgorithm).toBe("SHA-384");
        },
        60000
    );

    itIntegration(
        "should timestamp with Sectigo TSA",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.SECTIGO,
                    timeout: 30000,
                },
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.timestamp.genTime).toBeInstanceOf(Date);
        },
        60000
    );

    itIntegration(
        "should timestamp with FreeTSA",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: {
                    url: KNOWN_TSA_URLS.FREETSA,
                    timeout: 30000,
                },
            });

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(result.timestamp.genTime).toBeInstanceOf(Date);
            expect(result.timestamp.policy).toBeTruthy();
        },
        60000
    );

    itIntegration(
        "should return different timestamp for each request",
        async () => {
            const pdf = createTestPdf();

            const result1 = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.DIGICERT },
            });

            // Wait a moment to ensure different timestamp
            await new Promise((r) => setTimeout(r, 100));

            const result2 = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.DIGICERT },
            });

            // Serial numbers should be different
            expect(result1.timestamp.serialNumber).not.toBe(result2.timestamp.serialNumber);
        },
        60000
    );
});
