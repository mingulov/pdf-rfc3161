import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";

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

describe("Integration: TSA Certificate Trust Verification", () => {
    // Only run integration tests if explicitly enabled
    const itIntegration = process.env.LIVE_TSA_TESTS ? it : it.skip;

    // Test that each public TSA returns valid, parseable timestamps with certificates
    Object.entries(KNOWN_TSA_URLS).forEach(([name, url]) => {
        itIntegration(
            `${name} TSA should return a valid timestamp with certificate`,
            async () => {
                const pdf = createTestPdf();

                const result = await timestampPdf({
                    pdf,
                    tsa: { url, timeout: 30000 },
                });

                // Verify we got a response
                expect(result.pdf).toBeInstanceOf(Uint8Array);
                expect(result.timestamp.genTime).toBeInstanceOf(Date);
                expect(result.timestamp.policy).toBeTruthy();
                expect(result.timestamp.serialNumber).toBeTruthy();

                // Verify certificate was included (required for trust verification)
                expect(result.timestamp.hasCertificate).toBe(true);
            },
            60000
        );
    });

    itIntegration(
        "DigiCert timestamp should have valid certificate properties",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.DIGICERT },
            });

            // Verify the timestamp has a certificate
            expect(result.timestamp.hasCertificate).toBe(true);

            // Verify timestamp time is reasonable (within last hour)
            const now = new Date();
            const diff = now.getTime() - result.timestamp.genTime.getTime();
            expect(diff).toBeLessThan(3600000); // Less than 1 hour ago
            expect(diff).toBeGreaterThan(-60000); // Not more than 1 minute in future

            // Verify hash algorithm
            expect(["SHA-256", "SHA-384", "SHA-512"]).toContain(result.timestamp.hashAlgorithm);

            // Verify serial number is hex
            expect(result.timestamp.serialNumber).toMatch(/^[0-9a-f]+$/);

            // Verify message digest is hex
            expect(result.timestamp.messageDigest).toMatch(/^[0-9a-f]+$/);
        },
        60000
    );

    itIntegration(
        "Sectigo timestamp should have valid certificate properties",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.SECTIGO },
            });

            expect(result.timestamp.hasCertificate).toBe(true);
            expect(result.timestamp.policy).toBeTruthy();

            // OID should be a valid format
            expect(result.timestamp.policy).toMatch(/^\d+(\.\d+)+$/);
        },
        60000
    );

    itIntegration(
        "FreeTSA timestamp should have valid certificate properties",
        async () => {
            const pdf = createTestPdf();

            const result = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.FREETSA },
            });

            expect(result.timestamp.hasCertificate).toBe(true);
            expect(result.timestamp.policy).toBeTruthy();
        },
        60000
    );
});
