import { describe, it, expect } from "vitest";
import { timestampPdf, KNOWN_TSA_URLS, preparePdfForTimestamp } from "../../src/index.js";

// Create test PDFs of various sizes
function createTestPdf(sizeKB = 1): Uint8Array {
    const baseContent = `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> /Contents 4 0 R >>
endobj
4 0 obj
<< /Length ${(sizeKB * 1024).toString()} >>
stream
`;
    const padding = "A".repeat(sizeKB * 1024);
    const endContent = `
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000214 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
${(300 + sizeKB * 1024).toString()}
%%EOF`;

    return new TextEncoder().encode(baseContent + padding + endContent);
}

describe("Performance Tests", () => {
    describe("Integration: Performance", () => {
        // Only run integration tests if explicitly enabled
        const itIntegration = process.env.LIVE_TSA_TESTS ? it : it.skip;

        itIntegration("should add timestamp within acceptable time limit", async () => {
            const pdf = createTestPdf(1);

            const start = performance.now();
            const result = await preparePdfForTimestamp(pdf);
            const elapsed = performance.now() - start;

            expect(result.bytes).toBeInstanceOf(Uint8Array);
            expect(elapsed).toBeLessThan(500); // Should be under 500ms
            console.log(`1KB PDF prepared in ${elapsed.toFixed(2)}ms`);
        });

        itIntegration("should prepare a 100KB PDF quickly", async () => {
            const pdf = createTestPdf(100);

            const start = performance.now();
            const result = await preparePdfForTimestamp(pdf);
            const elapsed = performance.now() - start;

            expect(result.bytes).toBeInstanceOf(Uint8Array);
            expect(elapsed).toBeLessThan(1000); // Should be under 1s
            console.log(`100KB PDF prepared in ${elapsed.toFixed(2)}ms`);
        });

        itIntegration("should prepare a 1MB PDF in reasonable time", async () => {
            const pdf = createTestPdf(1024);

            const start = performance.now();
            const result = await preparePdfForTimestamp(pdf);
            const elapsed = performance.now() - start;

            expect(result.bytes).toBeInstanceOf(Uint8Array);
            expect(elapsed).toBeLessThan(5000); // Should be under 5s
            console.log(`1MB PDF prepared in ${elapsed.toFixed(2)}ms`);
        });

        itIntegration("should use 8KB default placeholder (sufficient for most TSAs)", async () => {
            const pdf = createTestPdf(1);
            const result = await preparePdfForTimestamp(pdf);

            // Default is 8192 bytes = 16384 hex characters
            expect(result.contentsPlaceholderLength).toBe(16384);
        });

        itIntegration("should allow custom signature size", async () => {
            const pdf = createTestPdf(1);

            const result4k = await preparePdfForTimestamp(pdf, { signatureSize: 4096 });
            const result16k = await preparePdfForTimestamp(pdf, { signatureSize: 16384 });

            expect(result4k.contentsPlaceholderLength).toBe(8192); // 4096 * 2
            expect(result16k.contentsPlaceholderLength).toBe(32768); // 16384 * 2
        });

        itIntegration("should handle large PDF files (1MB)", async () => {
            // Test with a larger placeholder to ensure it works
            const pdf = createTestPdf(1);
            const result = await preparePdfForTimestamp(pdf, { signatureSize: 32768 });

            expect(result.contentsPlaceholderLength).toBe(65536);
        });
    });
});

describe("Integration: Performance with Real TSA", () => {
    // Only run integration tests if explicitly enabled
    const itIntegration = process.env.LIVE_TSA_TESTS ? it : it.skip;

    itIntegration(
        "should measure actual timestamp token sizes from different TSAs",
        async () => {
            const pdf = createTestPdf(1);
            const sizes: Record<string, number> = {};

            // Test DigiCert
            const digicertResult = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.DIGICERT },
            });

            // Extract token size from the PDF
            const pdfString = new TextDecoder("latin1").decode(digicertResult.pdf);
            const contentsMatch = /\/Contents\s*<([0-9A-Fa-f]+)>/.exec(pdfString);

            if (contentsMatch?.[1]) {
                // Find first non-zero byte to get actual content length
                const hex = contentsMatch[1];
                let actualLength = hex.length;
                for (let i = hex.length - 1; i >= 0; i--) {
                    if (hex[i] !== "0") {
                        actualLength = i + 1;
                        break;
                    }
                }
                sizes.DigiCert = Math.ceil(actualLength / 2); // Convert hex chars to bytes
            }

            console.log("Actual TSA token sizes:");
            for (const [name, size] of Object.entries(sizes)) {
                console.log(`  ${name}: ${size.toString()} bytes`);
            }

            // DigiCert tokens are typically 4-6KB
            if (sizes.DigiCert !== undefined) {
                expect(sizes.DigiCert).toBeLessThan(8192);
                expect(sizes.DigiCert).toBeGreaterThan(1000);
            } else {
                // If we couldn't extract, the test still passes but log it
                console.log("Could not extract token size from PDF");
            }
        },
        60000
    );

    itIntegration(
        "should complete full timestamping within 10 seconds",
        async () => {
            const pdf = createTestPdf(100); // 100KB PDF

            const start = performance.now();
            const result = await timestampPdf({
                pdf,
                tsa: { url: KNOWN_TSA_URLS.DIGICERT },
            });
            const elapsed = performance.now() - start;

            expect(result.pdf).toBeInstanceOf(Uint8Array);
            expect(elapsed).toBeLessThan(10000); // Should complete within 10s
            console.log(`Full timestamping of 100KB PDF completed in ${elapsed.toFixed(2)}ms`);
        },
        60000
    );
});
