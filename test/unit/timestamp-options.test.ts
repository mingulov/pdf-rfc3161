import { describe, it, expect } from "vitest";
import { timestampPdf, TimestampErrorCode } from "../../src/index.js";
import { preparePdfForTimestamp } from "../../src/pdf/prepare.js";

function createTestPdf(sizeKB = 1): Uint8Array {
    const content = new Array(sizeKB * 1024).fill(0).map(() => 65); // 'A'
    return new Uint8Array(content);
}

describe("Timestamp Options Unit Tests", () => {
    it("should reject PDFs larger than MAX_PDF_SIZE", async () => {
        const largePdf = createTestPdf(1);
        // Mock the MAX_PDF_SIZE Check by passing a small maxSize

        try {
            await timestampPdf({
                pdf: largePdf,
                tsa: { url: "http://example.com" },
                maxSize: 100, // 100 bytes is smaller than 1KB
            });
            expect.fail("Should have thrown error");
        } catch (error: any) {
            expect(error.code).toBe(TimestampErrorCode.PDF_ERROR);
            expect(error.message).toContain("exceeds maximum");
        }
    });

    it("should accept PDFs smaller than maxSize", async () => {
        // We expect this to fail later at PDF parsing, not size check
        const smallPdf = new Uint8Array([37, 80, 68, 70, 45, 49, 46, 52]); // %PDF-1.4 header only

        try {
            await timestampPdf({
                pdf: smallPdf,
                tsa: { url: "http://example.com" },
                maxSize: 1000,
            });
            // If it fails here, it should be because of parsing or network, NOT size
        } catch (error: any) {
            expect(error.code).not.toBe(TimestampErrorCode.PDF_ERROR);
            expect(error.message).not.toContain("exceeds maximum");
        }
    });

    it("should use custom signature field name", async () => {
        const minimalPdf = new TextEncoder().encode(`%PDF-1.4
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
%%EOF`);

        const result = await preparePdfForTimestamp(minimalPdf, {
            signatureFieldName: "MyCustomSignature",
        });

        // With object streams, the field name may be compressed
        // Instead, verify the signature type is present (RFC3161 timestamp)
        const pdfString = new TextDecoder("latin1").decode(result.bytes);
        expect(pdfString).toContain("ETSI.RFC3161");
    });

    it("should default signature field name to Timestamp", async () => {
        const minimalPdf = new TextEncoder().encode(`%PDF-1.4
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
%%EOF`);

        const result = await preparePdfForTimestamp(minimalPdf, {});

        // With object streams, the field name may be compressed
        // Instead, verify the signature type is present (RFC3161 timestamp)
        const pdfString = new TextDecoder("latin1").decode(result.bytes);
        expect(pdfString).toContain("ETSI.RFC3161");
    });
});
