import { describe, it, expect } from "vitest";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { embedTimestampToken, extractBytesToHash } from "../../../core/src/pdf/embed.js";

// Minimal valid PDF (just header and basic structure)
// This is a very simple PDF for testing
const MINIMAL_PDF = createMinimalPdf();

function createMinimalPdf(): Uint8Array {
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

describe("PDF Preparation", () => {
    describe("preparePdfForTimestamp", () => {
        it("should prepare a PDF with signature placeholder", async () => {
            const result = await preparePdfForTimestamp(MINIMAL_PDF);

            expect(result).toHaveProperty("bytes");
            expect(result).toHaveProperty("byteRange");
            expect(result).toHaveProperty("contentsOffset");
            expect(result).toHaveProperty("contentsPlaceholderLength");

            expect(result.bytes).toBeInstanceOf(Uint8Array);
            expect(result.bytes.length).toBeGreaterThan(MINIMAL_PDF.length);
        });

        it("should include ETSI.RFC3161 SubFilter", async () => {
            const result = await preparePdfForTimestamp(MINIMAL_PDF);

            const pdfString = new TextDecoder("latin1").decode(result.bytes);
            // pdf-lib outputs with space: /SubFilter /ETSI.RFC3161
            expect(pdfString).toContain("/SubFilter");
            expect(pdfString).toContain("ETSI.RFC3161");
        });

        it("should include ByteRange", async () => {
            const result = await preparePdfForTimestamp(MINIMAL_PDF);

            const pdfString = new TextDecoder("latin1").decode(result.bytes);
            expect(pdfString).toContain("/ByteRange");
        });

        it("should have valid ByteRange structure", async () => {
            const result = await preparePdfForTimestamp(MINIMAL_PDF);

            const [offset1, length1, offset2, length2] = result.byteRange;

            // First range should start at 0
            expect(offset1).toBe(0);

            // Lengths should be positive
            expect(length1).toBeGreaterThan(0);
            expect(length2).toBeGreaterThan(0);

            // Second range should start after placeholder
            expect(offset2).toBeGreaterThan(length1);

            // Total should equal PDF size
            expect(length1 + (offset2 - length1) + length2).toBe(result.bytes.length);
        });

        it("should respect signatureSize option", async () => {
            const result1 = await preparePdfForTimestamp(MINIMAL_PDF, {
                signatureSize: 4096,
            });

            const result2 = await preparePdfForTimestamp(MINIMAL_PDF, {
                signatureSize: 16384,
            });

            // Larger signature size should result in larger PDF
            expect(result2.bytes.length).toBeGreaterThan(result1.bytes.length);
            expect(result2.contentsPlaceholderLength).toBeGreaterThan(
                result1.contentsPlaceholderLength
            );
        });

        it("should include reason when specified", async () => {
            const result = await preparePdfForTimestamp(MINIMAL_PDF, {
                reason: "Test timestamp",
            });

            const pdfString = new TextDecoder("latin1").decode(result.bytes);
            expect(pdfString).toContain("Test timestamp");
        });

        it("should include location when specified", async () => {
            const result = await preparePdfForTimestamp(MINIMAL_PDF, {
                location: "Test Location",
            });

            const pdfString = new TextDecoder("latin1").decode(result.bytes);
            expect(pdfString).toContain("Test Location");
        });
    });

    describe("extractBytesToHash", () => {
        it("should extract correct byte ranges", async () => {
            const prepared = await preparePdfForTimestamp(MINIMAL_PDF);
            const bytesToHash = extractBytesToHash(prepared);

            const [, length1, , length2] = prepared.byteRange;

            // Extracted bytes should be the sum of both ranges
            expect(bytesToHash.length).toBe(length1 + length2);
        });

        it("should not include placeholder content", async () => {
            const prepared = await preparePdfForTimestamp(MINIMAL_PDF);
            const bytesToHash = extractBytesToHash(prepared);

            // The placeholder is all zeros, so if we see a long run of zeros,
            // it might indicate the placeholder was incorrectly included
            const bytesString = new TextDecoder("latin1").decode(bytesToHash);

            // Should not contain the hex zeros from placeholder
            // The placeholder has thousands of '0' characters
            expect(bytesString).not.toContain("0".repeat(100));
        });
    });

    describe("embedTimestampToken", () => {
        it("should embed token into prepared PDF", async () => {
            const prepared = await preparePdfForTimestamp(MINIMAL_PDF);

            // Create a mock token (just some bytes)
            const mockToken = new Uint8Array(100);
            for (let i = 0; i < 100; i++) {
                mockToken[i] = (i * 17) % 256;
            }

            const result = embedTimestampToken(prepared, mockToken);

            expect(result).toBeInstanceOf(Uint8Array);
            expect(result.length).toBe(prepared.bytes.length);
        });

        it("should throw if token is too large", async () => {
            const prepared = await preparePdfForTimestamp(MINIMAL_PDF, {
                signatureSize: 100, // Very small
            });

            // Token larger than placeholder
            const largeToken = new Uint8Array(200);

            expect(() => embedTimestampToken(prepared, largeToken)).toThrow();
        });

        it("should replace placeholder with token hex", async () => {
            const prepared = await preparePdfForTimestamp(MINIMAL_PDF);

            const mockToken = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
            const result = embedTimestampToken(prepared, mockToken);

            const resultString = new TextDecoder("latin1").decode(result);

            // Should contain the hex representation of the token
            expect(resultString.toLowerCase()).toContain("deadbeef");
        });
    });
});
