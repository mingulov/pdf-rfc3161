import { describe, it, expect, vi, beforeEach } from "vitest";
import { extractTimestamps, verifyTimestamp } from "../../src/pdf/extract.js";
import { TimestampError } from "../../src/types.js";

// Mock dependencies
vi.mock("../../src/pki/pki-utils.js");

import { parseTimestampToken } from "../../src/pki/pki-utils.js";

describe("PDF Timestamp Extraction", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    describe("extractTimestamps", () => {
        it("should return empty array for PDF without timestamps", async () => {
            // Create a minimal valid PDF without signatures
            const minimalPdf = new Uint8Array([
                0x25,
                0x50,
                0x44,
                0x46,
                0x2d,
                0x31,
                0x2e,
                0x34,
                0x0a, // %PDF-1.4
                0x31,
                0x20,
                0x30,
                0x20,
                0x6f,
                0x62,
                0x6a,
                0x0a, // 1 0 obj
                0x3c,
                0x3c,
                0x2f,
                0x54,
                0x79,
                0x70,
                0x65,
                0x20, // <</Type
                0x2f,
                0x43,
                0x61,
                0x74,
                0x61,
                0x6c,
                0x6f,
                0x67, // /Catalog
                0x3e,
                0x3e,
                0x0a,
                0x65,
                0x6e,
                0x64,
                0x6f,
                0x62,
                0x6a, // >>\nendobj
                0x0a,
                0x78,
                0x72,
                0x65,
                0x66,
                0x0a, // \nxref\n
                0x30,
                0x20,
                0x32,
                0x0a, // 0 2\n
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30, // 0000000000
                0x20,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x20,
                0x6e,
                0x0a, //  00000 n\n
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30, // 0000000000
                0x20,
                0x30,
                0x30,
                0x30,
                0x30,
                0x30,
                0x20,
                0x6e,
                0x0a, //  00000 n\n
                0x74,
                0x72,
                0x61,
                0x69,
                0x6c,
                0x65,
                0x72,
                0x0a, // trailer\n
                0x3c,
                0x3c,
                0x2f,
                0x53,
                0x69,
                0x7a,
                0x65,
                0x20, // <</Size
                0x32,
                0x2f,
                0x52,
                0x6f,
                0x6f,
                0x74,
                0x20,
                0x31, // 2/Root 1
                0x20,
                0x30,
                0x20,
                0x52,
                0x3e,
                0x3e,
                0x0a, //  0 R>>\n
                0x73,
                0x74,
                0x61,
                0x72,
                0x74,
                0x78,
                0x72,
                0x65,
                0x66,
                0x0a, // startxref\n
                0x31,
                0x30,
                0x35,
                0x0a, // 105\n
                0x25,
                0x25,
                0x45,
                0x4f,
                0x46, // %%EOF
            ]);

            const result = await extractTimestamps(minimalPdf);

            expect(result).toEqual([]);
        });

        it("should throw error for invalid PDF data", async () => {
            const invalidPdf = new Uint8Array([0x00, 0x01, 0x02]);

            await expect(extractTimestamps(invalidPdf)).rejects.toThrow(TimestampError);
        });

        it("should handle empty PDF data", async () => {
            const emptyPdf = new Uint8Array([]);

            await expect(extractTimestamps(emptyPdf)).rejects.toThrow(TimestampError);
        });

        it("should handle PDF data that is too small", async () => {
            const smallPdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // Just %PDF

            await expect(extractTimestamps(smallPdf)).rejects.toThrow(TimestampError);
        });

        it("should handle malformed PDF structure", async () => {
            // PDF that starts correctly but has invalid structure
            const malformedPdf = new Uint8Array([
                0x25,
                0x50,
                0x44,
                0x46,
                0x2d,
                0x31,
                0x2e,
                0x34,
                0x0a, // %PDF-1.4
                0xff,
                0xff,
                0xff,
                0xff, // Invalid content
            ]);

            await expect(extractTimestamps(malformedPdf)).rejects.toThrow();
        });
    });

    describe("verifyTimestamp", () => {
        const mockExtractedTimestamp = {
            fieldName: "Timestamp1",
            info: {
                genTime: new Date("2024-01-01T00:00:00Z"),
                policy: "1.2.3.4.5",
                serialNumber: "12345",
                hashAlgorithm: "SHA-256",
                messageDigest: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                hasCertificate: true,
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            },
            token: new Uint8Array([0x30, 0x10, 0x20, 0x30]),
            coversWholeDocument: true,
            verified: true,
            byteRange: [0, 100, 200, 50] as [number, number, number, number],
        };

        it("should handle invalid timestamp token", async () => {
            const invalidTimestamp = {
                ...mockExtractedTimestamp,
                token: new Uint8Array([0xff, 0xff]), // Invalid ASN.1
            };

            const result = await verifyTimestamp(invalidTimestamp);

            expect(result.verified).toBe(false);
            expect(result.verificationError).toBeDefined();
        });

        it("should handle verification options", async () => {
            const options = {
                strictESSValidation: true,
            };

            const result = await verifyTimestamp(mockExtractedTimestamp, options);

            // The result should have the same structure regardless of options
            expect(result).toHaveProperty("verified");
            expect(result).toHaveProperty("fieldName");
            expect(result).toHaveProperty("token");
        });

        it("should handle timestamp with invalid token data", async () => {
            const invalidTimestamp = {
                ...mockExtractedTimestamp,
                token: new Uint8Array([]), // Empty token
            };

            const result = await verifyTimestamp(invalidTimestamp);

            expect(result.verified).toBe(false);
            expect(result.verificationError).toBeDefined();
        });

        it("should handle missing token data", async () => {
            const timestampWithoutToken = {
                ...mockExtractedTimestamp,
                token: new Uint8Array([]),
            };

            const mockedParseTimestampToken = vi.mocked(parseTimestampToken);
            mockedParseTimestampToken.mockRejectedValue(new Error("Empty token"));

            const result = await verifyTimestamp(timestampWithoutToken);

            expect(result.verified).toBe(false);
            expect(result.verificationError).toBeDefined();
        });

        it("should handle malformed timestamp info", async () => {
            const malformedTimestamp = {
                ...mockExtractedTimestamp,
                info: null as any, // Invalid info
            };

            const mockedParseTimestampToken = vi.mocked(parseTimestampToken);
            mockedParseTimestampToken.mockResolvedValue(null as any);

            const result = await verifyTimestamp(malformedTimestamp);

            expect(result.verified).toBe(false);
        });

        it("should preserve original timestamp properties", async () => {
            const mockedParseTimestampToken = vi.mocked(parseTimestampToken);
            mockedParseTimestampToken.mockResolvedValue(mockExtractedTimestamp.info);

            const result = await verifyTimestamp(mockExtractedTimestamp);

            expect(result.fieldName).toBe(mockExtractedTimestamp.fieldName);
            expect(result.token).toBe(mockExtractedTimestamp.token);
            expect(result.coversWholeDocument).toBe(mockExtractedTimestamp.coversWholeDocument);
            expect(result.byteRange).toEqual(mockExtractedTimestamp.byteRange);
        });

        it("should handle verification options with strict validation", async () => {
            const options = {
                strictESSValidation: false,
            };

            const result = await verifyTimestamp(mockExtractedTimestamp, options);

            expect(result).toHaveProperty("verified");
            expect(result).toHaveProperty("fieldName");
        });
    });

    describe("Error handling", () => {
        it("should handle extractTimestamps with corrupted PDF structure", async () => {
            // PDF that has valid header but corrupted xref
            const corruptedPdf = new Uint8Array([
                0x25,
                0x50,
                0x44,
                0x46,
                0x2d,
                0x31,
                0x2e,
                0x34,
                0x0a, // Valid header
                0x78,
                0x72,
                0x65,
                0x66,
                0x0a, // xref
                0xff,
                0xff,
                0xff,
                0xff, // Corrupted xref data
            ]);

            await expect(extractTimestamps(corruptedPdf)).rejects.toThrow();
        });
    });
});
