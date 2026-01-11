import { describe, it, expect, vi, beforeEach } from "vitest";
import { timestampPdfLTA, type ArchiveTimestampOptions } from "../../src/pdf/archive.js";
import type { TimestampResult } from "../../src/types.js";

// Mock dependencies
vi.mock("../../src/pdf/extract.js", () => ({
    extractTimestamps: vi.fn(),
    verifyTimestamp: vi.fn(),
}));

vi.mock("../../src/pdf/ltv.js", () => ({
    addDSS: vi.fn(),
    addVRI: vi.fn(),
    completeLTVData: vi.fn(),
}));

vi.mock("../../src/index.js", () => ({
    timestampPdf: vi.fn(),
}));

// Import the mocked functions
import { extractTimestamps, verifyTimestamp } from "../../src/pdf/extract.js";
import { addDSS, addVRI, completeLTVData } from "../../src/pdf/ltv.js";
import { timestampPdf } from "../../src/index.js";

describe("PDF Archive Timestamping (PAdES-LTA)", () => {
    beforeEach(() => {
        vi.clearAllMocks();

        // Default mock implementations
        const mockedCompleteLTVData = vi.mocked(completeLTVData);
        mockedCompleteLTVData.mockResolvedValue({
            data: {
                certificates: [],
                crls: [],
                ocspResponses: [],
            },
            errors: [],
        });
    });

    const mockPdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]); // Minimal PDF
    const mockTsaConfig = {
        url: "https://tsa.example.com",
        hashAlgorithm: "SHA-256" as const,
    };

    const mockTimestampResult: TimestampResult = {
        pdf: new Uint8Array([...mockPdf, 0x01, 0x02]), // Modified PDF
        timestamp: {
            genTime: new Date("2024-01-01T00:00:00Z"),
            policy: "1.2.3.4.5",
            serialNumber: "12345",
            hashAlgorithm: "SHA-256",
            messageDigest: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", // hex string
            hasCertificate: true,
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
        },
        ltvData: {
            certificates: [new Uint8Array([0x30, 0x01])],
            crls: [new Uint8Array([0x30, 0x02])],
            ocspResponses: [new Uint8Array([0x30, 0x03])],
        },
    };

    describe("timestampPdfLTA", () => {
        it("should process PDF without existing timestamps", async () => {
            // Mock no existing timestamps
            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([]);

            // Mock timestampPdf to return success
            const mockedTimestampPdf = vi.mocked(timestampPdf);
            mockedTimestampPdf.mockResolvedValue(mockTimestampResult);

            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
            };

            const result = await timestampPdfLTA(options);

            expect(mockedExtractTimestamps).toHaveBeenCalledWith(mockPdf);
            expect(mockedTimestampPdf).toHaveBeenCalled();
            expect(result).toEqual(mockTimestampResult);
        });

        it("should process PDF with existing timestamps and collect validation data", async () => {
            const mockExistingTimestamp = {
                fieldName: "Timestamp1",
                info: {
                    genTime: new Date("2023-01-01T00:00:00Z"),
                    policy: "1.2.3.4.1",
                    serialNumber: "67890",
                    hashAlgorithm: "SHA-256",
                    messageDigest:
                        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                    hasCertificate: true,
                    hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                },
                token: new Uint8Array([0x30, 0x10]),
                coversWholeDocument: true,
                verified: true,
                byteRange: [0, 100, 200, 50] as [number, number, number, number],
                certificates: [
                    {
                        toSchema: () => ({ toBER: () => new Uint8Array([0x30, 0x01]) }),
                    },
                ] as any, // Simplified mock
            };

            // Mock existing timestamp
            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([mockExistingTimestamp]);

            // Mock verification with certificates and revocation data
            const mockVerifiedTimestamp = {
                ...mockExistingTimestamp,
                verified: true,
                certificates: [
                    {
                        toSchema: () => ({ toBER: () => new Uint8Array([0x30, 0x01]) }),
                    },
                ] as any,
            };

            const mockedVerifyTimestamp = vi.mocked(verifyTimestamp);
            mockedVerifyTimestamp.mockResolvedValue(mockVerifiedTimestamp);

            // Mock LTV functions
            const mockedAddDSS = vi.mocked(addDSS);
            mockedAddDSS.mockResolvedValue(mockPdf);

            const mockedAddVRI = vi.mocked(addVRI);
            mockedAddVRI.mockResolvedValue(mockPdf);

            // Mock timestampPdf
            const mockedTimestampPdf = vi.mocked(timestampPdf);
            mockedTimestampPdf.mockResolvedValue(mockTimestampResult);

            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
                includeExistingRevocationData: true,
            };

            const result = await timestampPdfLTA(options);

            expect(mockedExtractTimestamps).toHaveBeenCalledWith(mockPdf);
            expect(mockedVerifyTimestamp).toHaveBeenCalledWith(mockExistingTimestamp);
            expect(mockedAddDSS).toHaveBeenCalled();
            // addVRI is conditionally called based on revocation data availability
            expect(mockedTimestampPdf).toHaveBeenCalled();
            expect(result).toEqual(mockTimestampResult);
        });

        it("should skip existing revocation data when disabled", async () => {
            const mockExistingTimestamp = {
                fieldName: "Timestamp1",
                info: {
                    genTime: new Date("2023-01-01T00:00:00Z"),
                    policy: "1.2.3.4.1",
                    serialNumber: "67890",
                    hashAlgorithm: "SHA-256",
                    messageDigest:
                        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                    hasCertificate: true,
                    hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                },
                token: new Uint8Array([0x30, 0x10]),
                coversWholeDocument: true,
                verified: true,
                byteRange: [0, 100, 200, 50] as [number, number, number, number],
            };

            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([mockExistingTimestamp]);

            const mockedVerifyTimestamp = vi.mocked(verifyTimestamp);
            mockedVerifyTimestamp.mockResolvedValue({
                ...mockExistingTimestamp,
                verified: true,
            });

            const mockedTimestampPdf = vi.mocked(timestampPdf);
            mockedTimestampPdf.mockResolvedValue(mockTimestampResult);

            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
                includeExistingRevocationData: false, // Disabled
            };

            const result = await timestampPdfLTA(options);

            expect(mockedVerifyTimestamp).toHaveBeenCalledWith(mockExistingTimestamp);
            expect(mockedTimestampPdf).toHaveBeenCalled();
            expect(result).toEqual(mockTimestampResult);
        });

        it("should use custom signature field name", async () => {
            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([]);

            const mockedTimestampPdf = vi.mocked(timestampPdf);
            mockedTimestampPdf.mockResolvedValue(mockTimestampResult);

            const customFieldName = "CustomArchiveTimestamp";
            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
                signatureFieldName: customFieldName,
            };

            await timestampPdfLTA(options);

            expect(mockedTimestampPdf).toHaveBeenCalledWith(
                expect.objectContaining({
                    signatureFieldName: customFieldName,
                })
            );
        });

        it("should handle empty PDF", async () => {
            const emptyPdf = new Uint8Array([]);

            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([]);

            const mockedTimestampPdf = vi.mocked(timestampPdf);
            mockedTimestampPdf.mockResolvedValue({
                ...mockTimestampResult,
                pdf: emptyPdf,
            });

            const options: ArchiveTimestampOptions = {
                pdf: emptyPdf,
                tsa: mockTsaConfig,
            };

            const result = await timestampPdfLTA(options);

            expect(mockedExtractTimestamps).toHaveBeenCalledWith(emptyPdf);
            expect(result.pdf).toBe(emptyPdf);
        });

        it("should propagate errors from timestampPdf", async () => {
            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([]);

            const mockError = new Error("TSA request failed");
            const mockedTimestampPdf = vi.mocked(timestampPdf);
            mockedTimestampPdf.mockRejectedValue(mockError);

            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
            };

            await expect(timestampPdfLTA(options)).rejects.toThrow("TSA request failed");
        });
    });

    describe("Error handling", () => {
        it("should handle extractTimestamps failure", async () => {
            const mockError = new Error("Failed to extract timestamps");
            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockRejectedValue(mockError);

            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
            };

            await expect(timestampPdfLTA(options)).rejects.toThrow("Failed to extract timestamps");
        });

        it("should handle verifyTimestamp failure", async () => {
            const mockExistingTimestamp = {
                fieldName: "Timestamp1",
                info: {
                    genTime: new Date(),
                    policy: "1.2.3.4.1",
                    serialNumber: "67890",
                    hashAlgorithm: "SHA-256",
                    messageDigest:
                        "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                    hasCertificate: true,
                    hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                },
                token: new Uint8Array([0x30, 0x10]),
                coversWholeDocument: true,
                verified: true,
                byteRange: [0, 100, 200, 50] as [number, number, number, number],
            };

            const mockedExtractTimestamps = vi.mocked(extractTimestamps);
            mockedExtractTimestamps.mockResolvedValue([mockExistingTimestamp]);

            const mockError = new Error("Verification failed");
            const mockedVerifyTimestamp = vi.mocked(verifyTimestamp);
            mockedVerifyTimestamp.mockRejectedValue(mockError);

            const options: ArchiveTimestampOptions = {
                pdf: mockPdf,
                tsa: mockTsaConfig,
            };

            await expect(timestampPdfLTA(options)).rejects.toThrow("Verification failed");
        });
    });
});
