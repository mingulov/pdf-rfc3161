import { describe, it, expect, vi, beforeEach } from "vitest";
import {
    archiveTimestamp,
    timestampPdfLTA,
    type ArchiveTimestampOptions,
} from "../../../core/src/pdf/archive.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import type { TimestampResult } from "../../../core/src/types.js";

// Mock dependencies -- these tests cover wrapper-layer wiring only.
// End-to-end PAdES-LTA behaviour is exercised in the LIVE-only
// integration tests (`archive-lta.test.ts`).
vi.mock("../../../core/src/pdf/extract.js", () => ({
    extractTimestamps: vi.fn(),
    verifyTimestamp: vi.fn(),
}));

vi.mock("../../../core/src/pdf/ltv.js", () => ({
    addDSS: vi.fn(),
    addVRI: vi.fn(),
    extractLTVData: vi.fn(),
    completeLTVData: vi.fn(),
}));

vi.mock("../../../core/src/index.js", () => ({
    timestampPdf: vi.fn(),
}));

// Mock the logger so we can assert warn() was called on the verify-failure
// path without polluting test output.
const warnSpy = vi.fn();
vi.mock("../../../core/src/utils/logger.js", async (importOriginal) => {
    const mod = await importOriginal<typeof import("../../../core/src/utils/logger.js")>();
    return {
        ...mod,
        getLogger: () => ({
            debug: vi.fn(),
            info: vi.fn(),
            warn: warnSpy,
            error: vi.fn(),
        }),
    };
});

import { extractTimestamps, verifyTimestamp } from "../../../core/src/pdf/extract.js";
import { completeLTVData, extractLTVData } from "../../../core/src/pdf/ltv.js";
import { timestampPdf } from "../../../core/src/index.js";

describe("PDF Archive Timestamping (PAdES-LTA) -- wrapper wiring", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        warnSpy.mockClear();

        vi.mocked(completeLTVData).mockResolvedValue({
            data: {
                certificates: [],
                crls: [],
                ocspResponses: [],
            },
            errors: [],
        });
        vi.mocked(extractLTVData).mockReturnValue({
            certificates: [],
            crls: [],
            ocspResponses: [],
        });
    });

    const mockPdf = new Uint8Array([0x25, 0x50, 0x44, 0x46]);
    const mockTsaConfig = {
        url: "https://tsa.example.com",
        hashAlgorithm: "SHA-256" as const,
    };

    const mockTimestampResult: TimestampResult = {
        pdf: new Uint8Array([...mockPdf, 0x01, 0x02]),
        timestamp: {
            genTime: new Date("2024-01-01T00:00:00Z"),
            policy: "1.2.3.4.5",
            serialNumber: "12345",
            hashAlgorithm: "SHA-256",
            messageDigest: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
            hasCertificate: true,
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
        },
        ltvData: {
            certificates: [new Uint8Array([0x30, 0x01])],
            crls: [new Uint8Array([0x30, 0x02])],
            ocspResponses: [new Uint8Array([0x30, 0x03])],
        },
    };

    it("should forward signatureFieldName through to timestampPdf", async () => {
        vi.mocked(extractTimestamps).mockResolvedValue([]);
        vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);

        const customFieldName = "CustomArchiveTimestamp";
        const options: ArchiveTimestampOptions = {
            pdf: mockPdf,
            tsa: mockTsaConfig,
            signatureFieldName: customFieldName,
        };

        await archiveTimestamp(options);

        expect(vi.mocked(timestampPdf)).toHaveBeenCalledWith(
            expect.objectContaining({
                signatureFieldName: customFieldName,
            })
        );
    });

    it("should propagate errors from timestampPdf", async () => {
        vi.mocked(extractTimestamps).mockResolvedValue([]);

        const mockError = new Error("TSA request failed");
        vi.mocked(timestampPdf).mockRejectedValue(mockError);

        const options: ArchiveTimestampOptions = {
            pdf: mockPdf,
            tsa: mockTsaConfig,
        };

        await expect(archiveTimestamp(options)).rejects.toThrow("TSA request failed");
    });

    it("should propagate errors from extractTimestamps", async () => {
        const mockError = new Error("Failed to extract timestamps");
        vi.mocked(extractTimestamps).mockRejectedValue(mockError);

        const options: ArchiveTimestampOptions = {
            pdf: mockPdf,
            tsa: mockTsaConfig,
        };

        await expect(archiveTimestamp(options)).rejects.toThrow("Failed to extract timestamps");
    });

    it("should propagate errors from verifyTimestamp on existing-signature paths", async () => {
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

        vi.mocked(extractTimestamps).mockResolvedValue([mockExistingTimestamp]);

        const mockError = new Error("Verification failed");
        vi.mocked(verifyTimestamp).mockRejectedValue(mockError);

        const options: ArchiveTimestampOptions = {
            pdf: mockPdf,
            tsa: mockTsaConfig,
        };

        await expect(archiveTimestamp(options)).rejects.toThrow("Verification failed");
    });

    // Audit H1: existing timestamps that fail verifyTimestamp (e.g. legacy
    // tokens without the id-kp-timeStamping EKU under the 0.2.0 G1/G2
    // defaults) previously had their material silently collected. Now:
    // default = warn + continue; strictExistingVerification = throw.
    describe("audit H1: existing-timestamp verify failures", () => {
        const failedVerification = {
            fieldName: "LegacyTimestamp1",
            info: {
                genTime: new Date("2020-01-01T00:00:00Z"),
                policy: "1.2.3.4.1",
                serialNumber: "67890",
                hashAlgorithm: "SHA-256" as const,
                messageDigest:
                    "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",
                hasCertificate: true,
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            },
            token: new Uint8Array([0x30, 0x10]),
            coversWholeDocument: true,
            verified: false,
            verificationError: "Signing certificate is missing id-kp-timeStamping",
            byteRange: [0, 100, 200, 50] as [number, number, number, number],
        };

        it("default: warns but does not throw on failed-verify existing timestamps", async () => {
            vi.mocked(extractTimestamps).mockResolvedValue([failedVerification]);
            vi.mocked(verifyTimestamp).mockResolvedValue(failedVerification);
            vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);

            const result = await archiveTimestamp({ pdf: mockPdf, tsa: mockTsaConfig });

            expect(result).toEqual(mockTimestampResult);
            expect(warnSpy).toHaveBeenCalledWith(
                expect.stringContaining("LegacyTimestamp1")
            );
            expect(warnSpy).toHaveBeenCalledWith(
                expect.stringContaining("Signing certificate is missing id-kp-timeStamping")
            );
        });

        it("strictExistingVerification: true throws on first failed verify", async () => {
            vi.mocked(extractTimestamps).mockResolvedValue([failedVerification]);
            vi.mocked(verifyTimestamp).mockResolvedValue(failedVerification);

            let caught: unknown;
            try {
                await archiveTimestamp({
                    pdf: mockPdf,
                    tsa: mockTsaConfig,
                    strictExistingVerification: true,
                });
            } catch (e) {
                caught = e;
            }

            expect(caught).toBeInstanceOf(TimestampError);
            expect((caught as TimestampError).code).toBe(
                TimestampErrorCode.VERIFICATION_FAILED
            );
            expect((caught as TimestampError).message).toContain("LegacyTimestamp1");
            // timestampPdf should NOT have been reached.
            expect(vi.mocked(timestampPdf)).not.toHaveBeenCalled();
        });

        it("does not warn when existing timestamps verify cleanly", async () => {
            const cleanTimestamp = { ...failedVerification, verified: true, verificationError: undefined };
            vi.mocked(extractTimestamps).mockResolvedValue([cleanTimestamp]);
            vi.mocked(verifyTimestamp).mockResolvedValue(cleanTimestamp);
            vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);

            await archiveTimestamp({ pdf: mockPdf, tsa: mockTsaConfig });

            expect(warnSpy).not.toHaveBeenCalledWith(
                expect.stringContaining("failed verification")
            );
        });

        // Audit F7: existing-timestamp verify previously called
        // verifyTimestamp(ts) with no options, skipping the document-hash
        // check and chain validation. A tampered PDF whose timestamp signed
        // an earlier revision would still report verified=true. The fix
        // always forwards `pdf` and lets callers pass
        // `existingTimestampVerifyOptions` for trustStore / opt-outs.
        it("forwards pdf bytes to verifyTimestamp for document-hash check (F7)", async () => {
            const clean = { ...failedVerification, verified: true, verificationError: undefined };
            vi.mocked(extractTimestamps).mockResolvedValue([clean]);
            vi.mocked(verifyTimestamp).mockResolvedValue(clean);
            vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);

            await archiveTimestamp({ pdf: mockPdf, tsa: mockTsaConfig });

            expect(vi.mocked(verifyTimestamp)).toHaveBeenCalledWith(
                clean,
                expect.objectContaining({ pdf: mockPdf })
            );
        });

        it("forwards existingTimestampVerifyOptions through to verifyTimestamp (F7)", async () => {
            const clean = { ...failedVerification, verified: true, verificationError: undefined };
            vi.mocked(extractTimestamps).mockResolvedValue([clean]);
            vi.mocked(verifyTimestamp).mockResolvedValue(clean);
            vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);

            const trustStore = { verifyChain: vi.fn() } as never;

            await archiveTimestamp({
                pdf: mockPdf,
                tsa: mockTsaConfig,
                existingTimestampVerifyOptions: {
                    trustStore,
                    requireTimestampingEKU: false,
                },
            });

            expect(vi.mocked(verifyTimestamp)).toHaveBeenCalledWith(
                clean,
                expect.objectContaining({
                    pdf: mockPdf,
                    trustStore,
                    requireTimestampingEKU: false,
                })
            );
        });
    });

    // Audit M9: ArchiveTimestampOptions extends TimestampOptions, so the type
    // accepts every TimestampOption field. Previously only 5 were forwarded
    // to the inner timestampPdf call; the rest were silently dropped. Now we
    // forward every applicable field, with explicit carve-outs for fields
    // archive owns (enableLTV) or doesn't make sense for (revocationData).
    describe("audit M9: ArchiveTimestampOptions field forwarding", () => {
        beforeEach(() => {
            vi.mocked(extractTimestamps).mockResolvedValue([]);
            vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);
        });

        it("forwards reason / location / contactInfo to timestampPdf", async () => {
            await archiveTimestamp({
                pdf: mockPdf,
                tsa: mockTsaConfig,
                reason: "Test reason",
                location: "Test location",
                contactInfo: "Test contact",
            });

            expect(vi.mocked(timestampPdf)).toHaveBeenCalledWith(
                expect.objectContaining({
                    reason: "Test reason",
                    location: "Test location",
                    contactInfo: "Test contact",
                })
            );
        });

        it("forwards omitModificationTime / maxSize / optimizePlaceholder", async () => {
            await archiveTimestamp({
                pdf: mockPdf,
                tsa: mockTsaConfig,
                omitModificationTime: true,
                maxSize: 1024 * 1024,
                optimizePlaceholder: true,
            });

            expect(vi.mocked(timestampPdf)).toHaveBeenCalledWith(
                expect.objectContaining({
                    omitModificationTime: true,
                    maxSize: 1024 * 1024,
                    optimizePlaceholder: true,
                })
            );
        });

        it("forwards rejectOnRevocationWarning", async () => {
            await archiveTimestamp({
                pdf: mockPdf,
                tsa: mockTsaConfig,
                rejectOnRevocationWarning: true,
            });

            expect(vi.mocked(timestampPdf)).toHaveBeenCalledWith(
                expect.objectContaining({ rejectOnRevocationWarning: true })
            );
        });

        it("always forces enableLTV: false (archive owns LTV)", async () => {
            await archiveTimestamp({
                pdf: mockPdf,
                tsa: mockTsaConfig,
                enableLTV: true, // caller request -- should be overridden
            });

            expect(vi.mocked(timestampPdf)).toHaveBeenCalledWith(
                expect.objectContaining({ enableLTV: false })
            );
            // And the override is announced so callers know it's not honoured.
            expect(warnSpy).toHaveBeenCalledWith(
                expect.stringContaining("enableLTV: true` is ignored")
            );
        });

        it("does not warn about enableLTV when caller omits it", async () => {
            await archiveTimestamp({ pdf: mockPdf, tsa: mockTsaConfig });

            expect(warnSpy).not.toHaveBeenCalledWith(
                expect.stringContaining("enableLTV")
            );
        });
    });

    // Audit L6: `timestampPdfLTA` is the deprecated pre-0.2.0 name for
    // `archiveTimestamp`. They must refer to the same function. If the
    // alias line in archive.ts (`export const timestampPdfLTA = archiveTimestamp`)
    // is ever removed or mistyped, deep imports that still use the old name
    // would silently fail. This identity check catches that.
    describe("audit L6: timestampPdfLTA deprecated alias", () => {
         
        it("timestampPdfLTA === archiveTimestamp", () => {
            // eslint-disable-next-line @typescript-eslint/no-deprecated
            expect(timestampPdfLTA).toBe(archiveTimestamp);
        });

         
        it("calling timestampPdfLTA exercises the same archive flow", async () => {
            vi.mocked(extractTimestamps).mockResolvedValue([]);
            vi.mocked(timestampPdf).mockResolvedValue(mockTimestampResult);

            // eslint-disable-next-line @typescript-eslint/no-deprecated
            const result = await timestampPdfLTA({ pdf: mockPdf, tsa: mockTsaConfig });

            expect(result).toEqual(mockTimestampResult);
            expect(vi.mocked(timestampPdf)).toHaveBeenCalledTimes(1);
        });
    });
});
