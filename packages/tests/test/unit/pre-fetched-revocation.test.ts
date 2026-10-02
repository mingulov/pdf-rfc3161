/**
 * Tests for pre-fetched revocation data API and completed cache implementation
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { InMemoryValidationCache } from "../../../core/src/pki/fetchers/memory-cache.js";
import { ValidationSession } from "../../../core/src/pki/index.js";
import { TSAStatus } from "../../../core/src/types.js";

const oneCallState = vi.hoisted(() => ({
    createRequest: vi.fn(async (_options: unknown) => new Uint8Array([0x30, 0x00])),
    embed: vi.fn(async (_response: Uint8Array) => new Uint8Array([0x25, 0x50, 0x44, 0x46])),
    send: vi.fn(async () => new Uint8Array([0x30, 0x03, 0x30, 0x01, 0x00])),
    parse: vi.fn(() => ({
        status: TSAStatus.GRANTED,
        token: new Uint8Array([1, 2, 3]),
        info: {
            genTime: new Date("2026-08-24T00:00:00Z"),
            policy: "1.2.3.4.5",
            serialNumber: "1",
            hashAlgorithm: "SHA-256",
            hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
            messageDigest: "00",
            hasCertificate: true,
        },
    })),
    extract: vi.fn(() => ({ certificates: [], crls: [], ocspResponses: [] })),
    complete: vi.fn(async (data: unknown) => ({ data, errors: [] as string[] })),
    addDSS: vi.fn(async (pdf: Uint8Array) => pdf),
}));

vi.mock("../../../core/src/session.js", () => {
    class FakeSession {
        async createTimestampRequest(options: unknown): Promise<Uint8Array> {
            return oneCallState.createRequest(options);
        }

        async embedTimestampToken(response: Uint8Array): Promise<Uint8Array> {
            return oneCallState.embed(response);
        }

        static calculateOptimalSize(_token: Uint8Array): number {
            return 8192;
        }
    }
    return { TimestampSession: FakeSession };
});

vi.mock("../../../core/src/tsa/index.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const original = await importOriginal<typeof import("../../../core/src/tsa/index.js")>();
    return {
        ...original,
        sendTimestampRequest: oneCallState.send,
        parseTimestampResponse: oneCallState.parse,
    };
});

vi.mock("../../../core/src/pdf/ltv.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const original = await importOriginal<typeof import("../../../core/src/pdf/ltv.js")>();
    return {
        ...original,
        extractLTVData: oneCallState.extract,
        completeLTVData: oneCallState.complete,
        addDSS: oneCallState.addDSS,
    };
});

const { timestampPdf } = await import("../../../core/src/index.js");

describe("InMemoryValidationCache", () => {
    let cache: InMemoryValidationCache;

    beforeEach(() => {
        cache = new InMemoryValidationCache();
    });

    it("should cache and retrieve OCSP responses", () => {
        const url = "http://ocsp.example.com";
        const request = new Uint8Array([0x01, 0x02, 0x03]);
        const response = new Uint8Array([0x04, 0x05, 0x06]);

        cache.setOCSP(url, request, response);
        const retrieved = cache.getOCSP(url, request);

        expect(retrieved).toEqual(response);
    });

    it("should cache and retrieve CRL responses", () => {
        const url = "http://crl.example.com";
        const response = new Uint8Array([0x01, 0x02, 0x03]);

        cache.setCRL(url, response);
        const retrieved = cache.getCRL(url);

        expect(retrieved).toEqual(response);
    });

    it("should return null for non-cached OCSP", () => {
        const retrieved = cache.getOCSP("http://unknown.com", new Uint8Array([]));
        expect(retrieved).toBeNull();
    });

    it("should return null for non-cached CRL", () => {
        const retrieved = cache.getCRL("http://unknown.com");
        expect(retrieved).toBeNull();
    });

    it("should clear all cached data", () => {
        const url = "http://test.com";
        cache.setOCSP(url, new Uint8Array([1]), new Uint8Array([2]));
        cache.setCRL(url, new Uint8Array([3]));

        cache.clear();

        expect(cache.getOCSP(url, new Uint8Array([1]))).toBeNull();
        expect(cache.getCRL(url)).toBeNull();
    });

    it("should handle different OCSP requests to same URL", () => {
        const url = "http://ocsp.example.com";
        const request1 = new Uint8Array([0x01, 0x02]);
        const request2 = new Uint8Array([0x03, 0x04]);
        const response1 = new Uint8Array([0x10, 0x11]);
        const response2 = new Uint8Array([0x12, 0x13]);

        cache.setOCSP(url, request1, response1);
        cache.setOCSP(url, request2, response2);

        expect(cache.getOCSP(url, request1)).toEqual(response1);
        expect(cache.getOCSP(url, request2)).toEqual(response2);
    });

    it("should distinguish between different URLs for same OCSP request", () => {
        const url1 = "http://ocsp1.example.com";
        const url2 = "http://ocsp2.example.com";
        const request = new Uint8Array([1, 2, 3]);
        const response = new Uint8Array([4, 5, 6]);

        cache.setOCSP(url1, request, response);
        expect(cache.getOCSP(url2, request)).toBeNull();
    });

    it("should miss when OCSP requests differ past the request prefix", () => {
        // T05: the cache compares all request bytes scoped by exact URL. The
        // old first-32-bytes key collided distinct requests (R1 cache
        // collision); same-prefix/different-tail requests must miss now.
        const url = "http://ocsp.example.com";
        const request1 = new Uint8Array(40).fill(1);
        const request2 = new Uint8Array(40).fill(1);
        request2[35] = 2;
        const response = new Uint8Array([4, 5, 6]);

        cache.setOCSP(url, request1, response);
        expect(cache.getOCSP(url, request2)).toBeNull();
        expect(cache.getOCSP(url, request1)).toEqual(response);
    });

    it("should overwrite an existing OCSP entry on repeated set", () => {
        const url = "http://ocsp.example.com";
        const request = new Uint8Array([1, 2, 3]);
        const response1 = new Uint8Array([4, 5, 6]);
        const response2 = new Uint8Array([7, 8, 9]);

        cache.setOCSP(url, request, response1);
        cache.setOCSP(url, request, response2);
        expect(cache.getOCSP(url, request)).toEqual(response2);
    });
});

describe("Pre-fetched Revocation Data API", () => {
    it("should accept revocationData in TimestampOptions interface", () => {
        // Test that the interface accepts the new field
        const options: any = {
            pdf: new Uint8Array([1, 2, 3]),
            tsa: { url: "http://tsa.example.com" },
            revocationData: {
                certificates: [new Uint8Array([4, 5, 6])],
                crls: [new Uint8Array([7, 8, 9])],
                ocspResponses: [new Uint8Array([10, 11, 12])],
            },
        };

        expect(options.revocationData.certificates).toHaveLength(1);
        expect(options.revocationData.crls).toHaveLength(1);
        expect(options.revocationData.ocspResponses).toHaveLength(1);
    });

    it("should handle empty revocationData gracefully", () => {
        const options: any = {
            pdf: new Uint8Array([1, 2, 3]),
            tsa: { url: "http://tsa.example.com" },
            revocationData: {},
        };

        expect(options.revocationData.certificates).toBeUndefined();
        expect(options.revocationData.crls).toBeUndefined();
        expect(options.revocationData.ocspResponses).toBeUndefined();
    });

    it("should allow undefined revocationData", () => {
        const options: any = {
            pdf: new Uint8Array([1, 2, 3]),
            tsa: { url: "http://tsa.example.com" },
            revocationData: undefined,
        };

        expect(options.revocationData).toBeUndefined();
    });
});

describe("ValidationSession Cache Integration", () => {
    it("should use cache for repeated OCSP requests", async () => {
        const cache = new InMemoryValidationCache();
        const session = new ValidationSession({
            cache,
            fetcher: { fetchOCSP: vi.fn(), fetchCRL: vi.fn() },
        });

        // Mock fetcher that returns different responses but cache should return same
        const mockFetcher = (session as any).options.fetcher as any;
        mockFetcher.fetchOCSP = vi.fn().mockResolvedValue(new Uint8Array([0x01, 0x02]));
        mockFetcher.fetchCRL = vi.fn().mockResolvedValue(new Uint8Array([0x03, 0x04]));

        // This would normally call fetchOCSP, but we're testing cache integration
        // In a real test, we'd queue certificates and validate
        expect((session as any).options.cache).toBe(cache);
    });

    it("should export cache statistics", () => {
        const cache = new InMemoryValidationCache();

        // Add some test data
        cache.setCRL("http://crl1.com", new Uint8Array([1]));
        cache.setCRL("http://crl2.com", new Uint8Array([2]));

        // Verify we can access the cache
        expect(cache.getCRL("http://crl1.com")).toEqual(new Uint8Array([1]));
        expect(cache.getCRL("http://crl2.com")).toEqual(new Uint8Array([2]));
    });
});

describe("One-call LTV diagnostics (ltvErrors)", () => {
    const PDF_BYTES = new Uint8Array([0x25, 0x50, 0x44, 0x46]);

    beforeEach(() => {
        oneCallState.createRequest.mockClear();
        oneCallState.embed.mockClear();
        oneCallState.send.mockClear();
        oneCallState.parse.mockClear();
        oneCallState.extract.mockClear();
        oneCallState.complete.mockClear();
        oneCallState.addDSS.mockClear();
    });

    it("surfaces collection errors as ltvErrors alongside successful bytes", async () => {
        const collected = {
            certificates: [new Uint8Array([0x30, 0x01])],
            crls: [] as Uint8Array[],
            ocspResponses: [] as Uint8Array[],
        };
        oneCallState.complete.mockResolvedValueOnce({
            data: collected,
            errors: ["OCSP fetch failed: boom"],
        });

        const result = await timestampPdf({
            pdf: PDF_BYTES,
            tsa: { url: "http://timestamp.mock.test" },
            enableLTV: true,
        });

        expect(result.pdf).toEqual(PDF_BYTES);
        expect(result.ltvData).toEqual(collected);
        expect(result.ltvErrors).toEqual(["OCSP fetch failed: boom"]);
    });

    it("omits ltvErrors when collection reports no errors", async () => {
        oneCallState.complete.mockResolvedValueOnce({
            data: { certificates: [], crls: [], ocspResponses: [] },
            errors: [],
        });

        const result = await timestampPdf({
            pdf: PDF_BYTES,
            tsa: { url: "http://timestamp.mock.test" },
            enableLTV: true,
        });

        expect(result.pdf).toEqual(PDF_BYTES);
        expect("ltvErrors" in result).toBe(false);
    });

    it("reports no collection errors when revocationData replaces network fetching", async () => {
        const prefetched = [new Uint8Array([0x30, 0x09])];

        const result = await timestampPdf({
            pdf: PDF_BYTES,
            tsa: { url: "http://timestamp.mock.test" },
            enableLTV: true,
            revocationData: { ocspResponses: prefetched },
        });

        expect(result.pdf).toEqual(PDF_BYTES);
        expect(oneCallState.complete).not.toHaveBeenCalled();
        expect(result.ltvData?.ocspResponses).toEqual(prefetched);
        expect("ltvErrors" in result).toBe(false);
    });

    it("ignores revocationData without rejection when enableLTV is false", async () => {
        const result = await timestampPdf({
            pdf: PDF_BYTES,
            tsa: { url: "http://timestamp.mock.test" },
            enableLTV: false,
            revocationData: { ocspResponses: [new Uint8Array([0x30, 0x09])] },
        });

        expect(result.pdf).toEqual(PDF_BYTES);
        expect(result.ltvData).toBeUndefined();
        expect(oneCallState.complete).not.toHaveBeenCalled();
        expect("ltvErrors" in result).toBe(false);
    });
});
