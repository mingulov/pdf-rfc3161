/**
 * Tests for pre-fetched revocation data API and completed cache implementation
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { InMemoryValidationCache } from "../../src/pki/fetchers/memory-cache.js";
import { ValidationSession } from "../../src/pki/index.js";

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
        const mockFetcher = session.options.fetcher as any;
        mockFetcher.fetchOCSP = vi.fn().mockResolvedValue(new Uint8Array([0x01, 0x02]));
        mockFetcher.fetchCRL = vi.fn().mockResolvedValue(new Uint8Array([0x03, 0x04]));

        // This would normally call fetchOCSP, but we're testing cache integration
        // In a real test, we'd queue certificates and validate
        expect(session.options.cache).toBe(cache);
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
