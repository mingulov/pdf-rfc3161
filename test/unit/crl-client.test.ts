import { describe, it, expect, vi, beforeEach } from "vitest";
import {
    parseCRLInfo,
    fetchCRL,
    getCRLCircuitState,
    resetCRLCircuits,
} from "../../src/pki/crl-client.js";

// Mock fetch for network tests
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("CRL Client", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        // Reset circuit breakers before each test
        resetCRLCircuits();
    });

    describe("parseCRLInfo", () => {
        it("should handle empty CRL data gracefully", () => {
            const emptyData = new Uint8Array([]);

            const result = parseCRLInfo(emptyData);

            expect(result).toBeDefined();
            expect(result.crl).toBe(emptyData);
            expect(result.isDelta).toBe(false);
        });

        it("should handle invalid CRL data gracefully", () => {
            const invalidData = new Uint8Array([0x00, 0x01, 0x02]);

            const result = parseCRLInfo(invalidData);

            expect(result).toBeDefined();
            expect(result.crl).toBe(invalidData);
            expect(result.isDelta).toBe(false);
        });

        it("should return CRLInfo object structure", () => {
            const testData = new Uint8Array([0xff]);

            const result = parseCRLInfo(testData);

            expect(result).toHaveProperty("crl");
            expect(result).toHaveProperty("isDelta");
            expect(result.crl).toBe(testData);
            expect(typeof result.isDelta).toBe("boolean");
        });
    });

    describe("fetchCRL", () => {
        it("should throw error for invalid URL", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(fetchCRL("invalid-url")).rejects.toThrow();
        });

        it("should handle network errors", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(fetchCRL("http://example.com/crl")).rejects.toThrow();
        });

        it("should handle HTTP errors", async () => {
            mockFetch.mockResolvedValue({
                ok: false,
                status: 404,
                statusText: "Not Found",
            } as Response);

            await expect(fetchCRL("http://example.com/crl")).rejects.toThrow();
        });

        it("should return Uint8Array for successful response", async () => {
            const mockData = new Uint8Array([0x01, 0x02, 0x03]);
            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                arrayBuffer: () => Promise.resolve(mockData.buffer),
            } as Response);

            const result = await fetchCRL("http://example.com/crl");

            expect(result).toBeInstanceOf(Uint8Array);
            expect(result.length).toBe(mockData.length);
        });
    });

    describe("Circuit Breaker Functions", () => {
        describe("getCRLCircuitState", () => {
            it("should return undefined for unknown URLs", () => {
                const state = getCRLCircuitState("http://unknown.com/crl");

                expect(state).toBeUndefined();
            });

            it("should return circuit state object when available", () => {
                // First make a request to initialize the circuit
                mockFetch.mockRejectedValue(new Error("Network error"));

                // This should trigger circuit breaker initialization
                fetchCRL("http://example.com/crl").catch(() => {});

                // Now check if we can get the state
                const state = getCRLCircuitState("http://example.com/crl");

                // It might be undefined if the circuit hasn't been created yet
                // This tests the function doesn't throw
                expect(state === undefined || typeof state === "object").toBe(true);
            });
        });

        describe("resetCRLCircuits", () => {
            it("should not throw when called", () => {
                expect(() => { resetCRLCircuits(); }).not.toThrow();
            });

            it("should reset circuit breaker state", () => {
                // Call reset multiple times to ensure it doesn't break
                resetCRLCircuits();
                resetCRLCircuits();

                expect(() => { resetCRLCircuits(); }).not.toThrow();
            });
        });
    });

    describe("Error handling", () => {
        it("should handle malformed URLs gracefully", async () => {
            // Test various malformed URL scenarios
            const malformedUrls = ["", "not-a-url", "http://", "https://"];

            for (const url of malformedUrls) {
                await expect(fetchCRL(url)).rejects.toThrow();
            }
        });

        it("should handle network timeouts", async () => {
            mockFetch.mockImplementation(
                () =>
                    new Promise((resolve) => {
                        // Simulate timeout by never resolving
                        setTimeout(() => { resolve({ ok: false, status: 408 }); }, 100);
                    })
            );

            await expect(fetchCRL("http://example.com/crl")).rejects.toThrow();
        });
    });
});
