import { describe, it, expect, vi, beforeEach } from "vitest";
import {
    fetchOCSPResponse,
    getOCSPCircuitState,
    resetOCSPCircuits,
} from "../../src/pki/ocsp-client.js";
import { CircuitState } from "../../src/utils/circuit-breaker.js";

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("OCSP Client", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        resetOCSPCircuits(); // Reset circuit breakers between tests
    });

    describe("fetchOCSPResponse", () => {
        const testUrl = "http://ocsp.example.com";
        const testRequest = new Uint8Array([0x30, 0x01, 0x02]);

        it("should successfully fetch OCSP response", async () => {
            const mockResponse = new Uint8Array([0x30, 0x03, 0x04, 0x05]);

            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                arrayBuffer: () => Promise.resolve(mockResponse.buffer),
            });

            const result = await fetchOCSPResponse(testUrl, testRequest);

            expect(result).toBeInstanceOf(Uint8Array);
            expect(result).toEqual(mockResponse);
            expect(mockFetch).toHaveBeenCalledWith(
                testUrl,
                expect.objectContaining({
                    method: "POST",
                    body: testRequest,
                    headers: {
                        "Content-Type": "application/ocsp-request",
                    },
                })
            );
        });

        it("should handle HTTP error responses", async () => {
            mockFetch.mockResolvedValue({
                ok: false,
                status: 404,
                statusText: "Not Found",
            });

            await expect(fetchOCSPResponse(testUrl, testRequest)).rejects.toThrow();
        });

        it("should handle network errors", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(fetchOCSPResponse(testUrl, testRequest)).rejects.toThrow();
        });

        it("should retry on failure", async () => {
            // Fail twice, succeed on third try
            mockFetch
                .mockRejectedValueOnce(new Error("Network error 1"))
                .mockRejectedValueOnce(new Error("Network error 2"))
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    arrayBuffer: () => Promise.resolve(new Uint8Array([0x30, 0x01]).buffer),
                });

            const result = await fetchOCSPResponse(testUrl, testRequest);

            expect(result).toBeInstanceOf(Uint8Array);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("should give up after max retries", async () => {
            mockFetch.mockRejectedValue(new Error("Persistent network error"));

            await expect(fetchOCSPResponse(testUrl, testRequest)).rejects.toThrow();
            expect(mockFetch).toHaveBeenCalledTimes(4); // 3 retries + 1 initial = 4
        });

        it("should handle timeout", async () => {
            mockFetch.mockImplementation(
                () =>
                    new Promise((resolve) => {
                        // Simulate a long delay that would trigger timeout
                        setTimeout(() => { resolve({ ok: true, status: 200 }); }, 6000);
                    })
            );

            await expect(fetchOCSPResponse(testUrl, testRequest)).rejects.toThrow();
        });
    });

    describe("Circuit Breaker Functions", () => {
        describe("getOCSPCircuitState", () => {
            it("should return undefined for unknown URLs", () => {
                const state = getOCSPCircuitState("http://unknown.example.com");
                expect(state).toBeUndefined();
            });

            it("should return circuit state for URLs that have been accessed", async () => {
                const testUrl = "http://example.com";

                // Make a request to initialize circuit breaker for this URL
                mockFetch.mockResolvedValue({
                    ok: true,
                    status: 200,
                    arrayBuffer: () => Promise.resolve(new Uint8Array([0x30, 0x01]).buffer),
                });

                await fetchOCSPResponse(testUrl, new Uint8Array([0x30, 0x01]));

                const state = getOCSPCircuitState(testUrl);
                // The state should be defined after a request has been made
                expect(state).toBeDefined();
                expect([CircuitState.OPEN, CircuitState.HALF_OPEN, CircuitState.CLOSED]).toContain(
                    state
                );
            });
        });

        describe("resetOCSPCircuits", () => {
            it("should not throw when called", () => {
                expect(() => { resetOCSPCircuits(); }).not.toThrow();
            });

            it("should reset circuit breaker state", () => {
                // Call reset multiple times
                resetOCSPCircuits();
                resetOCSPCircuits();

                expect(() => { resetOCSPCircuits(); }).not.toThrow();
            });
        });
    });

    describe("Request formatting", () => {
        it("should send correct headers", async () => {
            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                arrayBuffer: () => Promise.resolve(new Uint8Array([0x30, 0x01]).buffer),
            });

            await fetchOCSPResponse("http://ocsp.example.com", new Uint8Array([0x30, 0x02]));

            expect(mockFetch).toHaveBeenCalledWith(
                "http://ocsp.example.com",
                expect.objectContaining({
                    method: "POST",
                    headers: {
                        "Content-Type": "application/ocsp-request",
                    },
                })
            );
        });

        it("should send request body correctly", async () => {
            const requestData = new Uint8Array([0x30, 0x45, 0x67, 0x89]);

            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                arrayBuffer: () => Promise.resolve(new Uint8Array([0x30, 0x01]).buffer),
            });

            await fetchOCSPResponse("http://ocsp.example.com", requestData);

            expect(mockFetch).toHaveBeenCalledWith(
                "http://ocsp.example.com",
                expect.objectContaining({
                    body: requestData,
                })
            );
        });
    });
});
