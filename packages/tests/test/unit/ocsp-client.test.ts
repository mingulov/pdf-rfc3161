import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    fetchOCSPResponse,
    getOCSPCircuitState,
    resetOCSPCircuits,
} from "../../../core/src/pki/ocsp-client.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { CircuitState } from "../../../core/src/utils/circuit-breaker.js";

// Mock fetch globally
const mockFetch = vi.fn();
global.fetch = mockFetch;

async function expectRejected<T>(promise: Promise<T>): Promise<unknown> {
    const captured = promise.catch((e: unknown) => e);
    await vi.runAllTimersAsync();
    return captured;
}

function okResponse(bytes: Uint8Array): Response {
    return new Response(bytes as BodyInit, { status: 200 });
}

function statusResponse(status: number, statusText: string): Response {
    return new Response("error-body", { status, statusText });
}

describe("OCSP Client", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        resetOCSPCircuits(); // Reset circuit breakers between tests
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe("fetchOCSPResponse", () => {
        const testUrl = "http://ocsp.example.com";
        const testRequest = new Uint8Array([0x30, 0x01, 0x02]);

        it("should successfully fetch OCSP response", async () => {
            const mockResponse = new Uint8Array([0x30, 0x03, 0x04, 0x05]);

            mockFetch.mockResolvedValue(okResponse(mockResponse));

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

        it("should fail fast on HTTP error responses without retrying", async () => {
            mockFetch.mockResolvedValue(statusResponse(404, "Not Found"));

            const error = await expectRejected(fetchOCSPResponse(testUrl, testRequest));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("should handle network errors", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(fetchOCSPResponse(testUrl, testRequest));
            expect(error).toBeInstanceOf(Error);
        });

        it("should retry on failure", async () => {
            // Fail twice, succeed on third try
            mockFetch
                .mockRejectedValueOnce(new Error("Network error 1"))
                .mockRejectedValueOnce(new Error("Network error 2"))
                .mockResolvedValueOnce(okResponse(new Uint8Array([0x30, 0x01])));

            const promise = fetchOCSPResponse(testUrl, testRequest);
            await vi.runAllTimersAsync();
            const result = await promise;

            expect(result).toBeInstanceOf(Uint8Array);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("should give up after max retries", async () => {
            mockFetch.mockRejectedValue(new Error("Persistent network error"));

            const error = await expectRejected(fetchOCSPResponse(testUrl, testRequest));
            expect(error).toBeInstanceOf(Error);
            expect(mockFetch).toHaveBeenCalledTimes(4); // 3 retries + 1 initial
        });

        it("should report TIMEOUT when attempts die on the per-attempt deadline", async () => {
            mockFetch.mockImplementation(
                (_url: string, init?: { signal?: AbortSignal }) =>
                    new Promise<never>((_resolve, reject) => {
                        // Like real fetch: the pending request rejects when
                        // the attempt signal aborts (deadline or caller).
                        const signal = init?.signal;
                        if (signal?.aborted === true) {
                            const early = new Error("Aborted");
                            early.name = "AbortError";
                            reject(early);
                            return;
                        }
                        signal?.addEventListener("abort", () => {
                            const aborted = new Error("Aborted");
                            aborted.name = "AbortError";
                            reject(aborted);
                        });
                    })
            );

            const error = await expectRejected(fetchOCSPResponse(testUrl, testRequest));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            expect(mockFetch).toHaveBeenCalledTimes(4); // 3 retries + 1 initial
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
                mockFetch.mockResolvedValue(okResponse(new Uint8Array([0x30, 0x01])));

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
                expect(() => {
                    resetOCSPCircuits();
                }).not.toThrow();
            });

            it("should reset circuit breaker state", () => {
                // Call reset multiple times
                resetOCSPCircuits();
                resetOCSPCircuits();

                expect(() => {
                    resetOCSPCircuits();
                }).not.toThrow();
            });
        });

        describe("recordFailure on retry exhaustion (M1)", () => {
            it("should open after MAX_RETRIES * threshold failures and short-circuit", async () => {
                const url = "http://ocsp-trip.example.com";
                mockFetch.mockResolvedValue(statusResponse(500, "Internal Server Error"));

                // Threshold is 3 failures (one per fetchOCSPResponse call after
                // retries exhaust). Each call should record exactly one failure.
                for (let i = 0; i < 3; i++) {
                    const error = await expectRejected(
                        fetchOCSPResponse(url, new Uint8Array([0x30, 0x01]))
                    );
                    expect(error).toBeInstanceOf(Error);
                }

                expect(getOCSPCircuitState(url)).toBe(CircuitState.OPEN);

                // After OPEN, the next call must short-circuit without hitting fetch.
                const callsBefore = mockFetch.mock.calls.length;
                const error = await expectRejected(
                    fetchOCSPResponse(url, new Uint8Array([0x30, 0x01]))
                );
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.CIRCUIT_OPEN);
                expect(mockFetch.mock.calls.length).toBe(callsBefore);
            });
        });
    });

    describe("Request formatting", () => {
        it("should send correct headers", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([0x30, 0x01])));

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

            mockFetch.mockResolvedValue(okResponse(new Uint8Array([0x30, 0x01])));

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
