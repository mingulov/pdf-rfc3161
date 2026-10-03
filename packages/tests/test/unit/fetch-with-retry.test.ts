import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    fetchBytesWithRetry,
    type FetchWithRetryOptions,
} from "../../../core/src/utils/fetch-with-retry.js";
import { ResponseTooLargeError } from "../../../core/src/utils/bounded-fetch.js";
import { monotonicNow } from "../../../core/src/utils/clock.js";
import {
    OperationBudget,
    type OperationBudgetLimits,
} from "../../../core/src/utils/operation-budget.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { CircuitBreakerMap, CircuitState } from "../../../core/src/utils/circuit-breaker.js";

const TSA_URL = "https://tsa.example.com/ts";
const MAX_ABSOLUTE = 250 * 1024 * 1024;
const STILL_PENDING = Symbol("still-pending");

const mockFetch = vi.fn();

interface AttemptInit {
    signal?: AbortSignal;
    redirect?: string;
}

function makeOptions(
    overrides: Partial<FetchWithRetryOptions> & {
        retry?: number;
        retryDelay?: number;
        timeout?: number;
        maxResponseBytes?: number;
    } = {}
): FetchWithRetryOptions {
    const { retry, retryDelay, timeout, maxResponseBytes, ...rest } = overrides;
    return {
        url: TSA_URL,
        method: "POST",
        config: {
            retry: retry ?? 0,
            retryDelay: retryDelay ?? 10,
            timeout: timeout ?? 1000,
            maxResponseBytes: maxResponseBytes ?? 1024,
        },
        ...rest,
    };
}

function okResponse(bytes: Uint8Array): Response {
    return new Response(bytes as BodyInit, { status: 200 });
}

function statusResponse(status: number, statusText: string): Response {
    return new Response("error-body", { status, statusText });
}

function redirectResponse(location: string): Response {
    return new Response(null, {
        status: 307,
        statusText: "Temporary Redirect",
        headers: { Location: location },
    });
}

/** Real Response with the browser opaqueredirect/opaque type shadowed in. */
function opaqueTypeResponse(type: string): Response {
    const response = new Response("hidden", { status: 200 });
    Object.defineProperty(response, "type", { value: type, configurable: true });
    return response;
}

function abortError(): Error {
    const error = new Error("The operation was aborted");
    error.name = "AbortError";
    return error;
}

/** Manually advanced clock for elapsed-deadline tests (no timer mocking). */
function manualClock(startMs: number): { now: number; clock: () => number } {
    const state = { now: startMs, clock: () => state.now };
    return state;
}

/** Mock fetch that hangs until its attempt signal aborts, like real fetch. */
function hangUntilAbort(): void {
    mockFetch.mockImplementation(
        (_url: string, init?: AttemptInit) =>
            new Promise<never>((_resolve, reject) => {
                const signal = init?.signal;
                if (signal?.aborted === true) {
                    reject(abortError());
                    return;
                }
                signal?.addEventListener("abort", () => {
                    reject(abortError());
                });
            })
    );
}

function stalledBodyResponse(): Response {
    const stream = new ReadableStream<Uint8Array>({
        pull() {
            // Headers are delivered; body bytes never arrive.
        },
    });
    return new Response(stream, {
        status: 200,
        headers: { "content-type": "application/timestamp-reply" },
    });
}

function largeBodyResponse(totalChunks: number): Response {
    // Finite (no worker OOM on the old buffering path) but far over any
    // small cap; a fresh stream per call so retries can re-read the body.
    let sent = 0;
    const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
            if (sent < totalChunks) {
                sent++;
                controller.enqueue(new Uint8Array(1024).fill(7));
            } else {
                controller.close();
            }
        },
    });
    return new Response(stream, { status: 200 });
}

interface RaceOutcome {
    settled: true;
    value?: unknown;
    error?: unknown;
}

async function settleWithin(
    promise: Promise<unknown>,
    boundMs: number
): Promise<RaceOutcome | typeof STILL_PENDING> {
    return Promise.race([
        promise.then(
            (value: unknown): RaceOutcome => ({ settled: true, value }),
            (error: unknown): RaceOutcome => ({ settled: true, error })
        ),
        new Promise<typeof STILL_PENDING>((resolve) => {
            setTimeout(() => {
                resolve(STILL_PENDING);
            }, boundMs);
        }),
    ]);
}

function useFakeTimers(): void {
    vi.useFakeTimers();
}

describe("fetchBytesWithRetry", () => {
    beforeEach(() => {
        vi.stubGlobal("fetch", mockFetch);
        vi.clearAllMocks();
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.useRealTimers();
        vi.resetAllMocks();
    });

    describe("redirect policy (R23)", () => {
        it("rejects a 307 with a private Location in one attempt without a second destination", async () => {
            const privateLocation = "http://169.254.169.254/latest/meta-data";
            mockFetch.mockImplementation((url: string) => {
                if (url === privateLocation) {
                    return Promise.resolve(okResponse(new Uint8Array([1])));
                }
                return Promise.resolve(redirectResponse(privateLocation));
            });
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect((error as TimestampError).message).toMatch(/redirect/i);
            expect((error as TimestampError).message).not.toContain("169.254.169.254");
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(mockFetch.mock.calls[0]?.[0]).toBe(TSA_URL);
        });

        it.each([301, 302, 303, 307, 308])("makes one attempt on %i", async (status: number) => {
            mockFetch.mockResolvedValue(
                new Response(null, { status, headers: { Location: "https://other.example/x" } })
            );
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("treats an opaqueredirect response as an unreadable terminal failure", async () => {
            mockFetch.mockResolvedValue(opaqueTypeResponse("opaqueredirect"));
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("treats an opaque response as an unreadable terminal failure", async () => {
            mockFetch.mockResolvedValue(opaqueTypeResponse("opaque"));
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("passes redirect manual so the platform never follows for us", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2])));
            await fetchBytesWithRetry(makeOptions());
            expect(mockFetch.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
        });
    });

    describe("terminal failure classification (R25)", () => {
        it.each([400, 404, 408, 422, 429])("makes one attempt on %i", async (status: number) => {
            mockFetch.mockResolvedValue(statusResponse(status, "Client Error"));
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 2, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            // Local policy rejection is not a remote outage.
            expect(breakers.getState(TSA_URL)).toBeUndefined();
        });

        it("makes one attempt on an empty body", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array(0)));
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("makes one attempt on an over-cap body", async () => {
            mockFetch.mockImplementation(() => Promise.resolve(largeBodyResponse(500)));
            const verdict = await settleWithin(
                fetchBytesWithRetry(makeOptions({ retry: 2, maxResponseBytes: 64 })),
                2000
            );
            expect(verdict).not.toBe(STILL_PENDING);
            if (verdict === STILL_PENDING) {
                return;
            }
            expect(verdict.settled).toBe(true);
            expect(verdict.error).toBeInstanceOf(ResponseTooLargeError);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("makes one attempt on a declared-huge Content-Length", async () => {
            mockFetch.mockResolvedValue(
                new Response(new Uint8Array([1]) as BodyInit, {
                    status: 200,
                    headers: { "content-length": String(100 * 1024 * 1024) },
                })
            );
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 2, maxResponseBytes: 1024 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(ResponseTooLargeError);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("propagates a validator TimestampError without retry or circuit record", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2, 3])));
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const rejection = new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "bad token bytes"
            );
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 2,
                    circuitBreakers: breakers,
                    validateBytes: () => {
                        throw rejection;
                    },
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(rejection);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(breakers.getState(TSA_URL)).toBeUndefined();
        });

        it("wraps a non-TimestampError validator failure once", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2, 3])));
            const cause = new Error("validator blew up");
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 2,
                    validateBytes: () => {
                        throw cause;
                    },
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((error as TimestampError).cause).toBe(cause);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("stops at the first terminal failure after a retryable one", async () => {
            mockFetch
                .mockResolvedValueOnce(statusResponse(500, "Internal Server Error"))
                .mockResolvedValueOnce(statusResponse(404, "Not Found"));
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 3, retryDelay: 5, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(2);
            expect(breakers.getState(TSA_URL)).toBeUndefined();
        });

        it("cancels the rejected body instead of leaving it open", async () => {
            let cancelled = false;
            const stream = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new Uint8Array([1, 2, 3]));
                },
                cancel() {
                    cancelled = true;
                },
            });
            mockFetch.mockResolvedValue(new Response(stream, { status: 500 }));
            await fetchBytesWithRetry(makeOptions({ retry: 0 })).then(
                () => null,
                () => null
            );
            expect(cancelled).toBe(true);
        });

        it("settles a terminal discard when cancel() never settles (I1)", async () => {
            const stream = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new Uint8Array([1, 2, 3]));
                },
                cancel() {
                    return new Promise<never>(() => {
                        // Never settles: settlement must not wait for it.
                    });
                },
            });
            mockFetch.mockResolvedValue(
                new Response(stream, { status: 404, statusText: "Not Found" })
            );
            const verdict = await settleWithin(
                fetchBytesWithRetry(makeOptions({ retry: 2 })),
                2000
            );
            expect(verdict).not.toBe(STILL_PENDING);
            if (verdict === STILL_PENDING) {
                return;
            }
            expect(verdict.settled).toBe(true);
            expect(verdict.error).toBeInstanceOf(TimestampError);
            expect((verdict.error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("preserves the terminal verdict when discard cancel() rejects (I1)", async () => {
            const stream = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new Uint8Array([1, 2, 3]));
                },
                cancel() {
                    return Promise.reject(new Error("cancel blew up"));
                },
            });
            mockFetch.mockResolvedValue(
                new Response(stream, { status: 404, statusText: "Not Found" })
            );
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe("retryable failures", () => {
        it("retries network errors up to retry+1 and records one circuit failure", async () => {
            mockFetch.mockRejectedValue(new Error("socket hang up"));
            const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 2, retryDelay: 5, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect((error as TimestampError).message).toContain("after 3 attempts");
            expect(mockFetch).toHaveBeenCalledTimes(3);
            expect(breakers.getBreaker(TSA_URL).failureCount).toBe(1);
        });

        it("retries 5xx up to retry+1", async () => {
            mockFetch.mockResolvedValue(statusResponse(503, "Service Unavailable"));
            const error = await fetchBytesWithRetry(makeOptions({ retry: 2, retryDelay: 5 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("recovers when a retryable failure is followed by success", async () => {
            mockFetch
                .mockResolvedValueOnce(statusResponse(500, "Internal Server Error"))
                .mockResolvedValueOnce(okResponse(new Uint8Array([9, 9])));
            const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
            const result = await fetchBytesWithRetry(
                makeOptions({ retry: 2, retryDelay: 5, circuitBreakers: breakers })
            );
            expect(result).toEqual(new Uint8Array([9, 9]));
            expect(mockFetch).toHaveBeenCalledTimes(2);
            expect(breakers.getBreaker(TSA_URL).failureCount).toBe(0);
        });

        it("recovers when a per-attempt timeout is followed by success", async () => {
            // First call hangs until the attempt signal aborts (timeout),
            // second succeeds.
            let calls = 0;
            mockFetch.mockImplementation((_url: string, init?: AttemptInit) => {
                calls++;
                if (calls === 1) {
                    return new Promise<never>((_resolve, reject) => {
                        init?.signal?.addEventListener("abort", () => {
                            reject(abortError());
                        });
                    });
                }
                return Promise.resolve(okResponse(new Uint8Array([7])));
            });
            const result = await fetchBytesWithRetry(
                makeOptions({ retry: 1, retryDelay: 5, timeout: 40 })
            );
            expect(result).toEqual(new Uint8Array([7]));
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("backs off exponentially between attempts", async () => {
            useFakeTimers();
            try {
                mockFetch.mockRejectedValue(new Error("down"));
                const outcome = fetchBytesWithRetry(
                    makeOptions({ retry: 2, retryDelay: 100, timeout: 10000 })
                ).then(
                    () => "fulfilled",
                    (e: unknown) => e
                );
                await Promise.resolve();
                expect(mockFetch).toHaveBeenCalledTimes(1);
                await vi.advanceTimersByTimeAsync(100);
                expect(mockFetch).toHaveBeenCalledTimes(2);
                await vi.advanceTimersByTimeAsync(200);
                expect(mockFetch).toHaveBeenCalledTimes(3);
                const error = await outcome;
                expect(error).toBeInstanceOf(TimestampError);
            } finally {
                vi.useRealTimers();
            }
        });

        it("passes a TimestampError fetch rejection through after exhaustion", async () => {
            const original = new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "mock blew up"
            );
            mockFetch.mockRejectedValue(original);
            const error = await fetchBytesWithRetry(makeOptions({ retry: 1, retryDelay: 5 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(original);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("treats an immediate AbortError with a live signal as a network error, not our timeout (M3)", async () => {
            let observedAborted: boolean | undefined;
            mockFetch.mockImplementation((_url: string, init?: AttemptInit) => {
                observedAborted = init?.signal?.aborted;
                return Promise.reject(abortError());
            });
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 0, retryDelay: 5, timeout: 5000 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            // The attempt signal never aborted and the deadline never
            // passed: an error name alone proves no owned deadline.
            expect(observedAborted).toBe(false);
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });

    describe("per-attempt deadline covering headers and body (R24)", () => {
        it("times out hung headers with TIMEOUT after retry+1 attempts", async () => {
            hangUntilAbort();
            const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 1, retryDelay: 5, timeout: 40, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            expect((error as TimestampError).message).toContain("after 2 attempts");
            expect(mockFetch).toHaveBeenCalledTimes(2);
            expect(breakers.getBreaker(TSA_URL).failureCount).toBe(1);
        });

        it("times out a stalled body instead of hanging past the deadline", async () => {
            mockFetch.mockResolvedValue(stalledBodyResponse());
            const verdict = await settleWithin(
                fetchBytesWithRetry(makeOptions({ retry: 0, timeout: 40 })),
                2000
            );
            expect(verdict).not.toBe(STILL_PENDING);
            if (verdict === STILL_PENDING) {
                return;
            }
            expect(verdict.settled).toBe(true);
            expect(verdict.error).toBeInstanceOf(TimestampError);
            expect((verdict.error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("treats a body completing past the deadline as TIMEOUT without timer delivery (I4)", async () => {
            const manual = manualClock(5000);
            let pulls = 0;
            const stream = new ReadableStream<Uint8Array>({
                pull(controller) {
                    pulls++;
                    if (pulls === 2) {
                        // The clock advances without any timer callback
                        // firing, so signal state alone cannot see it.
                        manual.now += 5000;
                    }
                    controller.enqueue(new Uint8Array([7, 7]));
                    if (pulls >= 2) {
                        controller.close();
                    }
                },
            });
            mockFetch.mockResolvedValue(new Response(stream, { status: 200 }));
            const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 0,
                    timeout: 1000,
                    circuitBreakers: breakers,
                    clock: manual.clock,
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            // Genuine exhaustion routes through the normal accounting.
            expect(breakers.getBreaker(TSA_URL).failureCount).toBe(1);
        });

        it("fails safe into TIMEOUT when the wall clock steps backward past an elapsed deadline (I4)", async () => {
            const realStart = Date.now();
            const nowSpy = vi.spyOn(Date, "now").mockReturnValue(realStart);
            try {
                const manual = manualClock(5000);
                let pulls = 0;
                const stream = new ReadableStream<Uint8Array>({
                    pull(controller) {
                        pulls++;
                        if (pulls === 2) {
                            // Elapsed time passes on the monotonic clock
                            // while the wall clock steps a second backward.
                            manual.now += 5000;
                            nowSpy.mockReturnValue(realStart - 1000);
                        }
                        controller.enqueue(new Uint8Array([7, 7]));
                        if (pulls >= 2) {
                            controller.close();
                        }
                    },
                });
                mockFetch.mockResolvedValue(new Response(stream, { status: 200 }));
                const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
                const error = await fetchBytesWithRetry(
                    makeOptions({
                        retry: 0,
                        timeout: 1000,
                        circuitBreakers: breakers,
                        clock: manual.clock,
                    })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
                expect(mockFetch).toHaveBeenCalledTimes(1);
                expect(breakers.getBreaker(TSA_URL).failureCount).toBe(1);
            } finally {
                nowSpy.mockRestore();
            }
        });

        it("treats synchronous validation past the deadline as TIMEOUT without timer delivery (I4)", async () => {
            const manual = manualClock(5000);
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2, 3])));
            const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 0,
                    timeout: 1000,
                    circuitBreakers: breakers,
                    clock: manual.clock,
                    validateBytes: () => {
                        // Simulate CPU-bound validation outliving the
                        // deadline while the event loop runs no timers.
                        manual.now += 5000;
                    },
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(breakers.getBreaker(TSA_URL).failureCount).toBe(1);
        });

        it("fails safe when the wall clock steps backward during over-deadline validation (I4)", async () => {
            const realStart = Date.now();
            const nowSpy = vi.spyOn(Date, "now").mockReturnValue(realStart);
            try {
                const manual = manualClock(5000);
                mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2, 3])));
                const breakers = new CircuitBreakerMap({ failureThreshold: 5 });
                const error = await fetchBytesWithRetry(
                    makeOptions({
                        retry: 0,
                        timeout: 1000,
                        circuitBreakers: breakers,
                        clock: manual.clock,
                        validateBytes: () => {
                            manual.now += 5000;
                            nowSpy.mockReturnValue(realStart - 1000);
                        },
                    })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
                expect(mockFetch).toHaveBeenCalledTimes(1);
                expect(breakers.getBreaker(TSA_URL).failureCount).toBe(1);
            } finally {
                nowSpy.mockRestore();
            }
        });

        it("enforces elapsed deadlines on the shared monotonic clock by default", () => {
            // Wiring proof: the default clock tracks performance.now(), so
            // wall-clock steps cannot move it. Elapsed behavior itself is
            // covered by the manual-clock tests above.
            expect(Math.abs(monotonicNow() - performance.now())).toBeLessThan(1000);
        });
    });

    describe("caller cancellation", () => {
        it("never fetches when the caller signal is already aborted", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            controller.abort(reason);
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 3, signal: controller.signal, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).not.toHaveBeenCalled();
            expect(breakers.getState(TSA_URL)).toBeUndefined();
        });

        it("prefers caller cancellation over a breaker-open report", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            controller.abort(reason);
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            breakers.recordFailure(TSA_URL);
            expect(breakers.getState(TSA_URL)).toBe(CircuitState.OPEN);
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 3, signal: controller.signal, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it("never retries when the caller aborts mid-flight", async () => {
            hangUntilAbort();
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            setTimeout(() => {
                controller.abort(reason);
            }, 20);
            const verdict = await settleWithin(
                fetchBytesWithRetry(
                    makeOptions({
                        retry: 3,
                        retryDelay: 5,
                        timeout: 300,
                        signal: controller.signal,
                    })
                ),
                2000
            );
            expect(verdict).not.toBe(STILL_PENDING);
            if (verdict === STILL_PENDING) {
                return;
            }
            expect(verdict.error).toBe(reason);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("aborts promptly during backoff without a second attempt", async () => {
            mockFetch.mockResolvedValue(statusResponse(500, "Internal Server Error"));
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            setTimeout(() => {
                controller.abort(reason);
            }, 30);
            const started = Date.now();
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 1,
                    retryDelay: 1000,
                    timeout: 5000,
                    signal: controller.signal,
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(Date.now() - started).toBeLessThan(800);
        });

        it("propagates a caller abort during final-attempt 5xx discard without a circuit record", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            mockFetch.mockImplementationOnce(() => {
                const stream = new ReadableStream<Uint8Array>({
                    start(enqueueController) {
                        enqueueController.enqueue(new Uint8Array([1, 2, 3]));
                    },
                    cancel() {
                        // Deterministic: the abort lands inside the
                        // `await discardBody(response)` window on the final
                        // attempt, where there is no backoff sleep to re-check.
                        controller.abort(reason);
                    },
                });
                return Promise.resolve(new Response(stream, { status: 500 }));
            });
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 0,
                    timeout: 5000,
                    signal: controller.signal,
                    circuitBreakers: breakers,
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(breakers.getState(TSA_URL)).toBeUndefined();
        });

        it.each([307, 404])(
            "propagates a caller abort during terminal %i discard (I2)",
            async (status: number) => {
                const controller = new AbortController();
                const reason = new Error("caller stopped");
                const stream = new ReadableStream<Uint8Array>({
                    start(enqueueController) {
                        enqueueController.enqueue(new Uint8Array([1, 2, 3]));
                    },
                    cancel() {
                        // Deterministic: the abort lands inside discard,
                        // where only a post-discard re-check observes it.
                        controller.abort(reason);
                    },
                });
                mockFetch.mockResolvedValue(
                    new Response(stream, {
                        status,
                        statusText: "terminal",
                        headers: status === 307 ? { Location: "https://other.example/x" } : {},
                    })
                );
                const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
                const error = await fetchBytesWithRetry(
                    makeOptions({
                        retry: 2,
                        signal: controller.signal,
                        circuitBreakers: breakers,
                    })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                expect(error).toBe(reason);
                expect(mockFetch).toHaveBeenCalledTimes(1);
                expect(breakers.getState(TSA_URL)).toBeUndefined();
            }
        );

        it("propagates a caller abort during opaque discard (I2)", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            const stream = new ReadableStream<Uint8Array>({
                start(enqueueController) {
                    enqueueController.enqueue(new Uint8Array([1, 2, 3]));
                },
                cancel() {
                    controller.abort(reason);
                },
            });
            const response = new Response(stream, { status: 200 });
            Object.defineProperty(response, "type", {
                value: "opaqueredirect",
                configurable: true,
            });
            mockFetch.mockResolvedValue(response);
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 2, signal: controller.signal })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("propagates a caller abort when the validator aborts and returns (I2)", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2, 3])));
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 2,
                    signal: controller.signal,
                    circuitBreakers: breakers,
                    validateBytes: () => {
                        controller.abort(reason);
                    },
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            // A cancelled call records neither success nor failure.
            expect(breakers.getState(TSA_URL)).toBeUndefined();
        });

        it("propagates a caller abort when the validator aborts and throws (I2)", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1, 2, 3])));
            const error = await fetchBytesWithRetry(
                makeOptions({
                    retry: 2,
                    signal: controller.signal,
                    validateBytes: () => {
                        controller.abort(reason);
                        throw reason;
                    },
                })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("starts no second fetch when the caller aborts between backoff resolution and dispatch (I2)", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            mockFetch
                .mockRejectedValueOnce(new Error("down"))
                .mockResolvedValueOnce(okResponse(new Uint8Array([9])));
            // Scheduler control: wrap only the backoff timer so the abort is
            // already queued when the backoff continuation runs, while the
            // sleep itself resolved. Only an attempt-entry re-check observes
            // it; no wall-clock assertions are involved.
            const BACKOFF_MS = 30;
            const realSetTimeout = globalThis.setTimeout;
            const wrappedSetTimeout = (
                handler: () => void,
                delay?: number
            ): ReturnType<typeof setTimeout> => {
                if (delay === BACKOFF_MS) {
                    return realSetTimeout(() => {
                        queueMicrotask(() => {
                            controller.abort(reason);
                        });
                        handler();
                    }, delay);
                }
                return realSetTimeout(handler, delay);
            };
            globalThis.setTimeout = wrappedSetTimeout as typeof setTimeout;
            try {
                const error = await fetchBytesWithRetry(
                    makeOptions({
                        retry: 1,
                        retryDelay: BACKOFF_MS,
                        timeout: 5000,
                        signal: controller.signal,
                    })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                expect(error).toBe(reason);
                expect(mockFetch).toHaveBeenCalledTimes(1);
            } finally {
                globalThis.setTimeout = realSetTimeout;
            }
        });

        it("succeeds normally with a live caller signal attached", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([5])));
            const controller = new AbortController();
            const result = await fetchBytesWithRetry(makeOptions({ signal: controller.signal }));
            expect(result).toEqual(new Uint8Array([5]));
        });
    });

    describe("circuit breaker taxonomy (R7)", () => {
        it("short-circuits an open breaker with zero fetches and no backoff", async () => {
            useFakeTimers();
            try {
                const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
                breakers.recordFailure(TSA_URL);
                expect(breakers.getState(TSA_URL)).toBe(CircuitState.OPEN);
                // No timer advance: a backoff sleep would leave this pending.
                const error = await fetchBytesWithRetry(
                    makeOptions({ retry: 2, retryDelay: 5000, circuitBreakers: breakers })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.CIRCUIT_OPEN);
                expect(mockFetch).not.toHaveBeenCalled();
            } finally {
                vi.useRealTimers();
            }
        }, 5000);

        it("opens after threshold exhausted calls, then short-circuits", async () => {
            mockFetch.mockResolvedValue(statusResponse(500, "Internal Server Error"));
            const breakers = new CircuitBreakerMap({ failureThreshold: 2 });
            for (let i = 0; i < 2; i++) {
                const error = await fetchBytesWithRetry(
                    makeOptions({ retry: 0, retryDelay: 5, circuitBreakers: breakers })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            }
            expect(breakers.getState(TSA_URL)).toBe(CircuitState.OPEN);
            expect(mockFetch).toHaveBeenCalledTimes(2);
            const error = await fetchBytesWithRetry(
                makeOptions({ retry: 3, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.CIRCUIT_OPEN);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("records success on a 2xx fetch", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1])));
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            const result = await fetchBytesWithRetry(makeOptions({ circuitBreakers: breakers }));
            expect(result).toEqual(new Uint8Array([1]));
            expect(breakers.getState(TSA_URL)).toBe(CircuitState.CLOSED);
        });
    });

    describe("diagnostic URL redaction (M1)", () => {
        const SECRET_URL = "https://user:pass@tsa.example.com/ts?token=secret#frag";
        const SECRET_FRAGMENTS = ["user", "pass", "token", "secret", "frag"];

        it("redacts credentials, query, and fragment from NETWORK_ERROR", async () => {
            mockFetch.mockRejectedValue(new Error("down"));
            const error = await fetchBytesWithRetry(
                makeOptions({ url: SECRET_URL, retry: 0, retryDelay: 5 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            const message = (error as TimestampError).message;
            expect(message).toContain("https://tsa.example.com/ts");
            for (const fragment of SECRET_FRAGMENTS) {
                expect(message).not.toContain(fragment);
            }
        });

        it("redacts credentials, query, and fragment from TIMEOUT", async () => {
            hangUntilAbort();
            const error = await fetchBytesWithRetry(
                makeOptions({ url: SECRET_URL, retry: 0, timeout: 40 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            const message = (error as TimestampError).message;
            expect(message).toContain("https://tsa.example.com/ts");
            for (const fragment of SECRET_FRAGMENTS) {
                expect(message).not.toContain(fragment);
            }
        });

        it("redacts credential-bearing URLs from attached transport causes (M1-cause)", async () => {
            // Deterministic native-construction-failure shape: fetch rejects
            // before any network I/O with the full URL echoed in the message.
            mockFetch.mockRejectedValue(
                new TypeError(
                    "Request cannot be constructed from a URL that includes " +
                        `credentials: ${SECRET_URL}`
                )
            );
            const error = await fetchBytesWithRetry(
                makeOptions({ url: SECRET_URL, retry: 0, retryDelay: 5 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            const cause = (error as TimestampError).cause;
            expect(cause).toBeInstanceOf(Error);
            const causeMessage = (cause as Error).message;
            expect(causeMessage).toContain("https://tsa.example.com/ts");
            for (const fragment of SECRET_FRAGMENTS) {
                expect(causeMessage).not.toContain(fragment);
            }
        });

        it("redacts uppercase-scheme credential-bearing URLs from attached causes", async () => {
            const upperUrl = "HTTPS://user:pass@tsa.example.com/ts?token=secret";
            mockFetch.mockRejectedValue(new TypeError(`Request failed for ${upperUrl}`));
            const error = await fetchBytesWithRetry(
                makeOptions({ url: upperUrl, retry: 0, retryDelay: 5 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            const cause = (error as TimestampError).cause;
            expect(cause).toBeInstanceOf(Error);
            const causeMessage = (cause as Error).message;
            expect(causeMessage).toContain("https://tsa.example.com/ts");
            for (const fragment of SECRET_FRAGMENTS) {
                expect(causeMessage).not.toContain(fragment);
            }
        });

        it("redacts nested causes on attached transport errors", async () => {
            const nested = new Error(`responder boom for ${SECRET_URL}`);
            mockFetch.mockRejectedValue(new Error("outer failure", { cause: nested }));
            const error = await fetchBytesWithRetry(
                makeOptions({ url: SECRET_URL, retry: 0, retryDelay: 5 })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            const cause = (error as TimestampError).cause;
            expect(cause).toBeInstanceOf(Error);
            expect((cause as Error).message).toBe("outer failure");
            const nestedCause = (cause as Error).cause;
            expect(nestedCause).toBeInstanceOf(Error);
            for (const fragment of SECRET_FRAGMENTS) {
                expect((nestedCause as Error).message).not.toContain(fragment);
            }
        });

        it("preserves non-leaking transport causes by identity", async () => {
            const failure = new Error("down");
            mockFetch.mockRejectedValue(failure);
            const error = await fetchBytesWithRetry(makeOptions({ retry: 0, retryDelay: 5 })).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).cause).toBe(failure);
        });

        it("redacts credentials, query, and fragment from CIRCUIT_OPEN", async () => {
            const breakers = new CircuitBreakerMap({ failureThreshold: 1 });
            breakers.recordFailure(SECRET_URL);
            expect(breakers.getState(SECRET_URL)).toBe(CircuitState.OPEN);
            const error = await fetchBytesWithRetry(
                makeOptions({ url: SECRET_URL, retry: 2, circuitBreakers: breakers })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.CIRCUIT_OPEN);
            const message = (error as TimestampError).message;
            expect(message).toContain("https://tsa.example.com/ts");
            for (const fragment of SECRET_FRAGMENTS) {
                expect(message).not.toContain(fragment);
            }
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it("preserves caller-reason identity for credential-bearing URLs", async () => {
            const controller = new AbortController();
            const reason = new Error("caller stopped");
            controller.abort(reason);
            const error = await fetchBytesWithRetry(
                makeOptions({ url: SECRET_URL, retry: 3, signal: controller.signal })
            ).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBe(reason);
            expect(mockFetch).not.toHaveBeenCalled();
        });
    });

    describe("numeric config validation", () => {
        it.each([
            { retry: -1 },
            { retry: 1.5 },
            { retry: Number.NaN },
            { retry: Number.POSITIVE_INFINITY },
            { retryDelay: -1 },
            { retryDelay: Number.NaN },
            { retryDelay: Number.POSITIVE_INFINITY },
            { retryDelay: 2147483648 },
            { timeout: 0 },
            { timeout: -5 },
            { timeout: Number.NaN },
            { timeout: Number.POSITIVE_INFINITY },
            { timeout: 2147483648 },
            { maxResponseBytes: 0 },
            { maxResponseBytes: -1 },
            { maxResponseBytes: 1.5 },
            { maxResponseBytes: Number.NaN },
            { maxResponseBytes: MAX_ABSOLUTE + 1 },
        ])("rejects invalid config %o before fetch", async (patch) => {
            const error = await fetchBytesWithRetry(makeOptions(patch)).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_ARGUMENT);
            expect(mockFetch).not.toHaveBeenCalled();
        });

        it("accepts boundary config values", async () => {
            // Fake timers: the 1 ms timeout must not be able to fire before
            // the resolved mock wins (T02 follow-up stabilization).
            useFakeTimers();
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1])));
            const result = await fetchBytesWithRetry(
                makeOptions({ retry: 0, retryDelay: 0, timeout: 1, maxResponseBytes: MAX_ABSOLUTE })
            );
            expect(result).toEqual(new Uint8Array([1]));
        });

        it("accepts the platform timer ceiling as timeout and retryDelay", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([1])));
            const result = await fetchBytesWithRetry(
                makeOptions({ retry: 0, retryDelay: 2147483647, timeout: 2147483647 })
            );
            expect(result).toEqual(new Uint8Array([1]));
        });

        it("caps exponential backoff at the platform timer ceiling", async () => {
            useFakeTimers();
            try {
                mockFetch.mockRejectedValue(new Error("down"));
                const outcome = fetchBytesWithRetry(
                    makeOptions({ retry: 2, retryDelay: 2 ** 30, timeout: 10000 })
                ).then(
                    () => null,
                    (e: unknown) => e
                );
                await vi.advanceTimersByTimeAsync(2 ** 30);
                expect(mockFetch).toHaveBeenCalledTimes(2);
                // The attempt-1 backoff computes 2^31 and is capped at
                // 2^31 - 1: without the cap the platform misfires such a
                // delay as ~1 ms on real timers.
                await vi.advanceTimersByTimeAsync(2147483647 - 1);
                expect(mockFetch).toHaveBeenCalledTimes(2);
                await vi.advanceTimersByTimeAsync(1);
                expect(mockFetch).toHaveBeenCalledTimes(3);
                const error = await outcome;
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            } finally {
                vi.useRealTimers();
            }
        });
    });

    describe("operation budget (T08)", () => {
        const ownedBudgets: OperationBudget[] = [];
        const makeBudget = (limits: OperationBudgetLimits): OperationBudget => {
            const budget = new OperationBudget(limits);
            ownedBudgets.push(budget);
            return budget;
        };
        const withBudget = (
            options: FetchWithRetryOptions,
            limits: OperationBudgetLimits
        ): FetchWithRetryOptions =>
            ({ ...options, budget: makeBudget(limits) }) as FetchWithRetryOptions;

        afterEach(() => {
            for (const budget of ownedBudgets.splice(0)) {
                budget.dispose();
            }
        });

        it("stops retrying once the attempt budget is spent", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await fetchBytesWithRetry(
                withBudget(makeOptions({ retry: 3, retryDelay: 5 }), { maxAttempts: 1 })
            ).then(
                () => undefined,
                (e: unknown) => e
            );

            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect((error as Error | undefined)?.message ?? "").toMatch(
                /operation budget exhausted/
            );
        });

        it("counts bytes even from validator-rejected evidence and then refuses", async () => {
            const budget = makeBudget({ maxBytes: 150 });
            const withShared = (options: FetchWithRetryOptions): FetchWithRetryOptions =>
                ({ ...options, budget }) as FetchWithRetryOptions;
            // Fresh body per call: a shared Response would read empty after
            // the first consumption.
            mockFetch.mockImplementation(() => okResponse(new Uint8Array(100).fill(3)));

            const first = await fetchBytesWithRetry(
                withShared(
                    makeOptions({
                        maxResponseBytes: 1024,
                        validateBytes: () => {
                            throw new TimestampError(
                                TimestampErrorCode.INVALID_RESPONSE,
                                "rejected evidence"
                            );
                        },
                    })
                )
            ).then(
                (value: Uint8Array) => value,
                (e: unknown) => e
            );
            expect(first).toBeInstanceOf(TimestampError);
            expect((first as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);

            // 100 rejected + 100 tipping over the 150 cap: the tipping
            // bytes are still delivered, the call after is refused.
            const second = await fetchBytesWithRetry(
                withShared(makeOptions({ maxResponseBytes: 1024 }))
            );
            expect(second).toBeInstanceOf(Uint8Array);
            await expect(
                fetchBytesWithRetry(withShared(makeOptions({ maxResponseBytes: 1024 })))
            ).rejects.toThrow(/operation budget exhausted/);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("counts built-in over-cap bytes via actualBytes and then refuses", async () => {
            // P2-2: brief item 1 mandates byte counting on ALL built-in
            // paths, including bodies rejected by the service cap.
            const budget = makeBudget({ maxBytes: 150 });
            const withShared = (options: FetchWithRetryOptions): FetchWithRetryOptions =>
                ({ ...options, budget }) as FetchWithRetryOptions;
            mockFetch.mockImplementation(() => okResponse(new Uint8Array(100).fill(3)));

            // 100 bytes over the 60-byte service cap: rejected, but the
            // actualBytes still consume budget.
            const first = await fetchBytesWithRetry(
                withShared(makeOptions({ maxResponseBytes: 60 }))
            ).then(
                (value: Uint8Array) => value,
                (e: unknown) => e
            );
            expect(first).toBeInstanceOf(ResponseTooLargeError);
            expect((first as ResponseTooLargeError).actualBytes).toBe(100);

            // 100 consumed + 100 tipping over the 150 cap: the tipping
            // bytes are still delivered, the call after is refused.
            const second = await fetchBytesWithRetry(
                withShared(makeOptions({ maxResponseBytes: 1024 }))
            );
            expect(second).toBeInstanceOf(Uint8Array);
            await expect(
                fetchBytesWithRetry(withShared(makeOptions({ maxResponseBytes: 1024 })))
            ).rejects.toThrow(/operation budget exhausted/);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("counts partial body bytes read before a mid-body failure (fix round 4, F1)", async () => {
            // F1: bytes read before a body failure are observable and must
            // consume budget before the failure propagates.
            const budget = makeBudget({ maxBytes: 1024 });
            const withShared = (options: FetchWithRetryOptions): FetchWithRetryOptions =>
                ({ ...options, budget }) as FetchWithRetryOptions;
            mockFetch.mockImplementation(() => {
                const stream = new ReadableStream<Uint8Array>({
                    start(controller) {
                        controller.enqueue(new Uint8Array(4096).fill(0xab));
                    },
                    pull(controller) {
                        controller.error(new Error("body exploded"));
                    },
                });
                return new Response(stream, { status: 200 });
            });

            const error = await fetchBytesWithRetry(
                withShared(makeOptions({ retry: 3, retryDelay: 5, maxResponseBytes: 64 * 1024 }))
            ).then(
                () => undefined,
                (e: unknown) => e
            );

            // The first failed body delivered 4096 bytes against a
            // 1024-byte budget, so the retries are refused, never issued.
            // (Red run: 4 fetches, NETWORK_ERROR, zero bytes counted.)
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect((error as Error | undefined)?.message ?? "").toMatch(
                /operation budget exhausted/
            );
        });

        it("charges zero bytes for an unread declared Content-Length (fix round 4, F4)", async () => {
            // F4: the untrusted declared length is never charged; only
            // actually-read bytes consume budget.
            const budget = makeBudget({ maxBytes: 150 });
            const withShared = (options: FetchWithRetryOptions): FetchWithRetryOptions =>
                ({ ...options, budget }) as FetchWithRetryOptions;
            let calls = 0;
            mockFetch.mockImplementation(() => {
                calls++;
                if (calls === 1) {
                    const empty = new ReadableStream<Uint8Array>({
                        start(controller) {
                            controller.close();
                        },
                    });
                    return new Response(empty, {
                        status: 200,
                        headers: { "content-length": "20971521" },
                    });
                }
                return okResponse(new Uint8Array(100).fill(3));
            });

            const first = await fetchBytesWithRetry(
                withShared(makeOptions({ maxResponseBytes: 60 }))
            ).then(
                (value: Uint8Array) => value,
                (e: unknown) => e
            );
            expect(first).toBeInstanceOf(ResponseTooLargeError);
            expect((first as ResponseTooLargeError).actualBytes).toBe(0);

            // The zero-pull rejection charged zero, so the follow-up
            // fetch proceeds. (Red run: 20971521 charged, refused.)
            const second = await fetchBytesWithRetry(
                withShared(makeOptions({ maxResponseBytes: 1024 }))
            );
            expect(second).toBeInstanceOf(Uint8Array);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("merges distinct caller and budget signals without AbortSignal.any", async () => {
            // P1-1: AbortSignal.any is baseline-2024; older browsers and
            // edge runtimes throw TypeError. The shell must fall back to
            // manual listener chaining when it is missing.
            const realAny = AbortSignal.any;
            delete (AbortSignal as unknown as { any?: unknown }).any;
            try {
                const caller = new AbortController();
                mockFetch.mockImplementation(() => okResponse(new Uint8Array([1, 2, 3])));
                const bytes = await fetchBytesWithRetry(
                    withBudget(makeOptions({ signal: caller.signal }), {})
                );
                expect(bytes).toEqual(new Uint8Array([1, 2, 3]));
            } finally {
                (AbortSignal as unknown as { any: typeof realAny }).any = realAny;
            }
        });

        it("propagates caller aborts through the fallback merge", async () => {
            const realAny = AbortSignal.any;
            delete (AbortSignal as unknown as { any?: unknown }).any;
            try {
                const caller = new AbortController();
                const budget = makeBudget({});
                hangUntilAbort();
                const pending = fetchBytesWithRetry({
                    ...makeOptions({ timeout: 10000 }),
                    signal: caller.signal,
                    budget,
                });
                await new Promise((resolve) => setTimeout(resolve, 10));
                const reason = new Error("caller went away");
                caller.abort(reason);
                await expect(pending).rejects.toBe(reason);
            } finally {
                (AbortSignal as unknown as { any: typeof realAny }).any = realAny;
            }
        });

        it("reuses an identical caller and budget signal without AbortSignal.any", async () => {
            const realAny = AbortSignal.any;
            delete (AbortSignal as unknown as { any?: unknown }).any;
            try {
                const budget = makeBudget({});
                mockFetch.mockImplementation(() => okResponse(new Uint8Array([1, 2, 3])));
                const bytes = await fetchBytesWithRetry({
                    ...makeOptions({}),
                    signal: budget.signal,
                    budget,
                });
                expect(bytes).toEqual(new Uint8Array([1, 2, 3]));
            } finally {
                (AbortSignal as unknown as { any: typeof realAny }).any = realAny;
            }
        });
    });
});
