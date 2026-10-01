import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import {
    fetchCertificate,
    getCertCircuitState,
    resetCertCircuits,
} from "../../../core/src/pki/cert-client.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { CircuitState } from "../../../core/src/utils/circuit-breaker.js";

const fetchMock = vi.fn();
global.fetch = fetchMock as unknown as typeof fetch;

const warnSpy = vi.fn();
vi.mock("../../../core/src/utils/logger.js", () => {
    return {
        getLogger: () => ({
            debug: vi.fn(),
            info: vi.fn(),
            warn: warnSpy,
            error: vi.fn(),
        }),
    };
});

// fetchCertificate retries up to MAX_RETRIES=2 (3 attempts total) on any
// retryable error with exponential backoff (500ms, 1000ms). Tests that
// exercise the failure path must advance fake timers via vi.runAllTimersAsync().
async function expectRejected(promise: Promise<unknown>): Promise<unknown> {
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

describe("Cert Client", () => {
    beforeEach(() => {
        vi.clearAllMocks();
        resetCertCircuits();
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
    });

    describe("fetchCertificate", () => {
        it("returns bytes on success", async () => {
            const mockCert = new Uint8Array([1, 2, 3]);
            fetchMock.mockResolvedValueOnce(okResponse(mockCert));

            const result = await fetchCertificate("http://example.com/cert.cer");
            expect(result).toEqual(mockCert);
            expect(fetchMock).toHaveBeenCalledWith(
                "http://example.com/cert.cer",
                expect.any(Object)
            );
        });

        it("fails fast with TimestampError on 404 without retrying", async () => {
            fetchMock.mockResolvedValue(statusResponse(404, "Not Found"));

            const error = await expectRejected(fetchCertificate("http://example.com/404"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(fetchMock).toHaveBeenCalledTimes(1);
        });

        it("fails fast with TimestampError on empty response without retrying", async () => {
            fetchMock.mockResolvedValue(new Response(new ArrayBuffer(0), { status: 200 }));

            const error = await expectRejected(fetchCertificate("http://example.com/empty"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect(fetchMock).toHaveBeenCalledTimes(1);
        });

        it("retries on HTTP 500 then surfaces the error", async () => {
            fetchMock.mockResolvedValue(statusResponse(500, "Internal Server Error"));

            const error = await expectRejected(fetchCertificate("http://example.com/500"));
            expect(error).toBeInstanceOf(TimestampError);
            expect(fetchMock).toHaveBeenCalledTimes(3);
        });

        it("retries on aborted requests and reports TIMEOUT", async () => {
            // Like real fetch: the pending request rejects when the attempt
            // signal aborts (the owned deadline firing), so this proves
            // deadline state rather than an error name.
            fetchMock.mockImplementation(
                (_url: string, init?: { signal?: AbortSignal }) =>
                    new Promise<never>((_resolve, reject) => {
                        const signal = init?.signal;
                        if (signal?.aborted === true) {
                            const early = new Error("The operation was aborted");
                            early.name = "AbortError";
                            reject(early);
                            return;
                        }
                        signal?.addEventListener("abort", () => {
                            const err = new Error("The operation was aborted");
                            err.name = "AbortError";
                            reject(err);
                        });
                    })
            );

            const error = await expectRejected(fetchCertificate("http://example.com/timeout"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
            expect(fetchMock).toHaveBeenCalledTimes(3);
        });

        it("uses exponential backoff between attempts", async () => {
            fetchMock.mockResolvedValue(statusResponse(500, "Internal Server Error"));

            const promise = fetchCertificate("http://example.com/backoff").catch((e: unknown) => e);

            // Attempt 0 fires synchronously after the first await.
            await Promise.resolve();
            expect(fetchMock).toHaveBeenCalledTimes(1);

            // Backoff before attempt 1 is INITIAL_BACKOFF_MS * 2^0 = 500ms.
            await vi.advanceTimersByTimeAsync(500);
            expect(fetchMock).toHaveBeenCalledTimes(2);

            // Backoff before attempt 2 is INITIAL_BACKOFF_MS * 2^1 = 1000ms.
            await vi.advanceTimersByTimeAsync(1000);
            expect(fetchMock).toHaveBeenCalledTimes(3);

            await promise;
        });
    });

    describe("Circuit Breaker", () => {
        it("opens after failure threshold and short-circuits subsequent calls", async () => {
            const url = "http://example.com/failure";
            fetchMock.mockResolvedValue(statusResponse(500, "Internal Server Error"));

            // Threshold is 3 failures. Each fetchCertificate call does 3 attempts
            // and records ONE failure (only on final attempt).
            for (let i = 0; i < 3; i++) {
                const error = await expectRejected(fetchCertificate(url));
                expect(error).toBeInstanceOf(TimestampError);
            }

            expect(getCertCircuitState(url)).toBe(CircuitState.OPEN);
            expect(fetchMock).toHaveBeenCalledTimes(9); // 3 calls x 3 attempts

            // Once open, no further fetch is attempted -- short-circuits to
            // TimestampError(CIRCUIT_OPEN).
            const error = await expectRejected(fetchCertificate(url));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.CIRCUIT_OPEN);
            expect(fetchMock).toHaveBeenCalledTimes(9);
        });

        it("resetCertCircuits clears state and allows fetch to succeed again", async () => {
            const url = "http://example.com/failure";
            fetchMock.mockResolvedValue(statusResponse(500, "Internal Server Error"));

            for (let i = 0; i < 3; i++) {
                await expectRejected(fetchCertificate(url));
            }
            expect(getCertCircuitState(url)).toBe(CircuitState.OPEN);

            resetCertCircuits();
            expect(getCertCircuitState(url)).toBeUndefined();

            fetchMock.mockResolvedValueOnce(okResponse(new Uint8Array([1])));
            const res = await fetchCertificate(url);
            expect(res).toEqual(new Uint8Array([1]));
            expect(getCertCircuitState(url)).toBe(CircuitState.CLOSED);
        });
    });
});
