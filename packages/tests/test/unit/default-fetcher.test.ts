import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DefaultFetcher } from "../../../core/src/pki/fetchers/default-fetcher.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

const mockFetch = vi.fn();
global.fetch = mockFetch;

// DefaultFetcher uses exponential backoff (`await setTimeout(...)`) between
// retries. Under fake timers those sleeps don't progress until we explicitly
// run pending timers, so retry-aware assertions wrap promises in this helper.
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

function abortRejection(): Error {
    const abortError = new Error("Aborted");
    abortError.name = "AbortError";
    return abortError;
}

interface AttemptInit {
    signal?: AbortSignal;
}

/**
 * Like real fetch: the pending request rejects only when the attempt
 * signal aborts (the owned deadline firing), so "deadline" tests prove
 * deadline state rather than an error name.
 */
function rejectOnAttemptAbort(): void {
    mockFetch.mockImplementation(
        (_url: string, init?: AttemptInit) =>
            new Promise<never>((_resolve, reject) => {
                const signal = init?.signal;
                if (signal?.aborted === true) {
                    reject(abortRejection());
                    return;
                }
                signal?.addEventListener("abort", () => {
                    reject(abortRejection());
                });
            })
    );
}

describe("DefaultFetcher", () => {
    let fetcher: DefaultFetcher;
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
        globalThis.fetch = mockFetch;
        vi.clearAllMocks();
        vi.useFakeTimers();
        fetcher = new DefaultFetcher();
    });

    afterEach(() => {
        vi.useRealTimers();
        globalThis.fetch = originalFetch;
    });

    describe("Constructor", () => {
        it("should use default timeout and maxRetries", () => {
            const defaultFetcher = new DefaultFetcher();
            expect(defaultFetcher).toBeInstanceOf(DefaultFetcher);
        });

        it("should accept custom timeout", () => {
            const customFetcher = new DefaultFetcher({ timeout: 10000 });
            expect(customFetcher).toBeInstanceOf(DefaultFetcher);
        });

        it("should accept custom maxRetries", () => {
            const customFetcher = new DefaultFetcher({ maxRetries: 5 });
            expect(customFetcher).toBeInstanceOf(DefaultFetcher);
        });

        it("should accept both custom options", () => {
            const customFetcher = new DefaultFetcher({ timeout: 15000, maxRetries: 2 });
            expect(customFetcher).toBeInstanceOf(DefaultFetcher);
        });
    });

    describe("fetchOCSP", () => {
        it("should successfully fetch OCSP response on first attempt", async () => {
            const ocspResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(okResponse(ocspResponse));

            const result = await fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);

            expect(result).toEqual(ocspResponse);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(mockFetch).toHaveBeenCalledWith(
                "http://ocsp.example.com",
                expect.objectContaining({
                    method: "POST",
                    headers: { "Content-Type": "application/ocsp-request" },
                    body: ocspRequest,
                })
            );
        });

        it("should retry on 5xx errors and succeed on second attempt", async () => {
            const ocspResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch
                .mockResolvedValueOnce(statusResponse(503, "Service Unavailable"))
                .mockResolvedValueOnce(okResponse(ocspResponse));

            const promise = fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);
            await vi.runAllTimersAsync();
            const result = await promise;

            expect(result).toEqual(ocspResponse);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("should retry on network errors and succeed on third attempt", async () => {
            const ocspResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch
                .mockRejectedValueOnce(new Error("Network error"))
                .mockRejectedValueOnce(new Error("Network error"))
                .mockResolvedValueOnce(okResponse(ocspResponse));

            const promise = fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);
            await vi.runAllTimersAsync();
            const result = await promise;

            expect(result).toEqual(ocspResponse);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("should throw TimestampError with NETWORK_ERROR after all retries exhausted", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
        });

        it("should fail fast on 4xx HTTP errors without retrying", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(statusResponse(400, "Bad Request"));

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);

            expect(mockFetch).toHaveBeenCalledTimes(1); // Terminal: no retries
        });

        it("should treat 429 as terminal without retrying", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(statusResponse(429, "Too Many Requests"));

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);

            expect(mockFetch).toHaveBeenCalledTimes(1); // Terminal: no retries
        });

        it("should throw TimestampError for empty response body", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(new Response(new ArrayBuffer(0), { status: 200 }));

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("should retry 5xx errors and throw after retries exhausted", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(statusResponse(503, "Service Unavailable"));

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(4); // All errors are retried
        });

        it("should report TIMEOUT when attempts die on the deadline", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            rejectOnAttemptAbort();

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
        });

        it("should pass through existing TimestampError", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);
            const originalError = new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Invalid response"
            );

            mockFetch.mockRejectedValue(originalError);

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect(error).toEqual(originalError);
        });

        it("should use custom timeout from constructor", async () => {
            const shortTimeoutFetcher = new DefaultFetcher({ timeout: 100 });
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            rejectOnAttemptAbort();

            const error = await expectRejected(
                shortTimeoutFetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
        });

        it("should use custom maxRetries from constructor", async () => {
            const twoRetriesFetcher = new DefaultFetcher({ maxRetries: 1 });
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(
                twoRetriesFetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(2); // 1 initial + 1 retry
        });
    });

    describe("fetchCRL", () => {
        it("should successfully fetch CRL on first attempt", async () => {
            const crlData = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            mockFetch.mockResolvedValue(okResponse(crlData));

            const result = await fetcher.fetchCRL("http://crl.example.com");

            expect(result).toEqual(crlData);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(mockFetch).toHaveBeenCalledWith(
                "http://crl.example.com",
                expect.objectContaining({
                    method: "GET",
                })
            );
        });

        it("should retry on 5xx errors and succeed on second attempt", async () => {
            const crlData = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            mockFetch
                .mockResolvedValueOnce(statusResponse(500, "Internal Server Error"))
                .mockResolvedValueOnce(okResponse(crlData));

            const promise = fetcher.fetchCRL("http://crl.example.com");
            await vi.runAllTimersAsync();
            const result = await promise;

            expect(result).toEqual(crlData);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("should retry on network errors and succeed on third attempt", async () => {
            const crlData = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            mockFetch
                .mockRejectedValueOnce(new Error("Network error"))
                .mockRejectedValueOnce(new Error("Network error"))
                .mockResolvedValueOnce(okResponse(crlData));

            const promise = fetcher.fetchCRL("http://crl.example.com");
            await vi.runAllTimersAsync();
            const result = await promise;

            expect(result).toEqual(crlData);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("should throw TimestampError with NETWORK_ERROR after all retries exhausted", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
        });

        it("should fail fast on 4xx HTTP errors without retrying", async () => {
            mockFetch.mockResolvedValue(statusResponse(404, "Not Found"));

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);

            expect(mockFetch).toHaveBeenCalledTimes(1); // Terminal: no retries
        });

        it("should treat 408 as terminal without retrying", async () => {
            mockFetch.mockResolvedValue(statusResponse(408, "Request Timeout"));

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);

            expect(mockFetch).toHaveBeenCalledTimes(1); // Terminal: no retries
        });

        it("should throw TimestampError for empty response body", async () => {
            mockFetch.mockResolvedValue(new Response(new ArrayBuffer(0), { status: 200 }));

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });

        it("should retry 5xx errors and throw after retries exhausted", async () => {
            mockFetch.mockResolvedValue(statusResponse(500, "Internal Server Error"));

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(4); // All errors are retried
        });

        it("should report TIMEOUT when attempts die on the deadline", async () => {
            rejectOnAttemptAbort();

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
        });

        it("should include URL in error message after retries exhausted", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com/test.crl"));
            expect(error).toBeInstanceOf(TimestampError);
            const timestampError = error as TimestampError;
            expect(timestampError.message).toContain("http://crl.example.com/test.crl");
        });

        it("should pass through existing TimestampError", async () => {
            const originalError = new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Invalid response"
            );

            mockFetch.mockRejectedValue(originalError);

            const error = await expectRejected(fetcher.fetchCRL("http://crl.example.com"));
            expect(error).toEqual(originalError);
        });

        it("should use custom timeout from constructor", async () => {
            const shortTimeoutFetcher = new DefaultFetcher({ timeout: 100 });

            rejectOnAttemptAbort();

            const error = await expectRejected(
                shortTimeoutFetcher.fetchCRL("http://crl.example.com")
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.TIMEOUT);
        });

        it("should use custom maxRetries from constructor", async () => {
            const twoRetriesFetcher = new DefaultFetcher({ maxRetries: 1 });

            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(
                twoRetriesFetcher.fetchCRL("http://crl.example.com")
            );
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(2); // 1 initial + 1 retry
        });
    });

    describe("Exponential Backoff", () => {
        it("should retry on every failed attempt up to maxRetries", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockRejectedValue(new Error("Network error"));

            const error = await expectRejected(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            );
            expect(error).toBeInstanceOf(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
        });

        it("should not delay on first attempt", async () => {
            const ocspResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(okResponse(ocspResponse));

            // Use real timers temporarily so Date.now() measurements actually
            // reflect wall clock for this assertion.
            vi.useRealTimers();
            const startTime = Date.now();
            await fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);
            const elapsed = Date.now() - startTime;
            vi.useFakeTimers();

            expect(elapsed).toBeLessThan(100);
        });
    });

    describe("Interface Compliance", () => {
        it("should implement RevocationDataFetcher interface", () => {
            const fetcher = new DefaultFetcher();

            expect(typeof fetcher.fetchOCSP).toBe("function");
            expect(typeof fetcher.fetchCRL).toBe("function");
        });

        it("fetchOCSP should accept url string and request Uint8Array", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue(okResponse(new Uint8Array([0x01, 0x02])));

            const result = await fetcher.fetchOCSP("http://test.com", ocspRequest);

            expect(result).toBeInstanceOf(Uint8Array);
        });

        it("fetchCRL should accept url string and return Promise<Uint8Array>", async () => {
            mockFetch.mockResolvedValue(okResponse(new Uint8Array([0x01, 0x02])));

            const result = await fetcher.fetchCRL("http://test.com");

            expect(result).toBeInstanceOf(Uint8Array);
        });
    });
});
