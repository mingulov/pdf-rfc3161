import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { DefaultFetcher } from "../../../core/src/pki/fetchers/default-fetcher.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

const mockFetch = vi.fn();
global.fetch = mockFetch;

describe("DefaultFetcher", () => {
    let fetcher: DefaultFetcher;
    let originalFetch: typeof global.fetch;

    beforeEach(() => {
        originalFetch = globalThis.fetch;
        globalThis.fetch = mockFetch;
        vi.clearAllMocks();
        fetcher = new DefaultFetcher();
    });

    afterEach(() => {
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

            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => ocspResponse.buffer,
            });

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
                .mockResolvedValueOnce({
                    ok: false,
                    status: 503,
                    statusText: "Service Unavailable",
                    arrayBuffer: async () => new ArrayBuffer(0),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    statusText: "OK",
                    arrayBuffer: async () => ocspResponse.buffer,
                });

            const result = await fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);

            expect(result).toEqual(ocspResponse);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("should retry on network errors and succeed on third attempt", async () => {
            const ocspResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch
                .mockRejectedValueOnce(new Error("Network error"))
                .mockRejectedValueOnce(new Error("Network error"))
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    statusText: "OK",
                    arrayBuffer: async () => ocspResponse.buffer,
                });

            const result = await fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);

            expect(result).toEqual(ocspResponse);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("should throw TimestampError with NETWORK_ERROR after all retries exhausted", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
        });

        it("should retry 4xx HTTP errors and throw after retries exhausted", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue({
                ok: false,
                status: 400,
                statusText: "Bad Request",
                arrayBuffer: async () => new ArrayBuffer(0),
            });

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(4); // All errors are retried
        });

        it("should throw TimestampError for empty response body", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => new ArrayBuffer(0),
            });

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toThrow(
                TimestampError
            );
        });

        it("should retry 5xx errors and throw after retries exhausted", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockResolvedValue({
                ok: false,
                status: 503,
                statusText: "Service Unavailable",
                arrayBuffer: async () => new ArrayBuffer(0),
            });

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(4); // All errors are retried
        });

        it("should handle fetch abort due to timeout", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            const abortError = new Error("Aborted");
            abortError.name = "AbortError";
            mockFetch.mockRejectedValue(abortError);

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toThrow(
                TimestampError
            );
        });

        it("should pass through existing TimestampError", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);
            const originalError = new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Invalid response"
            );

            mockFetch.mockRejectedValue(originalError);

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toThrow(
                TimestampError
            );

            await expect(fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)).rejects.toEqual(
                originalError
            );
        });

        it("should use custom timeout from constructor", async () => {
            const shortTimeoutFetcher = new DefaultFetcher({ timeout: 100 });
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            const abortError = new Error("Aborted");
            abortError.name = "AbortError";
            mockFetch.mockRejectedValue(abortError);

            await expect(
                shortTimeoutFetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            ).rejects.toThrow(TimestampError);
        });

        it("should use custom maxRetries from constructor", async () => {
            const twoRetriesFetcher = new DefaultFetcher({ maxRetries: 1 });
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(
                twoRetriesFetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            ).rejects.toThrow(TimestampError);

            expect(mockFetch).toHaveBeenCalledTimes(2); // 1 initial + 1 retry
        });
    });

    describe("fetchCRL", () => {
        it("should successfully fetch CRL on first attempt", async () => {
            const crlData = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => crlData.buffer,
            });

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
                .mockResolvedValueOnce({
                    ok: false,
                    status: 500,
                    statusText: "Internal Server Error",
                    arrayBuffer: async () => new ArrayBuffer(0),
                })
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    statusText: "OK",
                    arrayBuffer: async () => crlData.buffer,
                });

            const result = await fetcher.fetchCRL("http://crl.example.com");

            expect(result).toEqual(crlData);
            expect(mockFetch).toHaveBeenCalledTimes(2);
        });

        it("should retry on network errors and succeed on third attempt", async () => {
            const crlData = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            mockFetch
                .mockRejectedValueOnce(new Error("Network error"))
                .mockRejectedValueOnce(new Error("Network error"))
                .mockResolvedValueOnce({
                    ok: true,
                    status: 200,
                    statusText: "OK",
                    arrayBuffer: async () => crlData.buffer,
                });

            const result = await fetcher.fetchCRL("http://crl.example.com");

            expect(result).toEqual(crlData);
            expect(mockFetch).toHaveBeenCalledTimes(3);
        });

        it("should throw TimestampError with NETWORK_ERROR after all retries exhausted", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(fetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
        });

        it("should retry 4xx HTTP errors and throw after retries exhausted", async () => {
            mockFetch.mockResolvedValue({
                ok: false,
                status: 404,
                statusText: "Not Found",
                arrayBuffer: async () => new ArrayBuffer(0),
            });

            await expect(fetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(4); // All errors are retried
        });

        it("should throw TimestampError for empty response body", async () => {
            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => new ArrayBuffer(0),
            });

            await expect(fetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );
        });

        it("should retry 5xx errors and throw after retries exhausted", async () => {
            mockFetch.mockResolvedValue({
                ok: false,
                status: 500,
                statusText: "Internal Server Error",
                arrayBuffer: async () => new ArrayBuffer(0),
            });

            await expect(fetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(4); // All errors are retried
        });

        it("should handle fetch abort due to timeout", async () => {
            const abortError = new Error("Aborted");
            abortError.name = "AbortError";
            mockFetch.mockRejectedValue(abortError);

            await expect(fetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );
        });

        it("should include URL in error message after retries exhausted", async () => {
            mockFetch.mockRejectedValue(new Error("Network error"));

            try {
                await fetcher.fetchCRL("http://crl.example.com/test.crl");
                expect(true).toBe(false);
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                const timestampError = error as TimestampError;
                expect(timestampError.message).toContain("http://crl.example.com/test.crl");
            }
        });

        it("should pass through existing TimestampError", async () => {
            const originalError = new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Invalid response"
            );

            mockFetch.mockRejectedValue(originalError);

            await expect(fetcher.fetchCRL("http://crl.example.com")).rejects.toEqual(originalError);
        });

        it("should use custom timeout from constructor", async () => {
            const shortTimeoutFetcher = new DefaultFetcher({ timeout: 100 });

            const abortError = new Error("Aborted");
            abortError.name = "AbortError";
            mockFetch.mockRejectedValue(abortError);

            await expect(shortTimeoutFetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );
        });

        it("should use custom maxRetries from constructor", async () => {
            const twoRetriesFetcher = new DefaultFetcher({ maxRetries: 1 });

            mockFetch.mockRejectedValue(new Error("Network error"));

            await expect(twoRetriesFetcher.fetchCRL("http://crl.example.com")).rejects.toThrow(
                TimestampError
            );

            expect(mockFetch).toHaveBeenCalledTimes(2); // 1 initial + 1 retry
        });
    });

    describe("Exponential Backoff", () => {
        it("should increase delay exponentially between retries", async () => {
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);
            const startTimes: number[] = [];

            mockFetch.mockImplementation(() => {
                startTimes.push(Date.now());
                return Promise.reject(new Error("Network error"));
            });

            await expect(
                fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest)
            ).rejects.toThrow();

            expect(mockFetch).toHaveBeenCalledTimes(4); // 1 initial + 3 retries
        });

        it("should not delay on first attempt", async () => {
            const ocspResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);
            const ocspRequest = new Uint8Array([0x01, 0x02, 0x03]);

            const startTime = Date.now();
            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => ocspResponse.buffer,
            });

            await fetcher.fetchOCSP("http://ocsp.example.com", ocspRequest);
            const elapsed = Date.now() - startTime;

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

            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => new Uint8Array([0x01, 0x02]).buffer,
            });

            const result = await fetcher.fetchOCSP("http://test.com", ocspRequest);

            expect(result).toBeInstanceOf(Uint8Array);
        });

        it("fetchCRL should accept url string and return Promise<Uint8Array>", async () => {
            mockFetch.mockResolvedValue({
                ok: true,
                status: 200,
                statusText: "OK",
                arrayBuffer: async () => new Uint8Array([0x01, 0x02]).buffer,
            });

            const result = await fetcher.fetchCRL("http://test.com");

            expect(result).toBeInstanceOf(Uint8Array);
        });
    });
});
