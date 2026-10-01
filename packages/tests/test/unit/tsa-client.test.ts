import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { sendTimestampRequest } from "../../../core/src/tsa/client.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

async function expectRejected<T>(promise: Promise<T>): Promise<unknown> {
    const captured = promise.catch((e: unknown) => e);
    await vi.runAllTimersAsync();
    return captured;
}

function tsrResponse(bytes: Uint8Array): Response {
    return new Response(bytes as BodyInit, {
        status: 200,
        headers: { "content-type": "application/timestamp-reply" },
    });
}

describe("TSA Client", () => {
    const mockFetch = vi.fn();

    beforeEach(() => {
        vi.stubGlobal("fetch", mockFetch);
        vi.useFakeTimers();
    });

    afterEach(() => {
        vi.useRealTimers();
        vi.unstubAllGlobals();
        vi.resetAllMocks();
    });

    describe("sendTimestampRequest", () => {
        it("should send POST request with correct content type", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            const request = new Uint8Array([0x30, 0x05]);
            await sendTimestampRequest(request, {
                url: "http://timestamp.test.com",
            });

            expect(mockFetch).toHaveBeenCalledTimes(1);
            const call = mockFetch.mock.calls[0];
            if (!call) throw new Error("Fetch not called");
            const [url, options] = call;
            expect(url).toBe("http://timestamp.test.com");
            expect(options.method).toBe("POST");
            expect(options.headers["Content-Type"]).toBe("application/timestamp-query");
        });

        it("should include custom headers", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            await sendTimestampRequest(new Uint8Array([0x30]), {
                url: "http://timestamp.test.com",
                headers: {
                    Authorization: "Bearer [REDACTED]",
                },
            });

            const call = mockFetch.mock.calls[0];
            if (!call) throw new Error("Fetch not called");
            const [, options] = call;
            expect(options.headers.Authorization).toBe("Bearer [REDACTED]");
        });

        it("should throw on HTTP error", async () => {
            mockFetch.mockResolvedValue(
                new Response("error", { status: 500, statusText: "Internal Server Error" })
            );

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: "http://timestamp.test.com",
                })
            );
            expect(error).toBeInstanceOf(TimestampError);
        });

        it("should throw NETWORK_ERROR on fetch failure", async () => {
            mockFetch.mockRejectedValue(new Error("Network unreachable"));

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: "http://timestamp.test.com",
                })
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
        });

        it("should return response bytes on success", async () => {
            const responseBytes = new Uint8Array([0x30, 0x0a, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            const result = await sendTimestampRequest(new Uint8Array([0x30]), {
                url: "http://timestamp.test.com",
            });

            expect(result).toBeInstanceOf(Uint8Array);
            expect(Array.from(result)).toEqual(Array.from(responseBytes));
        });

        it("should reject a TSA redirect in one attempt without following it", async () => {
            mockFetch.mockResolvedValue(
                new Response(null, {
                    status: 307,
                    statusText: "Temporary Redirect",
                    headers: { Location: "http://169.254.169.254/redirect-target" },
                })
            );

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: "http://timestamp.test.com",
                    retry: 3,
                })
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect((error as TimestampError).message).toMatch(/redirect/i);
            expect(mockFetch).toHaveBeenCalledTimes(1);
            expect(mockFetch.mock.calls[0]?.[0]).toBe("http://timestamp.test.com");
            expect(mockFetch.mock.calls[0]?.[1]).toMatchObject({ redirect: "manual" });
        });

        it("should fail fast on 4xx without retrying", async () => {
            mockFetch.mockResolvedValue(
                new Response("bad request", { status: 400, statusText: "Bad Request" })
            );

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: "http://timestamp.test.com",
                    retry: 3,
                })
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(mockFetch).toHaveBeenCalledTimes(1);
        });
    });
});
