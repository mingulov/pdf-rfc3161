import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { sendTimestampRequest } from "../../../core/src/tsa/client.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

const warnSpy = vi.fn();
vi.mock("../../../core/src/utils/logger.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const mod = await importOriginal<typeof import("../../../core/src/utils/logger.js")>();
    return {
        ...mod,
        getLogger: () => ({
            debug: vi.fn(),
            info: vi.fn(),
            warn: warnSpy,
            error: vi.fn(),
        }),
    };
});

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

        it("warns once per operation for plain-HTTP TSA URLs, with a redacted URL", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch
                .mockResolvedValueOnce(
                    new Response("error", { status: 500, statusText: "Server Error" })
                )
                .mockResolvedValueOnce(tsrResponse(responseBytes));

            const pending = sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                url: "http://user:pass@timestamp.test.com/ts?token=MARKER",
                retry: 1,
                retryDelay: 5,
            });
            await vi.runAllTimersAsync();
            const result = await pending;

            expect(result).toEqual(responseBytes);
            expect(mockFetch).toHaveBeenCalledTimes(2);
            expect(warnSpy).toHaveBeenCalledTimes(1);
            const message = String(warnSpy.mock.calls[0]?.[0]);
            expect(message).toMatch(/plain HTTP/i);
            expect(message).toContain("http://timestamp.test.com/ts");
            expect(message).not.toContain("MARKER");
            expect(message).not.toContain("user:pass@");
            expect(message).not.toMatch(/auth/i);
        });

        it("warns for uppercase-scheme plain-HTTP TSA URLs", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            await sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                url: "HTTP://timestamp.test.com/ts",
            });

            expect(warnSpy).toHaveBeenCalledTimes(1);
            expect(String(warnSpy.mock.calls[0]?.[0])).toContain("http://timestamp.test.com/ts");
        });

        it("does not warn for HTTPS TSA URLs", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            await sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                url: "https://timestamp.test.com/ts",
            });

            expect(warnSpy).not.toHaveBeenCalled();
        });

        it("does not warn for dotted-localhost TSA URLs (local fixture shape)", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            const result = await sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                url: "http://tsa.localhost:34147/tsr",
            });

            expect(result).toEqual(responseBytes);
            expect(warnSpy).not.toHaveBeenCalled();
        });

        it.each([
            "http://localhost/tsr",
            "http://localhost./tsr",
            "http://127.0.0.1/tsr",
            "http://127.1.2.3/tsr",
            "http://[::1]/tsr",
        ])("does not warn for loopback TSA URL %s even though it is rejected", async (url) => {
            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30, 0x05]), { url })
            );

            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(warnSpy).not.toHaveBeenCalled();
        });

        it("T12 P1: redacts long quoted query tails from transport causes", async () => {
            const marker = "T12_FIXTURE_SECRET";
            const fixtureUrl = `https://tsa.example.test/ts?token="${"a".repeat(600)}${marker}"`;
            mockFetch.mockRejectedValue(new TypeError(`request failed for ${fixtureUrl}`));

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: fixtureUrl,
                    retry: 0,
                })
            );

            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            const cause = (error as TimestampError).cause;
            expect(cause).toBeInstanceOf(Error);
            expect((cause as Error).message).toContain("https://tsa.example.test/ts");
            expect((cause as Error).message).not.toContain(marker);
            expect((cause as Error).stack ?? "").not.toContain(marker);
        });

        it("T12 P1: redacts query tails after a quoted value from transport causes", async () => {
            const marker = "T12_FIXTURE_SECRET";
            const fixtureUrl = `https://tsa.example.test/ts?first="short"&token=${marker}`;
            mockFetch.mockRejectedValue(new TypeError(`request failed for ${fixtureUrl}`));

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: fixtureUrl,
                    retry: 0,
                })
            );

            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            const cause = (error as TimestampError).cause;
            expect(cause).toBeInstanceOf(Error);
            expect((cause as Error).message).toContain("https://tsa.example.test/ts");
            expect((cause as Error).message).not.toContain(marker);
            expect((cause as Error).stack ?? "").not.toContain(marker);
        });

        it("T12 N1: redacts spaces inside a second quoted value from transport causes", async () => {
            const marker = "T12_FIXTURE_SECRET";
            const fixtureUrl = `https://fixture-user:fixture-pass@tsa.example.test/ts?first="short"&token="first ${marker}"`;
            mockFetch.mockRejectedValue(new TypeError(`request failed for ${fixtureUrl} failed`));

            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: fixtureUrl,
                    retry: 0,
                })
            );

            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            const cause = (error as TimestampError).cause;
            expect(cause).toBeInstanceOf(Error);
            expect((cause as Error).message).toContain("https://tsa.example.test/ts");
            expect((cause as Error).message).not.toContain(marker);
            expect((cause as Error).message).not.toContain("fixture-user");
            expect((cause as Error).stack ?? "").not.toContain(marker);
        });

        it.each([" \tHTTP://tsa.example.test/ts", "http:tsa.example.test/ts"])(
            "T12 P2: warns for normalized plain-HTTP TSA URL %s",
            async (url) => {
                const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
                mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

                const result = await sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                    url,
                });

                expect(result).toEqual(responseBytes);
                expect(warnSpy).toHaveBeenCalledTimes(1);
                expect(String(warnSpy.mock.calls[0]?.[0])).toMatch(/plain HTTP/i);
            }
        );

        it("T12 P2 variant: stays silent for padded HTTPS TSA URLs", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce(tsrResponse(responseBytes));

            const result = await sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                url: "\t\nhttps://tsa.example.test/ts \t",
            });

            expect(result).toEqual(responseBytes);
            expect(warnSpy).not.toHaveBeenCalled();
        });

        it("T12 P2: warns fail-closed for unparseable TSA URLs", async () => {
            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                    url: "://missing-scheme",
                })
            );

            expect(error).toBeInstanceOf(TimestampError);
            expect(warnSpy).toHaveBeenCalledTimes(1);
            expect(String(warnSpy.mock.calls[0]?.[0])).toMatch(/plain HTTP/i);
        });

        it("still warns for private-network TSA URLs", async () => {
            const error = await expectRejected(
                sendTimestampRequest(new Uint8Array([0x30, 0x05]), {
                    url: "http://192.168.1.10/tsr",
                })
            );

            expect(error).toBeInstanceOf(TimestampError);
            expect(warnSpy).toHaveBeenCalledTimes(1);
            expect(String(warnSpy.mock.calls[0]?.[0])).toMatch(/plain HTTP/i);
        });
    });
});
