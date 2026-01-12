import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { sendTimestampRequest } from "../../../core/src/tsa/client.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

describe("TSA Client", () => {
    const mockFetch = vi.fn();

    beforeEach(() => {
        vi.stubGlobal("fetch", mockFetch);
    });

    afterEach(() => {
        vi.unstubAllGlobals();
        vi.resetAllMocks();
    });

    describe("sendTimestampRequest", () => {
        it("should send POST request with correct content type", async () => {
            const responseBytes = new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce({
                ok: true,
                headers: new Headers({
                    "content-type": "application/timestamp-reply",
                }),
                arrayBuffer: () => Promise.resolve(responseBytes.buffer),
            });

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
            mockFetch.mockResolvedValueOnce({
                ok: true,
                headers: new Headers({
                    "content-type": "application/timestamp-reply",
                }),
                arrayBuffer: () => Promise.resolve(responseBytes.buffer),
            });

            await sendTimestampRequest(new Uint8Array([0x30]), {
                url: "http://timestamp.test.com",
                headers: {
                    Authorization: "Bearer token123",
                },
            });

            const call = mockFetch.mock.calls[0];
            if (!call) throw new Error("Fetch not called");
            const [, options] = call;
            expect(options.headers.Authorization).toBe("Bearer token123");
        });

        it("should throw on HTTP error", async () => {
            mockFetch.mockResolvedValueOnce({
                ok: false,
                status: 500,
                statusText: "Internal Server Error",
            });

            await expect(
                sendTimestampRequest(new Uint8Array([0x30]), {
                    url: "http://timestamp.test.com",
                })
            ).rejects.toThrow(TimestampError);
        });

        it("should throw NETWORK_ERROR on fetch failure", async () => {
            mockFetch.mockRejectedValueOnce(new Error("Network unreachable"));

            try {
                await sendTimestampRequest(new Uint8Array([0x30]), {
                    url: "http://timestamp.test.com",
                });
                expect.fail("Should have thrown");
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.NETWORK_ERROR);
            }
        });

        it("should return response bytes on success", async () => {
            const responseBytes = new Uint8Array([0x30, 0x0a, 0x02, 0x01, 0x00]);
            mockFetch.mockResolvedValueOnce({
                ok: true,
                headers: new Headers({
                    "content-type": "application/timestamp-reply",
                }),
                arrayBuffer: () => Promise.resolve(responseBytes.buffer),
            });

            const result = await sendTimestampRequest(new Uint8Array([0x30]), {
                url: "http://timestamp.test.com",
            });

            expect(result).toBeInstanceOf(Uint8Array);
            expect(Array.from(result)).toEqual(Array.from(responseBytes));
        });
    });
});
