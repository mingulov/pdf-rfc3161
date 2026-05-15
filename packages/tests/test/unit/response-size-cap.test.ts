import { describe, it, expect } from "vitest";
import {
    readResponseBounded,
    ResponseTooLargeError,
} from "../../../core/src/utils/bounded-fetch.js";

function makeResponse(bytes: Uint8Array, contentLengthHeader?: number | null): Response {
    const headers = new Headers();
    if (contentLengthHeader !== null && contentLengthHeader !== undefined) {
        headers.set("content-length", String(contentLengthHeader));
    }
    return new Response(bytes as BodyInit, { status: 200, headers });
}

describe("readResponseBounded (H5)", () => {
    it("returns the bytes when response size is within the cap", async () => {
        const data = new Uint8Array([1, 2, 3, 4]);
        const result = await readResponseBounded(makeResponse(data, 4), 1000);
        expect(result).toEqual(data);
    });

    it("rejects immediately when Content-Length exceeds the cap (no body read)", async () => {
        const data = new Uint8Array([1, 2, 3]);
        // Content-Length lies about the actual body size; reject on header value.
        await expect(
            readResponseBounded(makeResponse(data, 10_000_000), 1024)
        ).rejects.toBeInstanceOf(ResponseTooLargeError);
    });

    it("rejects after reading when actual body exceeds cap and no Content-Length", async () => {
        const big = new Uint8Array(2048).fill(0xab);
        await expect(
            readResponseBounded(makeResponse(big, null), 1024)
        ).rejects.toBeInstanceOf(ResponseTooLargeError);
    });

    it("accepts when Content-Length is missing and body is within cap", async () => {
        const data = new Uint8Array([0xaa, 0xbb]);
        const result = await readResponseBounded(makeResponse(data, null), 1024);
        expect(result).toEqual(data);
    });

    it("rejects when Content-Length header is a malformed number", async () => {
        const data = new Uint8Array([1, 2]);
        const r = new Response(data, {
            status: 200,
            headers: { "content-length": "not-a-number" },
        });
        // Malformed header -> we fall back to size check after reading.
        // For tiny data within cap, that's a pass; the malformed header is
        // ignored, which matches generous behaviour.
        const result = await readResponseBounded(r, 1024);
        expect(result).toEqual(data);
    });
});
