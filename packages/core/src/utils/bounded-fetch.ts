import { TimestampError, TimestampErrorCode } from "../types.js";

/**
 * Thrown when a fetched response exceeds the configured size cap.
 * Extends TimestampError so existing catch blocks that look for
 * TimestampError(NETWORK_ERROR) still trip.
 */
export class ResponseTooLargeError extends TimestampError {
    constructor(
        message: string,
        public readonly maxBytes: number,
        public readonly actualBytes: number | undefined
    ) {
        super(TimestampErrorCode.NETWORK_ERROR, message);
        this.name = "ResponseTooLargeError";
    }
}

/**
 * Read a fetch Response body into a Uint8Array, rejecting bodies larger
 * than `maxBytes`. Used to bound TSA/OCSP/CRL/cert response sizes so a
 * malicious or compromised server can't OOM the host (REVIEW-2026-02-09 H5).
 *
 * Strategy:
 *  1. If `Content-Length` parses to a number > maxBytes, reject before
 *     reading the body. This is the cheap path -- attacker advertises a
 *     huge body, we don't allocate.
 *  2. Otherwise read the body to completion and verify the resulting
 *     length is <= maxBytes. This catches:
 *       - missing Content-Length (chunked transfer)
 *       - lying Content-Length (header says small, body is huge)
 *       - non-numeric Content-Length
 *
 *  Streaming with abort-mid-body would tighten step 2 but requires the
 *  ReadableStream API which is uneven across runtimes (Node 18, Workers,
 *  Deno, browsers). The post-read check still prevents the timestamp
 *  pipeline from consuming oversized bodies; the cap on what fetch can
 *  buffer is a separate concern (Node imposes its own).
 */
export async function readResponseBounded(
    response: Response,
    maxBytes: number
): Promise<Uint8Array> {
    // Defensive: some test mocks provide a Response-shape without a real
    // Headers object. Cast to a permissive shape so the runtime guard works
    // without TS warning that headers is non-nullable per the official type.
    const headers = (response as { headers?: Headers | null }).headers ?? null;
    const declared = headers ? headers.get("content-length") : null;
    if (declared) {
        const declaredNum = Number(declared);
        if (Number.isFinite(declaredNum) && declaredNum > maxBytes) {
            throw new ResponseTooLargeError(
                `Response declared Content-Length ${declaredNum.toString()} exceeds cap of ${maxBytes.toString()} bytes`,
                maxBytes,
                declaredNum
            );
        }
    }

    const buf = await response.arrayBuffer();
    if (buf.byteLength > maxBytes) {
        throw new ResponseTooLargeError(
            `Response body of ${buf.byteLength.toString()} bytes exceeds cap of ${maxBytes.toString()} bytes`,
            maxBytes,
            buf.byteLength
        );
    }
    return new Uint8Array(buf);
}
