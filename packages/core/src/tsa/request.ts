import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { HASH_ALGORITHM_TO_OID } from "../constants.js";
import {
    TimestampError,
    TimestampErrorCode,
    type HashAlgorithm,
    type TimestampRequestOptions,
} from "../types.js";
import { toArrayBuffer } from "../utils.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";

/**
 * A TimeStampReq DER bundled with the random nonce that was embedded inside it.
 * For PDF timestamping, TimestampSession keeps this request context and nonce together
 * until it verifies the TimeStampResp (RFC 3161 Section 2.4.2 replay defence).
 */
export interface TimestampRequest {
    /** The DER-encoded TimeStampReq, ready to send to the TSA */
    request: Uint8Array;
    /** The 8-byte random nonce embedded in the request */
    nonce: Uint8Array;
}

/**
 * Creates an RFC 3161 TimeStampReq for the given data.
 *
 * @param data - The data to be timestamped (will be hashed)
 * @param options - Request-shaping options (hash algorithm, policy, certReq)
 * @returns The DER-encoded TimeStampReq paired with the nonce embedded inside it.
 *
 * @example
 * For PDF timestamping, use TimestampSession so the request context and nonce remain
 * coupled to the PDF ByteRange until the response is validated and embedded:
 *
 * ```typescript
 * import { TimestampSession, sendTimestampRequest } from "pdf-rfc3161";
 *
 * const session = new TimestampSession(pdfBytes, { hashAlgorithm: "SHA-256" });
 * const request = await session.createTimestampRequest();
 * const responseBytes = await sendTimestampRequest(request, { url: tsaUrl });
 * const timestampedPdf = await session.embedTimestampToken(responseBytes);
 * ```
 */
export async function createTimestampRequest(
    data: Uint8Array,
    options: TimestampRequestOptions = {}
): Promise<TimestampRequest> {
    await ensureWebCrypto();
    const hashAlgorithm: HashAlgorithm = options.hashAlgorithm ?? "SHA-256";

    // Hash the data using Web Crypto API (edge-compatible)
    const hashBuffer = await crypto.subtle.digest(hashAlgorithm, toArrayBuffer(data));

    return buildRequest(hashBuffer, hashAlgorithm, options);
}

/**
 * Creates a TimeStampReq for a pre-computed hash. Useful when the caller has
 * already hashed the data, or when running in a context where Web Crypto's
 * `subtle.digest` is unavailable.
 *
 * **Sync-crypto constraint:** unlike {@link createTimestampRequest},
 * this function is synchronous and does NOT `await ensureWebCrypto()`. It still
 * calls `globalThis.crypto.getRandomValues(nonce)` directly, which is always
 * available on Node 22.12.0+ (the library's engines floor), Cloudflare Workers,
 * Deno, and modern browsers.
 *
 * If you are on an environment where `globalThis.crypto` is lazy-initialised
 * (some embedded runtimes), call `await ensureWebCrypto()` from
 * `pdf-rfc3161/internals` once at startup before the first call. This avoids
 * a sync/async signature break for the vast majority of callers who don't
 * need the polyfill.
 *
 * @param hash - The pre-computed hash
 * @param hashAlgorithm - The algorithm used to compute the hash
 * @param options - Request-shaping options (policy, certReq). `hashAlgorithm`
 *   on the options object is ignored in favour of the explicit positional arg.
 * @returns The DER-encoded TimeStampReq paired with its nonce.
 *
 * This low-level helper does not provide a supported standalone PDF
 * embed-and-response-validation flow. Use TimestampSession for PDF timestamping.
 */
export function createTimestampRequestFromHash(
    hash: Uint8Array,
    hashAlgorithm: HashAlgorithm,
    options: Omit<TimestampRequestOptions, "hashAlgorithm"> = {}
): TimestampRequest {
    return buildRequest(toArrayBuffer(hash), hashAlgorithm, options);
}

function buildRequest(
    hashBuffer: ArrayBuffer,
    hashAlgorithm: HashAlgorithm,
    options: TimestampRequestOptions
): TimestampRequest {
    const nonce = new Uint8Array(8);
    crypto.getRandomValues(nonce);
    // RFC 3161 carries the nonce as an ASN.1 INTEGER. Keep its octet form
    // positive, nonzero, and DER-minimal so the request context and echoed
    // TSTInfo value compare without signed-integer ambiguity.
    const firstNonceByte = nonce[0] ?? 0;
    nonce[0] = (firstNonceByte & 0x7f) || 1;

    const algorithmOID = HASH_ALGORITHM_TO_OID[hashAlgorithm];
    if (!algorithmOID) {
        throw new TimestampError(
            TimestampErrorCode.UNSUPPORTED_ALGORITHM,
            `Unsupported hash algorithm: ${hashAlgorithm}`
        );
    }

    const messageImprint = new pkijs.MessageImprint({
        hashAlgorithm: new pkijs.AlgorithmIdentifier({ algorithmId: algorithmOID }),
        hashedMessage: new asn1js.OctetString({ valueHex: hashBuffer }),
    });

    const tsReq = new pkijs.TimeStampReq({
        version: 1,
        messageImprint,
        certReq: options.requestCertificate ?? true,
        nonce: new asn1js.Integer({ valueHex: toArrayBuffer(nonce) }),
    });

    if (options.policy) {
        tsReq.reqPolicy = options.policy;
    }

    const schema = tsReq.toSchema();
    const berBuffer = schema.toBER(false);

    return { request: new Uint8Array(berBuffer), nonce };
}
