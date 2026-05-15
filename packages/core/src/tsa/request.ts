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
 * Callers must keep the nonce around to verify the TimeStampResp on the way back
 * (RFC 3161 §2.4.2 replay defence).
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
 * @param config - TSA configuration
 * @returns The DER-encoded TimeStampReq paired with the nonce embedded inside it.
 *
 * @example
 * ```typescript
 * const { request, nonce } = await createTimestampRequest(data, { hashAlgorithm: "SHA-256" });
 * const responseBytes = await sendTimestampRequest(request, { url: tsaUrl });
 * const info = parseTimestampResponse(responseBytes);
 * validateTimestampResponse(info, hash, "SHA-256", nonce); // verify echoed nonce
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
 * **Sync-crypto constraint (audit M10):** unlike {@link createTimestampRequest},
 * this function is synchronous and does NOT `await ensureWebCrypto()`. It still
 * calls `globalThis.crypto.getRandomValues(nonce)` directly, which is always
 * available on Node 18+ (the library's engines floor), Cloudflare Workers,
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
 * @example
 * ```typescript
 * // note: sync, unlike createTimestampRequest
 * const { request, nonce } = createTimestampRequestFromHash(precomputedSha256, "SHA-256");
 * ```
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
