import * as asn1js from "asn1js";
import { preparePdfForTimestamp, PreparedPDF, PrepareOptions } from "./pdf/prepare.js";
import { extractBytesToHash } from "./pdf/embed.js";
import { createTimestampRequest } from "./tsa/index.js";
import { embedTimestampToken } from "./pdf/embed.js";
import { extractLTVData, addDSS, completeLTVData } from "./pdf/ltv.js";
import { parseTimestampResponse, validateTimestampResponse } from "./tsa/response.js";
import { HashAlgorithm, TimestampErrorCode, TimestampError, TSAStatus } from "./types.js";
import { toArrayBuffer } from "./utils.js";
import { ensureWebCrypto } from "./utils/web-crypto.js";

/**
 * Heuristically detect whether the supplied bytes are a TimeStampResp
 * envelope (SEQUENCE whose first child is a PKIStatusInfo SEQUENCE) or a
 * raw timestamp token (ContentInfo SEQUENCE whose first child is an
 * ObjectIdentifier for id-signedData = 1.2.840.113549.1.7.2).
 *
 * Returns `true` for "looks like a TSR", `false` for "looks like a raw token
 * or cannot be parsed". Used by `embedTimestampToken` to avoid feeding a
 * raw token into `parseTimestampResponse`, which would mis-identify it (via
 * `tryExtractStatusFromASN1`'s default-GRANTED) and throw
 * `MALFORMED_RESPONSE` -- breaking the legitimate raw-token-fallback path.
 * Audit F1 / S1.
 */
function looksLikeTimeStampResp(bytes: Uint8Array): boolean {
    try {
        const asn1 = asn1js.fromBER(toArrayBuffer(bytes));
        if (asn1.offset === -1) return false;
        const outer = asn1.result;
        if (!(outer instanceof asn1js.Sequence)) return false;
        const firstChild = outer.valueBlock.value[0];
        if (firstChild === undefined) return false;
        // ContentInfo (raw token) starts with an OID; TimeStampResp starts
        // with a PKIStatusInfo (SEQUENCE) whose first child is INTEGER status.
        return !(firstChild instanceof asn1js.ObjectIdentifier);
    } catch {
        return false;
    }
}
import {
    LTV_SIGNATURE_SIZE,
    DEFAULT_SIGNATURE_SIZE,
    SIGNATURE_SIZE_OPTIMIZE_ADD,
    SIGNATURE_SIZE_OPTIMIZE_ALIGN,
} from "./constants.js";

/**
 * Options for configuring a TimestampSession
 */
export interface TimestampSessionOptions {
    /** Hash algorithm to use (default: SHA-256) */
    hashAlgorithm?: HashAlgorithm;
    /** Options for preparing the PDF (signature size, reason, etc.) */
    prepareOptions?: PrepareOptions;
    /** Whether to prepare for Long-Term Validation (default: true) */
    enableLTV?: boolean;
    /**
     * Whether to ignore PDF encryption when loading the document.
     * Forwarded into prepareOptions.ignoreEncryption when set here.
     * @default false
     */
    ignoreEncryption?: boolean;
}

/**
 * TimestampSession vs timestampPdf -- which to use:
 *
 *   - `timestampPdf({ pdf, tsa })` is the one-call API. It does
 *     prepare -> TSQ -> send -> embed -> (optional LTV) for you.
 *     Use this for almost everything. Internally, it constructs a
 *     TimestampSession and drives it.
 *
 *   - `TimestampSession` is the step-by-step API for callers who
 *     must split the TSA round-trip out of the library -- e.g. send
 *     the TSQ from a different process, batch through a custom queue,
 *     or test individual stages. The flow is:
 *         const session = new TimestampSession(pdf, options);
 *         const tsq = await session.createTimestampRequest();
 *         // ...send tsq to TSA somehow, get tsr bytes back...
 *         const out = await session.embedTimestampToken(tsr);
 *
 * Both apply the same security checks (nonce, digest, eContentType,
 * etc.) -- the session is not a "less safe" mode. The flag that
 * differs in behaviour is LTV: `timestampPdf` extracts and returns
 * the LTV bundle to the caller; the session embeds LTV in the PDF
 * but does not return the bundle separately.
 */
/**
 * Simplified API for handling multi-step (async/manual) timestamping workflows.
 * Useful when the timestamp request (TSQ) needs to be sent externally or out-of-band.
 *
 * @example
 * ```typescript
 * const session = new TimestampSession(pdfBytes, { hashAlgorithm: "SHA-256" });
 * const tsq = await session.createTimestampRequest();
 * // ... send `tsq` to your TSA out-of-band; receive `tsr` bytes ...
 * const result = await session.embedTimestampToken(tsr);
 * ```
 */
export class TimestampSession {
    private pdfBytes: Uint8Array;
    private options: TimestampSessionOptions;
    private prepared: PreparedPDF | null = null;
    private disposed = false;
    /**
     * Nonce embedded in the most recent TimeStampReq. Used to verify that the
     * TimeStampResp echoes the same nonce back (RFC 3161 §2.4.2 replay defence).
     */
    private currentNonce: Uint8Array | null = null;
    /**
     * Hash algorithm + bytes-to-hash captured for nonce/digest verification on
     * the way back through embedTimestampToken.
     */
    private currentBytesToHash: Uint8Array | null = null;
    private currentHashAlgorithm: HashAlgorithm | null = null;

    // Store mutable prepare options directly to allow updates
    private currentPrepareOptions: PrepareOptions;

    /**
     * Start a new timestamping session
     * @param pdfBytes The original PDF bytes
     * @param options Session configuration options
     */
    constructor(pdfBytes: Uint8Array, options: TimestampSessionOptions = {}) {
        this.pdfBytes = pdfBytes;
        this.options = options;
        this.currentPrepareOptions = {
            ...(options.prepareOptions ?? {}),
            ignoreEncryption:
                options.ignoreEncryption ?? options.prepareOptions?.ignoreEncryption,
        };
    }

    /**
     * Get the current signature size configuration
     */
    get signatureSize(): number {
        if (
            this.currentPrepareOptions.signatureSize &&
            this.currentPrepareOptions.signatureSize > 0
        ) {
            return this.currentPrepareOptions.signatureSize;
        }
        // Logic interpretation: signatureSize: 0 means default/auto
        // If LTV is enabled, we need a larger default (usually 16KB)
        return this.options.enableLTV ? LTV_SIGNATURE_SIZE : DEFAULT_SIGNATURE_SIZE;
    }

    /**
     * Update the signature size for the next request generation.
     * Useful for optimization loops or retries.
     * @param newSize New size in bytes
     */
    setSignatureSize(newSize: number): void {
        this.currentPrepareOptions.signatureSize = newSize;
        // Invalidate previous preparation
        this.prepared = null;
    }

    /**
     * Releases resources held by this session.
     * Call this method when you're done with the session to free memory.
     *
     * After calling dispose(), the session cannot be used for further operations.
     * Any subsequent calls to createTimestampRequest() or embedTimestampToken()
     * will throw an error.
     */
    dispose(): void {
        this.disposed = true;
        this.pdfBytes = new Uint8Array(0);
        this.prepared = null;
        this.currentPrepareOptions = {};
    }

    private throwIfDisposed(): void {
        if (this.disposed) {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Session has been disposed. Create a new TimestampSession."
            );
        }
    }

    /**
     * Calculate the optimal signature size based on an existing token.
     * Includes a safety margin for LTV data and padding.
     * @param token The DER-encoded timestamp token
     * @returns Recommended signature size
     */
    /**
     * Calculates an optimized signature size for a given token length.
     * Original precise formula with alignment.
     */
    static calculateOptimalSize(token: Uint8Array): number {
        const tokenLength = token.length;
        return (
            Math.ceil((tokenLength + SIGNATURE_SIZE_OPTIMIZE_ADD) / SIGNATURE_SIZE_OPTIMIZE_ALIGN) *
            SIGNATURE_SIZE_OPTIMIZE_ALIGN
        );
    }

    /**
     * Step 1: Prepare the PDF and generate the Timestamp Request (TSQ).
     * Uses the configuration provided in constructor or updated via setters.
     * @param reqOptions Optional overrides for specific request parameters
     * @returns The DER-encoded Timestamp Request (TSQ)
     */
    async createTimestampRequest(
        reqOptions: { hashAlgorithm?: HashAlgorithm } = {}
    ): Promise<Uint8Array> {
        this.throwIfDisposed();
        // (Legacy soft guard retained as defence-in-depth for code paths that
        // mutated internal state before the disposed flag was introduced.)
        if (this.pdfBytes.length === 0 && this.prepared === null) {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Session has been disposed. Create a new TimestampSession."
            );
        }

        // 1. Prepare PDF with placeholder
        // Re-prepare if needed (e.g. if size changed) or if not yet done
        this.prepared ??= await preparePdfForTimestamp(this.pdfBytes, this.currentPrepareOptions);

        // 2. Extract bytes to hash
        const bytesToHash = extractBytesToHash(this.prepared);

        // 3. Create TSQ + capture nonce/hash for response verification
        const hashAlgorithm =
            reqOptions.hashAlgorithm ?? this.options.hashAlgorithm ?? "SHA-256";
        const { request, nonce } = await createTimestampRequest(bytesToHash, { hashAlgorithm });
        this.currentNonce = nonce;
        this.currentBytesToHash = bytesToHash;
        this.currentHashAlgorithm = hashAlgorithm;
        return request;
    }

    /**
     * Step 2: Embed the Timestamp Response (TSR) into the prepared PDF.
     * Automatically handles LTV if enabled in constructor.
     * @param tsrBytes The DER-encoded Timestamp Response (TSR)
     * @returns The final timestamped PDF bytes
     */
    async embedTimestampToken(tsrBytes: Uint8Array): Promise<Uint8Array> {
        this.throwIfDisposed();

        if (!this.prepared) {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Session not ready: call createTimestampRequest first"
            );
        }

        // 1. Determine if we have a raw token or a full TimeStampResp.
        //
        // Audit F1/S1 fix: pre-detect the shape before invoking
        // `parseTimestampResponse`. Without this guard, raw-token input
        // would be fed to `tryExtractStatusFromASN1` which defaults the
        // status to GRANTED and then throws MALFORMED_RESPONSE downstream
        // -- breaking every real-world `timestampPdf` call that extracts
        // the token from the parsed TSR before re-passing it here.
        let token = tsrBytes;
        if (!looksLikeTimeStampResp(tsrBytes)) {
            // Looks like a raw token (ContentInfo + signedData). Use as-is.
            // The downstream embed will surface any further-malformed
            // bytes via its own PDF_ERROR throw.
        } else try {
            const parsed = parseTimestampResponse(tsrBytes);
            // Check if TSA rejected the request
            if (
                parsed.status !== TSAStatus.GRANTED &&
                parsed.status !== TSAStatus.GRANTED_WITH_MODS &&
                parsed.status !== TSAStatus.REVOCATION_WARNING &&
                parsed.status !== TSAStatus.REVOCATION_NOTIFICATION
            ) {
                throw new TimestampError(
                    TimestampErrorCode.TSA_ERROR,
                    `TSA rejected request: ${parsed.statusString ?? `Status code: ${String(parsed.status)}`}`
                );
            }

            // 1a. RFC 3161 §2.4.2: verify nonce, message digest, and hash algorithm
            // against the original request. The session captured these values when
            // createTimestampRequest was called. `parsed.info` is non-optional in
            // granted branches after the status guard above.
            if (
                this.currentBytesToHash !== null &&
                this.currentHashAlgorithm !== null
            ) {
                await ensureWebCrypto();
                const hashBuffer = await crypto.subtle.digest(
                    this.currentHashAlgorithm,
                    toArrayBuffer(this.currentBytesToHash)
                );
                const ok = validateTimestampResponse(
                    parsed.info,
                    new Uint8Array(hashBuffer),
                    this.currentHashAlgorithm,
                    this.currentNonce ?? undefined
                );
                if (!ok) {
                    // Distinct code so the catch below cannot swallow a real
                    // replay/MITM attempt. See audit C1.
                    throw new TimestampError(
                        TimestampErrorCode.VERIFICATION_FAILED,
                        "TSA response did not match the original request (hash, algorithm, or nonce mismatch)"
                    );
                }
            }

            // Granted branches carry `token: Uint8Array` (discriminated union).
            token = parsed.token;
        } catch (error) {
            // The fallback "raw token" path exists because some callers pass a
            // raw timestamp token (ContentInfo/SignedData) instead of a full
            // TimeStampResp envelope. Only INVALID_RESPONSE (outer-parse
            // failure) signals that case; every other TimestampError code
            // indicates a real semantic problem we must NOT swallow:
            //   - TSA_ERROR: TSA rejected the request
            //   - VERIFICATION_FAILED: nonce/digest/algorithm mismatch (audit C1)
            //   - MALFORMED_RESPONSE: response parsed but inner structure broken (audit F2)
            //   - any other code: future-safe re-throw
            if (error instanceof TimestampError) {
                if (error.code === TimestampErrorCode.INVALID_RESPONSE) {
                    // Fall through; treat tsrBytes as a raw token.
                } else {
                    throw error;
                }
            }
            // Non-TimestampError (e.g. asn1js fromBER throws): treat as raw-token input.
        }

        // 2. Embed the token into the signed data field
        let finalPdf = embedTimestampToken(this.prepared, token);

        // 3. Add LTV data if enabled (DSS)
        // Default to true if not specified, unless explicitly set to false
        const shouldEnableLTV = this.options.enableLTV !== false;

        if (shouldEnableLTV) {
            let ltvData = extractLTVData(token);
            // Fetch missing OCSP data to make LTV complete
            ltvData = (await completeLTVData(ltvData)).data;
            finalPdf = await addDSS(finalPdf, ltvData);
        }

        return finalPdf;
    }
}
