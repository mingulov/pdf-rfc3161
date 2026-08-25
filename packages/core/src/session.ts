import { preparePdfForTimestamp, PreparedPDF, PrepareOptions } from "./pdf/prepare.js";
import { extractBytesToHash } from "./pdf/embed.js";
import { createTimestampRequest } from "./tsa/index.js";
import { embedTimestampToken } from "./pdf/embed.js";
import { extractLTVData, addDSS, completeLTVData } from "./pdf/ltv.js";
import {
    validateTimestampToken,
    type TimestampRequestContext,
} from "./tsa/token-validation.js";
import {
    type HashAlgorithm,
    TimestampErrorCode,
    TimestampError,
    type TimestampRequestOptions,
    type TimestampResponseValidationOptions,
} from "./types.js";
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
    /** Exact request binding captured for the mandatory pre-embed validator. */
    private currentRequestContext: TimestampRequestContext | null = null;

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
        this.currentRequestContext = null;
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
        reqOptions: TimestampRequestOptions = {}
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
        const hashAlgorithm = reqOptions.hashAlgorithm ?? this.options.hashAlgorithm ?? "SHA-256";
        const requestCertificate = reqOptions.requestCertificate ?? true;
        const { request, nonce } = await createTimestampRequest(bytesToHash, {
            hashAlgorithm,
            ...(reqOptions.policy !== undefined && { policy: reqOptions.policy }),
            requestCertificate,
        });
        this.currentRequestContext = {
            data: bytesToHash,
            hashAlgorithm,
            nonce,
            ...(reqOptions.policy !== undefined && { policy: reqOptions.policy }),
            requestCertificate,
        };
        return request;
    }

    /**
     * Step 2: Embed the Timestamp Response (TSR) into the prepared PDF.
     * Automatically handles LTV if enabled in constructor.
     * @param responseOrToken The DER-encoded Timestamp Response or raw ContentInfo token
     * @param validationOptions External signer candidates for a certReq=false manual response
     * @returns The final timestamped PDF bytes
     */
    async embedTimestampToken(
        responseOrToken: Uint8Array,
        validationOptions: TimestampResponseValidationOptions = {}
    ): Promise<Uint8Array> {
        this.throwIfDisposed();

        if (!this.prepared) {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Session not ready: call createTimestampRequest first"
            );
        }

        const context = this.currentRequestContext;
        if (!context) {
            throw new TimestampError(
                TimestampErrorCode.STATE_ERROR,
                "Session not ready: call createTimestampRequest first"
            );
        }

        // Validation is intentionally the immediate predecessor of the only PDF
        // write primitive. Raw tokens and complete responses share this one path.
        const validated = await validateTimestampToken(responseOrToken, context, validationOptions);
        const token = validated.token;

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
