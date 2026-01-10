import { preparePdfForTimestamp, PreparedPDF, PrepareOptions } from "./pdf/prepare.js";
import { extractBytesToHash } from "./pdf/embed.js";
import { createTimestampRequest } from "./tsa/index.js";
import { embedTimestampToken } from "./pdf/embed.js";
import { extractLTVData, addDSS, completeLTVData } from "./pdf/ltv.js";
import { parseTimestampResponse } from "./tsa/response.js";
import { HashAlgorithm, TimestampErrorCode, TimestampError, TSAStatus } from "./types.js";
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
}

/**
 * Simplified API for handling multi-step (async/manual) timestamping workflows.
 * Useful when the timestamp request (TSQ) needs to be sent externally or out-of-band.
 */
export class TimestampSession {
    private pdfBytes: Uint8Array;
    private options: TimestampSessionOptions;
    private prepared: PreparedPDF | null = null;

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
        this.currentPrepareOptions = { ...(options.prepareOptions ?? {}) };
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
        this.pdfBytes = new Uint8Array(0);
        this.prepared = null;
        this.currentPrepareOptions = {};
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
        // Check if session has been disposed
        if (this.pdfBytes.length === 0 && this.prepared === null) {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Session has been disposed. Create a new TimestampSession."
            );
        }

        // 1. Prepare PDF with placeholder
        // Re-prepare if needed (e.g. if size changed) or if not yet done
        this.prepared ??= await preparePdfForTimestamp(this.pdfBytes, this.currentPrepareOptions);

        // 2. Extract bytes to hash
        const bytesToHash = extractBytesToHash(this.prepared);

        // 3. Create TSQ
        return createTimestampRequest(bytesToHash, {
            hashAlgorithm: reqOptions.hashAlgorithm ?? this.options.hashAlgorithm ?? "SHA-256",
        });
    }

    /**
     * Step 2: Embed the Timestamp Response (TSR) into the prepared PDF.
     * Automatically handles LTV if enabled in constructor.
     * @param tsrBytes The DER-encoded Timestamp Response (TSR)
     * @returns The final timestamped PDF bytes
     */
    async embedTimestampToken(tsrBytes: Uint8Array): Promise<Uint8Array> {
        // Check if session has been disposed
        if (this.pdfBytes.length === 0 && this.prepared === null) {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Session has been disposed. Create a new TimestampSession."
            );
        }

        if (!this.prepared) {
            throw new TimestampError(
                TimestampErrorCode.PDF_ERROR,
                "Session not ready: call createTimestampRequest first"
            );
        }

        // 1. Determine if we have a raw token or a full TimeStampResp
        let token = tsrBytes;
        try {
            const parsed = parseTimestampResponse(tsrBytes);
            // Check if TSA rejected the request
            if (
                parsed.status !== TSAStatus.GRANTED &&
                parsed.status !== TSAStatus.GRANTED_WITH_MODS
            ) {
                throw new TimestampError(
                    TimestampErrorCode.TSA_ERROR,
                    `TSA rejected request: ${parsed.statusString ?? `Status code: ${String(parsed.status)}`}`
                );
            }
            if (parsed.token) {
                token = parsed.token;
            }
        } catch (error) {
            // If parsing fails (e.g., invalid ASN.1 or pkijs schema error),
            // fall back to raw bytes as token for backward compatibility.
            // This handles cases where the input is already a raw token (ContentInfo/SignedData)
            // or when the TSA response can't be parsed by pkijs.
            // Only throw if this was a rejection error (TSA_ERROR), not a parse error.
            // Parse errors mean the input might be a raw token, so use raw bytes as fallback.
            if (
                error instanceof TimestampError &&
                error.code !== TimestampErrorCode.INVALID_RESPONSE
            ) {
                throw error;
            }
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
