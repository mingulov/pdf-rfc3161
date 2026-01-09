import {
    DEFAULT_TSA_CONFIG,
    MAX_PDF_SIZE,
    DEFAULT_SIGNATURE_SIZE,
    LTV_SIGNATURE_SIZE,
} from "./constants.js";
import {
    createTimestampRequest,
    sendTimestampRequest,
    parseTimestampResponse,
} from "./tsa/index.js";
import {
    preparePdfForTimestamp,
    embedTimestampToken,
    extractBytesToHash,
    extractLTVData,
    addDSS,
} from "./pdf/index.js";
import {
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
    type TimestampOptions,
    type TimestampResult,
    type TSAConfig,
    type HashAlgorithm,
    type TimestampInfo,
} from "./types.js";

// Re-export types and errors for consumers
export {
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
    type TimestampOptions,
    type TimestampResult,
    type TSAConfig,
    type HashAlgorithm,
    type TimestampInfo,
};

// Re-export lower-level APIs for advanced usage
export {
    createTimestampRequest,
    sendTimestampRequest,
    parseTimestampResponse,
} from "./tsa/index.js";

export {
    preparePdfForTimestamp,
    embedTimestampToken,
    extractBytesToHash,
    type PreparedPDF,
    type PrepareOptions,
} from "./pdf/index.js";

// Re-export LTV functions
export { extractLTVData, addDSS, fetchOCSPResponse, type LTVData } from "./pdf/index.js";

// Re-export extraction and verification functions
export { extractTimestamps, verifyTimestamp, type ExtractedTimestamp } from "./pdf/index.js";

/**
 * Options for timestamping with LTV support
 */
export { type TrustStore, SimpleTrustStore } from "./pki/trust-store.js";

export interface TimestampWithLTVOptions extends TimestampOptions {
    /** Enable LTV (Long-Term Validation) by embedding DSS */
    enableLTV?: boolean;
    /** Fetch OCSP responses for certificates (slower but more complete) */
    fetchOCSP?: boolean;
}

/**
 * Result of timestamping with LTV support
 */
export interface TimestampWithLTVResult extends TimestampResult {
    /** LTV data that was embedded (if enableLTV was true) */
    ltvData?: import("./pdf/ltv.js").LTVData;
}

/**
 * Adds an RFC 3161 document timestamp to a PDF.
 *
 * This is the main entry point for the library. It handles the complete
 * timestamping workflow:
 * 1. Prepares the PDF with a signature placeholder
 * 2. Calculates the hash of the document
 * 3. Sends a timestamp request to the TSA
 * 4. Embeds the timestamp token in the PDF
 *
 * @example
 * ```typescript
 * import { timestampPdf } from 'pdf-rfc3161';
 *
 * const result = await timestampPdf({
 *   pdf: pdfBytes,
 *   tsa: {
 *     url: 'http://timestamp.digicert.com',
 *   },
 * });
 *
 * // Save the timestamped PDF
 * fs.writeFileSync('timestamped.pdf', result.pdf);
 *
 * console.log('Timestamp time:', result.timestamp.genTime);
 * ```
 *
 * @param options - Timestamping options
 * @returns Promise resolving to the timestamped PDF and timestamp info
 * @throws {TimestampError} If timestamping fails
 */
export async function timestampPdf(options: TimestampOptions): Promise<TimestampResult> {
    const { pdf, tsa, reason, location, contactInfo, signatureFieldName, maxSize, signatureSize } =
        options;
    const hashAlgorithm = tsa.hashAlgorithm ?? DEFAULT_TSA_CONFIG.hashAlgorithm;
    const maxPdfSize = maxSize ?? MAX_PDF_SIZE;
    const autoExtend = signatureSize === 0;
    // DEFAULT_SIGNATURE_SIZE imported from constants
    const MAX_SIGNATURE_SIZE = 65536; // 64KB max to prevent runaway growth
    const MAX_AUTO_EXTEND_ATTEMPTS = 2; // Maximum retry attempts for auto-extend
    const SIGNATURE_SIZE_MARGIN = 1.2; // 20% extra margin when calculating required size

    if (pdf.length > maxPdfSize) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `PDF exceeds maximum supported size of ${maxPdfSize.toString()} bytes`
        );
    }

    // Determine initial signature size (0 means auto, use default)
    let currentSignatureSize =
        signatureSize && signatureSize > 0 ? signatureSize : DEFAULT_SIGNATURE_SIZE;
    let autoExtendAttempts = 0;

    // Auto-extend loop: try embedding, grow placeholder if needed (max 2 retries)
    for (;;) {
        // Step 1: Prepare the PDF with a signature placeholder
        const prepared = await preparePdfForTimestamp(pdf, {
            reason,
            location,
            contactInfo,
            signatureFieldName,
            signatureSize: currentSignatureSize,
        });

        // Step 2: Extract the bytes to be hashed (covered by ByteRange)
        const bytesToHash = extractBytesToHash(prepared);

        // Step 3: Create and send timestamp request
        const tsRequest = await createTimestampRequest(bytesToHash, {
            ...tsa,
            hashAlgorithm,
        });

        const tsResponseBytes = await sendTimestampRequest(tsRequest, tsa);

        // Step 4: Parse the timestamp response
        const tsResponse = parseTimestampResponse(tsResponseBytes);

        // Check for errors
        if (
            tsResponse.status !== TSAStatus.GRANTED &&
            tsResponse.status !== TSAStatus.GRANTED_WITH_MODS
        ) {
            const statusMessages: Record<number, string> = {
                [TSAStatus.REJECTION]: "Request rejected",
                [TSAStatus.WAITING]: "Request pending (try again later)",
                [TSAStatus.REVOCATION_WARNING]: "Revocation warning",
                [TSAStatus.REVOCATION_NOTIFICATION]: "Certificate revoked",
            };

            throw new TimestampError(
                TimestampErrorCode.TSA_ERROR,
                `TSA error: ${statusMessages[tsResponse.status] ?? `Unknown status ${tsResponse.status.toString()}`}` +
                    (tsResponse.statusString ? ` - ${tsResponse.statusString}` : "")
            );
        }

        if (!tsResponse.token || !tsResponse.info) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "TSA response missing timestamp token"
            );
        }

        // Step 5: Try to embed the timestamp token in the PDF
        try {
            const timestampedPdf = embedTimestampToken(prepared, tsResponse.token);

            return {
                pdf: timestampedPdf,
                timestamp: tsResponse.info,
            };
        } catch (embedError) {
            // Check if it's a size error and auto-extend is enabled
            if (
                autoExtend &&
                embedError instanceof Error &&
                embedError.message.includes("larger than placeholder")
            ) {
                autoExtendAttempts++;

                // Check if we've exceeded max attempts
                if (autoExtendAttempts >= MAX_AUTO_EXTEND_ATTEMPTS) {
                    throw new TimestampError(
                        TimestampErrorCode.PDF_ERROR,
                        `Timestamp token still too large after ${MAX_AUTO_EXTEND_ATTEMPTS.toString()} auto-extend attempts. ` +
                            `Try specifying a larger signatureSize manually.`
                    );
                }

                // Calculate required size with safety margin
                const requiredSize = Math.ceil(tsResponse.token.length * SIGNATURE_SIZE_MARGIN);

                if (requiredSize > MAX_SIGNATURE_SIZE) {
                    throw new TimestampError(
                        TimestampErrorCode.PDF_ERROR,
                        `Timestamp token too large (${tsResponse.token.length.toString()} bytes). Maximum supported is ${(MAX_SIGNATURE_SIZE / 2).toString()} bytes.`
                    );
                }

                // Grow the signature size and retry
                currentSignatureSize = requiredSize;
                continue; // Retry with larger placeholder
            }

            // Re-throw if not auto-extendable or different error
            throw embedError;
        }
    }
}

/**
 * Adds an RFC 3161 document timestamp to a PDF with LTV (Long-Term Validation) support.
 *
 * LTV embeds the certificate chain and revocation data into the PDF so the
 * timestamp can be verified even after the TSA's certificate expires.
 *
 * @example
 * ```typescript
 * import { timestampPdfWithLTV, KNOWN_TSA_URLS } from 'pdf-rfc3161';
 *
 * const result = await timestampPdfWithLTV({
 *   pdf: pdfBytes,
 *   tsa: { url: KNOWN_TSA_URLS.DIGICERT },
 *   enableLTV: true,
 * });
 *
 * console.log('Embedded', result.ltvData?.certificates.length, 'certificates for LTV');
 * ```
 *
 * @param options - Timestamping options with LTV configuration
 * @returns Promise resolving to the timestamped PDF with LTV data
 */
export async function timestampPdfWithLTV(
    options: TimestampWithLTVOptions
): Promise<TimestampWithLTVResult> {
    const {
        pdf,
        tsa,
        reason,
        location,
        contactInfo,
        signatureFieldName,
        maxSize,
        signatureSize,
        enableLTV = true,
    } = options;
    const hashAlgorithm = tsa.hashAlgorithm ?? DEFAULT_TSA_CONFIG.hashAlgorithm;
    const maxPdfSize = maxSize ?? MAX_PDF_SIZE;
    // DEFAULT_SIGNATURE_SIZE imported from constants

    // For LTV, auto-extend (signatureSize = 0) is not fully supported because:
    // 1. We need the exact token for DSS embedding
    // 2. Retrying would get a different token (different serial, time)
    // 3. The LTV data must correspond to the embedded token
    // If signatureSize is 0, we use a generous default (16KB) to reduce chance of overflow
    let effectiveSignatureSize = DEFAULT_SIGNATURE_SIZE;
    if (signatureSize === 0) {
        effectiveSignatureSize = LTV_SIGNATURE_SIZE;
    } else if (signatureSize && signatureSize > 0) {
        effectiveSignatureSize = signatureSize;
    }

    if (pdf.length > maxPdfSize) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `PDF exceeds maximum supported size of ${maxPdfSize.toString()} bytes`
        );
    }

    // Step 1: Prepare the PDF with a signature placeholder
    const prepared = await preparePdfForTimestamp(pdf, {
        reason,
        location,
        contactInfo,
        signatureFieldName,
        signatureSize: effectiveSignatureSize,
    });

    // Step 2: Extract the bytes to be hashed (covered by ByteRange)
    const bytesToHash = extractBytesToHash(prepared);

    // Step 3: Create and send timestamp request
    const tsRequest = await createTimestampRequest(bytesToHash, {
        ...tsa,
        hashAlgorithm,
    });

    const tsResponseBytes = await sendTimestampRequest(tsRequest, tsa);

    // Step 4: Parse the timestamp response
    const tsResponse = parseTimestampResponse(tsResponseBytes);

    // Check for errors
    if (
        tsResponse.status !== TSAStatus.GRANTED &&
        tsResponse.status !== TSAStatus.GRANTED_WITH_MODS
    ) {
        const statusMessages: Record<number, string> = {
            [TSAStatus.REJECTION]: "Request rejected",
            [TSAStatus.WAITING]: "Request pending (try again later)",
            [TSAStatus.REVOCATION_WARNING]: "Revocation warning",
            [TSAStatus.REVOCATION_NOTIFICATION]: "Certificate revoked",
        };

        throw new TimestampError(
            TimestampErrorCode.TSA_ERROR,
            `TSA error: ${statusMessages[tsResponse.status] ?? `Unknown status ${tsResponse.status.toString()}`} ` +
                (tsResponse.statusString ? ` - ${tsResponse.statusString} ` : "")
        );
    }

    if (!tsResponse.token || !tsResponse.info) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "TSA response missing timestamp token"
        );
    }

    // Step 5: Embed the timestamp token in the PDF
    const timestampedPdf = embedTimestampToken(prepared, tsResponse.token);

    // If LTV is disabled, return without DSS
    if (!enableLTV) {
        return {
            pdf: timestampedPdf,
            timestamp: tsResponse.info,
        };
    }

    // Step 6: Extract LTV data from the token we just received
    const ltvData = extractLTVData(tsResponse.token);

    // Step 7: Add DSS (Document Security Store) to the PDF
    const pdfWithDSS = await addDSS(timestampedPdf, ltvData);

    return {
        pdf: pdfWithDSS,
        timestamp: tsResponse.info,
        ltvData,
    };
}

/**
 * Adds an additional timestamp to an already timestamped PDF.
 *
 * This is useful for:
 * - Adding timestamps from multiple TSAs for redundancy
 * - Re-timestamping a document before a TSA's certificate expires
 *
 * @example
 * ```typescript
 * import { timestampPdf, addTimestamp, KNOWN_TSA_URLS } from 'pdf-rfc3161';
 *
 * // First timestamp
 * const result1 = await timestampPdf({
 *   pdf: pdfBytes,
 *   tsa: { url: KNOWN_TSA_URLS.DIGICERT },
 * });
 *
 * // Add second timestamp from different TSA
 * const result2 = await addTimestamp({
 *   pdf: result1.pdf,
 *   tsa: { url: KNOWN_TSA_URLS.SECTIGO },
 * });
 *
 * console.log('PDF now has 2 timestamps');
 * ```
 *
 * @param options - Timestamping options
 * @returns Promise resolving to the PDF with an additional timestamp
 */
export async function addTimestamp(options: TimestampOptions): Promise<TimestampResult> {
    // For adding an additional timestamp, we simply call timestampPdf
    // The PDF preparation will create a new signature field
    // while preserving the existing one(s)
    return timestampPdf(options);
}

/**
 * Timestamps a PDF with multiple TSAs in sequence.
 *
 * This provides redundancy by having multiple independent timestamps.
 * If one TSA's certificate is revoked or expires, the other timestamps
 * remain valid.
 *
 * @example
 * ```typescript
 * import { timestampPdfMultiple, KNOWN_TSA_URLS } from 'pdf-rfc3161';
 *
 * const result = await timestampPdfMultiple({
 *   pdf: pdfBytes,
 *   tsaList: [
 *     { url: KNOWN_TSA_URLS.DIGICERT },
 *     { url: KNOWN_TSA_URLS.SECTIGO },
 *     { url: KNOWN_TSA_URLS.FREETSA },
 *   ],
 * });
 *
 * console.log('Added', result.timestamps.length, 'timestamps');
 * ```
 *
 * @param options - Options with multiple TSA configurations
 * @returns Promise resolving to PDF with multiple timestamps
 */
export async function timestampPdfMultiple(options: {
    pdf: Uint8Array;
    tsaList: TSAConfig[];
    reason?: string;
    location?: string;
    contactInfo?: string;
}): Promise<{
    pdf: Uint8Array;
    timestamps: TimestampInfo[];
}> {
    const { pdf, tsaList, reason, location, contactInfo } = options;

    if (tsaList.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.TSA_ERROR,
            "At least one TSA must be specified"
        );
    }

    let currentPdf = pdf;
    const timestamps: TimestampInfo[] = [];

    // Apply timestamps sequentially
    for (const tsa of tsaList) {
        const result = await timestampPdf({
            pdf: currentPdf,
            tsa,
            reason,
            location,
            contactInfo,
        });

        currentPdf = result.pdf;
        timestamps.push(result.timestamp);
    }

    return {
        pdf: currentPdf,
        timestamps,
    };
}

// Re-export KNOWN_TSA_URLS from its dedicated module
export { KNOWN_TSA_URLS } from "./tsa-urls.js";
