import {
    DEFAULT_TSA_CONFIG,
    MAX_PDF_SIZE,
    DEFAULT_SIGNATURE_SIZE,
    LTV_SIGNATURE_SIZE,
} from "./constants.js";

import {
    createTimestampRequest,
    createTimestampRequestFromHash,
    sendTimestampRequest,
    parseTimestampResponse,
} from "./tsa/index.js";

import {
    extractTimestamps,
    verifyTimestamp,
    verifyPdfTimestamps,
    type ExtractedTimestamp,
} from "./pdf/extract.js";

import {
    extractLTVData,
    completeLTVData,
    addDSS,
    type LTVData,
    type CompletedLTVData,
    type LTVSettings,
} from "./pdf/ltv.js";

import {
    archiveTimestamp,
    timestampPdfLTA,
    type ArchiveTimestampOptions,
} from "./pdf/archive.js";

import { TimestampSession, type TimestampSessionOptions } from "./session.js";

import {
    type TimestampOptions,
    type TimestampResult,
    type TimestampInfo,
    type ExtractOptions,
    type VerificationOptions,
    type HashAlgorithm,
    type TSAConfig,
    type TimestampRequestOptions,
    type ParsedTimestampResponse,
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
} from "./types.js";

// Export Logger Interface and Utils
export { getLogger, setLogger, disableLogging } from "./utils/logger.js";
export type { Logger } from "./utils/logger.js";

import { TrustStore, SimpleTrustStore } from "./pki/trust-store.js";

// ValidationSession, DefaultFetcher, MockFetcher, InMemoryValidationCache, and
// the CircuitBreaker family are reachable via the `pdf-rfc3161/advanced`
// subpath so bundlers can drop them when unused. They are no longer
// re-exported from the main entry to keep autocomplete focused on the
// timestampPdf / verifyTimestamp / TimestampSession surface most callers want.

export { KNOWN_TSA_URLS, type KnownTSAName, type KnownTSAUrl } from "./tsa-urls.js";

// RFC 5544 TimeStampedData support
export {
    createTimeStampedData,
    addTimestampsToEnvelope,
    parseTimeStampedData,
    extractDataFromEnvelope,
    extractTimestampsFromEnvelope,
    verifyTimeStampedDataEnvelope,
    type TimeStampedDataOptions,
    type ParsedTimeStampedData,
} from "./rfcs/rfc5544.js";

// RFC 8933 CMS Algorithm Identifier Protection
export {
    validateRFC8933Compliance,
    validateTimestampTokenRFC8933Compliance,
    RFC8933_CONSTANTS,
    type RFC8933ValidationResult,
} from "./rfcs/rfc8933.js";

// Re-export standard APIs and Types
export { TimestampError, TimestampErrorCode, TSAStatus };

export type {
    TimestampOptions,
    TimestampResult,
    TSAConfig,
    TimestampRequestOptions,
    HashAlgorithm,
    TimestampInfo,
};

// Re-export lower-level APIs for advanced usage
export {
    createTimestampRequest,
    createTimestampRequestFromHash,
    sendTimestampRequest,
    parseTimestampResponse,
};

// Lower-level helpers (PDF I/O, PKI plumbing) live on the `/internals`
// subpath -- import via `from "pdf-rfc3161/internals"`. The top-level entry
// surfaces only the high-frequency signing/verification flow.

// eslint-disable-next-line @typescript-eslint/no-deprecated -- public alias kept on purpose
export { archiveTimestamp, timestampPdfLTA, SimpleTrustStore };
export { CertificateStatus } from "./pki/ocsp-utils.js";
export { extractTimestamps, verifyTimestamp, verifyPdfTimestamps, type ExtractedTimestamp };
export { getDefaultTrustStore } from "./pki/default-trust-store.js";

export type { LTVData, ArchiveTimestampOptions, TrustStore, LTVSettings, ExtractOptions };

// Re-export constants
export { DEFAULT_TSA_CONFIG, MAX_PDF_SIZE, DEFAULT_SIGNATURE_SIZE, LTV_SIGNATURE_SIZE };

// Re-export new Session API (imported above for local use)
export { TimestampSession };
export type { TimestampSessionOptions };

// Re-export verify types that were missed
export type { VerificationOptions, ParsedTimestampResponse };

// CircuitBreaker / CircuitBreakerMap / CircuitState / CircuitBreakerError
// have moved to the `pdf-rfc3161/advanced` subpath.

/**
 * Adds an RFC 3161 trusted timestamp to a PDF.
 *
 * This is the one-call API: prepare the PDF, send a TimeStampReq to the
 * TSA, embed the TimeStampResp as a Document Timestamp (DocTimeStamp /
 * ETSI.RFC3161) signature, and optionally collect Long-Term Validation
 * (LTV) data into the PDF's Document Security Store (DSS).
 *
 * @param options - {@link TimestampOptions}: the PDF bytes, TSA config,
 *   and tuning flags. Only `pdf` and `tsa` are required.
 * @returns A {@link TimestampResult} with the timestamped PDF bytes,
 *   parsed {@link TimestampInfo}, optional `ltvData`, and an optional
 *   `tsaRevocationWarning` if the TSA returned status 4 or 5.
 *
 * @throws {TimestampError} with `code`:
 *   - `PDF_ERROR` if the input PDF can't be parsed or exceeds `maxSize`.
 *   - `TSA_ERROR` if the TSA rejected the request, or returned a
 *     revocation warning with `rejectOnRevocationWarning: true`.
 *   - `NETWORK_ERROR` if the TSA URL fails {@link validateUrl} (SSRF),
 *     exceeds the response size cap, or all retries are exhausted.
 *   - `INVALID_RESPONSE` if the TSA response doesn't parse, the nonce
 *     doesn't match, or the message digest doesn't match.
 *
 * @example
 * Minimal usage:
 * ```typescript
 * import { timestampPdf, KNOWN_TSA_URLS } from "pdf-rfc3161";
 * const { pdf, timestamp } = await timestampPdf({
 *     pdf: bytes,
 *     tsa: { url: KNOWN_TSA_URLS.FREETSA },
 * });
 * console.log("Timestamped at:", timestamp.genTime);
 * ```
 *
 * @example
 * With LTV embedding:
 * ```typescript
 * const result = await timestampPdf({
 *     pdf: bytes,
 *     tsa: { url: KNOWN_TSA_URLS.DIGICERT },
 *     enableLTV: true,
 * });
 * // result.ltvData contains the embedded certs/CRLs/OCSP responses.
 * ```
 */
export async function timestampPdf(options: TimestampOptions): Promise<TimestampResult> {
    const {
        pdf,
        tsa,
        enableLTV = true,
        signatureSize,
        optimizePlaceholder,
        maxSize,
        revocationData,
    } = options;
    const maxPdfSize = maxSize ?? MAX_PDF_SIZE;

    if (pdf.length > maxPdfSize) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `PDF exceeds maximum supported size of ${maxPdfSize.toString()} bytes`
        );
    }

    // Config for retries
    let currentSignatureSize = signatureSize ?? 0; // 0 will use default in Session
    const MAX_RETRIES = 3;

    // Optimization phase: if enabled, determine optimal size first
    if (optimizePlaceholder) {
        try {
            // Use session to handle defaults and preparation
            const session = new TimestampSession(pdf, {
                enableLTV,
                prepareOptions: { ...options, signatureSize: currentSignatureSize },
                hashAlgorithm: tsa.hashAlgorithm,
            });

            const request = await session.createTimestampRequest();

            // We need to fetch a real token to know its size
            const responseBytes = await sendTimestampRequest(request, tsa);
            const tsResponse = parseTimestampResponse(responseBytes);

            if (tsResponse.token) {
                const optimalSize = TimestampSession.calculateOptimalSize(tsResponse.token);
                session.setSignatureSize(optimalSize);
                currentSignatureSize = optimalSize;
            }
        } catch {
            // If optimization probe fails, proceed with standard logic
        }
    }

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        let tsResponse: ParsedTimestampResponse | undefined;
        try {
            const session = new TimestampSession(pdf, {
                enableLTV: false, // We handle LTV manually to capture the data for the return value
                prepareOptions: {
                    ...options,
                    signatureSize: currentSignatureSize,
                },
                hashAlgorithm: tsa.hashAlgorithm,
            });

            const request = await session.createTimestampRequest();
            const responseBytes = await sendTimestampRequest(request, tsa);
            tsResponse = parseTimestampResponse(responseBytes);

            if (
                tsResponse.status !== TSAStatus.GRANTED &&
                tsResponse.status !== TSAStatus.GRANTED_WITH_MODS &&
                tsResponse.status !== TSAStatus.REVOCATION_WARNING &&
                tsResponse.status !== TSAStatus.REVOCATION_NOTIFICATION
            ) {
                throw new TimestampError(
                    TimestampErrorCode.TSA_ERROR,
                    `TSA server returned error: ${tsResponse.statusString ?? "Unknown error"} (Status: ${String(tsResponse.status)})`
                );
            }

            // M4: surface revocation warnings. Optionally treat them as fatal.
            const isRevocationWarning =
                tsResponse.status === TSAStatus.REVOCATION_WARNING ||
                tsResponse.status === TSAStatus.REVOCATION_NOTIFICATION;
            if (isRevocationWarning && options.rejectOnRevocationWarning) {
                throw new TimestampError(
                    TimestampErrorCode.TSA_ERROR,
                    `TSA returned status ${String(tsResponse.status)} (revocation warning/notification): ${tsResponse.statusString ?? "TSA signing certificate is being revoked"}. Rejected because rejectOnRevocationWarning is true.`
                );
            }

            // The status guard above narrows to a granted branch, so
            // `tsResponse.token` is now non-optional in the type. No runtime
            // check needed.
            let finalPdf = await session.embedTimestampToken(tsResponse.token);

            let ltvData: TimestampResult["ltvData"] = undefined;
            if (enableLTV) {
                const extracted = extractLTVData(tsResponse.token);

                let completed: CompletedLTVData;
                if (revocationData) {
                    // Use pre-fetched revocation data instead of network fetching
                    completed = {
                        data: {
                            certificates: revocationData.certificates ?? extracted.certificates,
                            crls: revocationData.crls ?? [],
                            ocspResponses: revocationData.ocspResponses ?? [],
                        },
                        errors: [],
                    };
                } else {
                    // Fetch missing OCSP data to make LTV complete
                    completed = await completeLTVData(extracted);
                }

                ltvData = {
                    certificates: completed.data.certificates,
                    crls: completed.data.crls,
                    ocspResponses: completed.data.ocspResponses,
                };

                finalPdf = await addDSS(finalPdf, completed.data);
            }

            // Likewise: granted branches carry `info: TimestampInfo`.


            return {
                pdf: finalPdf,
                timestamp: tsResponse.info,
                ltvData,
                ...(isRevocationWarning && { tsaRevocationWarning: tsResponse.status }),
            };
        } catch (error) {
            // Check if error is due to placeholder size
            if (error instanceof Error && error.message.includes("Increase signatureSize")) {
                if (attempt < MAX_RETRIES) {
                    // Use the optimal size for the token we just received if available
                    if (tsResponse?.token) {
                        currentSignatureSize = TimestampSession.calculateOptimalSize(
                            tsResponse.token
                        );
                    } else {
                        // Fallback to doubling if we don't have a token (shouldn't happen with this error)
                        const currentVal = currentSignatureSize || DEFAULT_SIGNATURE_SIZE;
                        currentSignatureSize = currentVal * 2;
                    }
                    continue;
                }
            }
            throw error;
        }
    }
    throw new TimestampError(TimestampErrorCode.PDF_ERROR, "Failed to timestamp after retries");
}

/**
 * Timestamps a PDF with multiple TSAs in sequence. Each TSA produces a
 * separate signed timestamp; the resulting PDF carries all of them.
 *
 * @example
 * ```typescript
 * const result = await timestampPdfMultiple({
 *     pdf,
 *     tsaList: [
 *         { url: KNOWN_TSA_URLS.FREETSA },
 *         { url: KNOWN_TSA_URLS.DIGICERT },
 *     ],
 * });
 * console.log(`Embedded ${result.timestamps.length} timestamps`);
 * ```
 */
export async function timestampPdfMultiple(
    options: { pdf: Uint8Array; tsaList: TSAConfig[] } & Omit<TimestampOptions, "pdf" | "tsa">
): Promise<{
    pdf: Uint8Array;
    timestamps: TimestampInfo[];
    ltvData?: TimestampResult["ltvData"][];
}> {
    const { pdf, tsaList, ...rest } = options;

    if (tsaList.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            "At least one TSA must be specified"
        );
    }

    let currentPdf = pdf;
    const timestamps: TimestampInfo[] = [];
    const ltvDataList: TimestampResult["ltvData"][] = [];

    for (const tsa of tsaList) {
        const result = await timestampPdf({
            ...rest,
            pdf: currentPdf,
            tsa,
        });

        currentPdf = result.pdf;
        timestamps.push(result.timestamp);
        if (result.ltvData) {
            ltvDataList.push(result.ltvData);
        }
    }

    return {
        pdf: currentPdf,
        timestamps,
        ltvData: ltvDataList.length > 0 ? ltvDataList : undefined,
    };
}
