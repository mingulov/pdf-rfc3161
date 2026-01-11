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

import { preparePdfForTimestamp, type PreparedPDF } from "./pdf/prepare.js";

import { embedTimestampToken, extractBytesToHash } from "./pdf/embed.js";

import { extractTimestamps, verifyTimestamp, type ExtractedTimestamp } from "./pdf/extract.js";

import {
    extractLTVData,
    completeLTVData,
    addDSS,
    addVRI,
    addVRIEnhanced,
    getDSSInfo,
    type LTVData,
    type CompletedLTVData,
} from "./pdf/ltv.js";

import { timestampPdfLTA, type ArchiveTimestampOptions } from "./pdf/archive.js";

import { TimestampSession } from "./session.js";

import {
    type TimestampOptions,
    type TimestampResult,
    type TimestampInfo,
    type VerificationOptions,
    type HashAlgorithm,
    type TSAConfig,
    type ParsedTimestampResponse,
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
} from "./types.js";

import { TrustStore, SimpleTrustStore } from "./pki/trust-store.js";

export {
    ValidationSession,
    type CertificateToValidate,
    type ValidationResult,
    type RevocationDataFetcher,
    type ValidationCache,
    type ValidationSessionOptions,
    DefaultFetcher,
    MockFetcher,
    InMemoryValidationCache,
} from "./pki/index.js";

export { KNOWN_TSA_URLS, EXTENDED_TSA_URLS, ALL_KNOWN_TSA_URLS } from "./tsa-urls.js";

export {
    TSA_COMPATIBILITY,
    INCOMPATIBLE_TSA_URLS,
    isTSACompatible,
    getTSACompatibility,
    type TSACompatibilityInfo,
} from "./tsa-compatibility.js";

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

export type { TimestampOptions, TimestampResult, TSAConfig, HashAlgorithm, TimestampInfo };

// Re-export lower-level APIs for advanced usage
export { createTimestampRequest, sendTimestampRequest, parseTimestampResponse };

export { preparePdfForTimestamp, embedTimestampToken, extractBytesToHash };

export type { PreparedPDF };

// Re-export LTV and verification functions
export {
    extractLTVData,
    completeLTVData,
    addDSS,
    addVRI,
    addVRIEnhanced,
    getDSSInfo,
    timestampPdfLTA,
    SimpleTrustStore,
};
export { extractTimestamps, verifyTimestamp };

export type { LTVData, ExtractedTimestamp, ArchiveTimestampOptions, TrustStore };

// Re-export constants
export { DEFAULT_TSA_CONFIG, MAX_PDF_SIZE, DEFAULT_SIGNATURE_SIZE, LTV_SIGNATURE_SIZE };

// Re-export new Session API
export { TimestampSession, type TimestampSessionOptions } from "./session.js";

// Re-export verify types that were missed
export type { VerificationOptions, ParsedTimestampResponse };

// Re-export Circuit Breaker utilities
export {
    CircuitBreaker,
    CircuitBreakerMap,
    CircuitState,
    CircuitBreakerError,
} from "./utils/circuit-breaker.js";

/**
 * Main API function to timestamp a PDF with LTV support
 */
export async function timestampPdf(options: TimestampOptions): Promise<TimestampResult> {
    const {
        pdf,
        tsa,
        enableLTV = false,
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
                tsResponse.status !== TSAStatus.GRANTED_WITH_MODS
            ) {
                throw new TimestampError(
                    TimestampErrorCode.TSA_ERROR,
                    `TSA server returned error: ${tsResponse.statusString ?? "Unknown error"} (Status: ${String(tsResponse.status)})`
                );
            }

            if (!tsResponse.token) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "No timestamp token in response"
                );
            }

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

            if (!tsResponse.info) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "No timestamp information in response"
                );
            }

            return {
                pdf: finalPdf,
                timestamp: tsResponse.info,
                ltvData,
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
 * Timestamps a PDF with multiple TSAs in sequence.
 */
export async function timestampPdfMultiple(options: {
    pdf: Uint8Array;
    tsaList: TSAConfig[];
    reason?: string;
    location?: string;
    contactInfo?: string;
    enableLTV?: boolean;
}): Promise<{
    pdf: Uint8Array;
    timestamps: TimestampInfo[];
    ltvData?: TimestampResult["ltvData"][];
}> {
    const { pdf, tsaList, reason, location, contactInfo, enableLTV } = options;

    if (tsaList.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.TSA_ERROR,
            "At least one TSA must be specified"
        );
    }

    let currentPdf = pdf;
    const timestamps: TimestampInfo[] = [];
    const ltvDataList: TimestampResult["ltvData"][] = [];

    for (const tsa of tsaList) {
        const result = await timestampPdf({
            pdf: currentPdf,
            tsa,
            reason,
            location,
            contactInfo,
            enableLTV,
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
