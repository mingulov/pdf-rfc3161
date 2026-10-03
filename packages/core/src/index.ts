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
    type ExtractInputOptions,
} from "./pdf/extract.js";

import { type LTVData, type LTVSettings } from "./pdf/ltv.js";

import { archiveTimestamp, timestampPdfLTA, type ArchiveTimestampOptions } from "./pdf/archive.js";

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
    type TimestampResponseValidationOptions,
    type ParsedTimestampResponse,
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
} from "./types.js";

// Export Logger Interface and Utils
export { getLogger, setLogger, disableLogging } from "./utils/logger.js";
export type { Logger } from "./utils/logger.js";

import { type TrustStore, SimpleTrustStore } from "./pki/trust-store.js";

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
    TimestampResponseValidationOptions,
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
export {
    extractTimestamps,
    verifyTimestamp,
    verifyPdfTimestamps,
    type ExtractedTimestamp,
    type ExtractInputOptions,
};
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

// The one-call API lives in `./timestamp-pdf.js` (audit S1): archive renewal
// drives it, so defining it here created an index <-> archive value cycle.
// Export locations are unchanged.
export { timestampPdf, timestampPdfMultiple } from "./timestamp-pdf.js";
