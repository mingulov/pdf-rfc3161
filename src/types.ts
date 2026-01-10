import { TrustStore } from "./pki/trust-store.js";

/**
 * Configuration for connecting to a Time Stamping Authority (TSA)
 */
export interface TSAConfig {
    /** URL of the TSA server (e.g., "http://timestamp.digicert.com") */
    url: string;
    /** Hash algorithm to use (default: "SHA-256") */
    hashAlgorithm?: HashAlgorithm;
    /** Optional TSA policy OID */
    policy?: string;
    /** Request TSA certificate in response (default: true) */
    requestCertificate?: boolean;
    /** Custom HTTP headers for TSA requests */
    headers?: Record<string, string>;
    /** Timeout in milliseconds (default: 30000) */
    timeout?: number;
    /** Number of retry attempts for network errors (default: 3) */
    retry?: number;
    /** Base delay in ms between retries, doubles each retry (default: 1000) */
    retryDelay?: number;
}

/**
 * Supported hash algorithms for timestamping
 */
export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512";

/**
 * Options for timestamping a PDF document
 */
export interface TimestampOptions {
    /** PDF document bytes to timestamp */
    pdf: Uint8Array;
    /** TSA configuration */
    tsa: TSAConfig;
    /** Optional reason for the timestamp */
    reason?: string;
    /** Optional location metadata */
    location?: string;
    /** Optional contact information */
    contactInfo?: string;
    /** Optional name for the signature field */
    signatureFieldName?: string;
    /** Maximum allowed PDF size in bytes (default: 250MB) */
    maxSize?: number;
    /**
     * Size reserved for timestamp token in bytes (default: 8192).
     * Set to 0 for automatic sizing (will retry with larger size if needed).
     */
    signatureSize?: number;
    /**
     * Whether to optimize the signature placeholder size.
     * If true, may perform an additional TSA request to determine exact token size,
     * reducing file size and padding.
     */
    optimizePlaceholder?: boolean;
    /**
     * Whether to omit the modification time (/M) from the signature dictionary.
     * Some users prefer to omit this as the timestamp token already contains the authoritative time.
     */
    omitModificationTime?: boolean;
    /**
     * Enable LTV (Long-Term Validation) by embedding DSS (Document Security Store).
     * This includes certificates, CRLs, and OCSP responses needed for offline validation.
     */
    enableLTV?: boolean;
}

/**
 * Result of a successful timestamping operation
 */
export interface TimestampResult {
    /** The timestamped PDF bytes */
    pdf: Uint8Array;
    /** Information about the embedded timestamp */
    timestamp: TimestampInfo;
    /** LTV data that was embedded (if enableLTV was true) */
    ltvData?: {
        /** Certificates embedded for LTV */
        certificates: Uint8Array[];
        /** CRLs embedded for LTV */
        crls: Uint8Array[];
        /** OCSP responses embedded for LTV */
        ocspResponses: Uint8Array[];
    };
}

/**
 * Information extracted from a timestamp token
 */
export interface TimestampInfo {
    /** Time from the TSA (UTC) */
    genTime: Date;
    /** TSA policy OID */
    policy: string;
    /** Serial number of the timestamp (hex string) */
    serialNumber: string;
    /** Hash algorithm used */
    hashAlgorithm: string;
    /** Hash algorithm OID */
    hashAlgorithmOID: string;
    /** Message digest that was timestamped (hex string) */
    messageDigest: string;
    /** Whether the TSA certificate was included */
    hasCertificate: boolean;
}

/**
 * Error codes for timestamp operations
 */
export enum TimestampErrorCode {
    /** Network error communicating with TSA */
    NETWORK_ERROR = "NETWORK_ERROR",
    /** TSA returned an error status */
    TSA_ERROR = "TSA_ERROR",
    /** Invalid or malformed TSA response */
    INVALID_RESPONSE = "INVALID_RESPONSE",
    /** PDF parsing or manipulation error */
    PDF_ERROR = "PDF_ERROR",
    /** Timeout waiting for TSA response */
    TIMEOUT = "TIMEOUT",
    /** Hash algorithm not supported */
    UNSUPPORTED_ALGORITHM = "UNSUPPORTED_ALGORITHM",
    /** LTV data extraction or embedding failed */
    LTV_ERROR = "LTV_ERROR",
    /** Timestamp verification failed */
    VERIFICATION_FAILED = "VERIFICATION_FAILED",
}

/**
 * Custom error class for timestamp operations
 */
export class TimestampError extends Error {
    constructor(
        public readonly code: TimestampErrorCode,
        message: string,
        public readonly cause?: unknown
    ) {
        super(message);
        this.name = "TimestampError";
    }
}

/**
 * TSA status codes from RFC 3161
 */
export enum TSAStatus {
    GRANTED = 0,
    GRANTED_WITH_MODS = 1,
    REJECTION = 2,
    WAITING = 3,
    REVOCATION_WARNING = 4,
    REVOCATION_NOTIFICATION = 5,
}

/**
 * Internal representation of a parsed TimeStampResp
 */
export interface ParsedTimestampResponse {
    status: TSAStatus;
    statusString?: string;
    failInfo?: number;
    token?: Uint8Array;
    info?: TimestampInfo;
}

/**
 * Options for verifying a timestamp
 */
export interface VerificationOptions {
    /**
     * Trust store to use for chain validation.
     * If provided, the verification will fail if the signer is not trusted.
     * If omitted, only cryptographic integrity is checked (no chain validation).
     */
    trustStore?: TrustStore;

    /**
     * Enforce strict PAdES compliance (ESIC).
     * If true, verifies that the 'signing-certificate' or 'signing-certificate-v2' (ESS) attribute is present.
     * This attribute binds the signature to a specific certificate.
     */
    strictESSValidation?: boolean;

    /**
     * The original PDF bytes.
     * If provided, verifyTimestamp will also verify that the document hash
     * matches the hash stored in the timestamp token.
     */
    pdf?: Uint8Array;
}
