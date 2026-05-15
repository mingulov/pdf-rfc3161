/**
 * OID constants for hash algorithms and other cryptographic identifiers
 */
export const OID = {
    // Hash algorithms
    SHA256: "2.16.840.1.101.3.4.2.1",
    SHA384: "2.16.840.1.101.3.4.2.2",
    SHA512: "2.16.840.1.101.3.4.2.3",

    // Content types
    DATA: "1.2.840.113549.1.7.1",
    SIGNED_DATA: "1.2.840.113549.1.7.2",
    TST_INFO: "1.2.840.113549.1.9.16.1.4",

    // Signature algorithms
    RSA_ENCRYPTION: "1.2.840.113549.1.1.1",
    SHA256_WITH_RSA: "1.2.840.113549.1.1.11",
    SHA384_WITH_RSA: "1.2.840.113549.1.1.12",
    SHA512_WITH_RSA: "1.2.840.113549.1.1.13",

    // Attributes
    CONTENT_TYPE: "1.2.840.113549.1.9.3",
    MESSAGE_DIGEST: "1.2.840.113549.1.9.4",
    SIGNING_TIME: "1.2.840.113549.1.9.5",
    SIGNING_CERTIFICATE_V2: "1.2.840.113549.1.9.16.2.47",
} as const;

/**
 * Map from algorithm name to OID
 */
export const HASH_ALGORITHM_TO_OID: Record<string, string> = {
    "SHA-256": OID.SHA256,
    "SHA-384": OID.SHA384,
    "SHA-512": OID.SHA512,
};

/**
 * Map from OID to algorithm name
 */
export const OID_TO_HASH_ALGORITHM: Record<string, string> = {
    [OID.SHA256]: "SHA-256",
    [OID.SHA384]: "SHA-384",
    [OID.SHA512]: "SHA-512",
};

/**
 * Default TSA configuration values
 */
export const DEFAULT_TSA_CONFIG = {
    hashAlgorithm: "SHA-256" as const,
    requestCertificate: true,
    timeout: 30000,
    retry: 3,
    retryDelay: 1000,
};

/**
 * Default CRL configuration values.
 * CRLs are typically larger and slower to fetch, so we allow more time and retries.
 */
export const DEFAULT_CRL_CONFIG = {
    timeout: 15000, // 15 seconds
    retry: 3,
    retryDelay: 1000, // 1 second base delay
    resetTimeoutMs: 120000, // 2 minutes circuit breaker reset
    /** H5 cap. Real-world CRLs can be a few MB; 10MB is a generous upper bound. */
    maxResponseBytes: 10 * 1024 * 1024,
};

/**
 * Default OCSP configuration values.
 * OCSP requests are small and should be fast.
 */
export const DEFAULT_OCSP_CONFIG = {
    timeout: 5000, // 5 seconds
    retry: 3,
    retryDelay: 500, // 500ms base delay
    resetTimeoutMs: 60000, // 1 minute circuit breaker reset
    /** H5 cap. OCSP responses are typically 1-5 KB; 50 KB is more than enough. */
    maxResponseBytes: 50 * 1024,
};

/**
 * Default Certificate configuration values (AIA).
 */
export const DEFAULT_CERT_CONFIG = {
    timeout: 10000, // 10 seconds
    retry: 2,
    retryDelay: 500, // 500ms base delay
    resetTimeoutMs: 60000, // 1 minute circuit breaker reset
    /** H5 cap. Single certificates are typically 1-3 KB. 50 KB is the cap. */
    maxResponseBytes: 50 * 1024,
};

/**
 * H5 cap for TSA responses. TimeStampResp bodies hold a single token +
 * possibly an embedded chain; 100 KB is the cap.
 */
export const DEFAULT_TSA_MAX_RESPONSE_BYTES = 100 * 1024;

/**
 * Content-Type headers for TSA communication
 */
export const TSA_CONTENT_TYPE = {
    REQUEST: "application/timestamp-query",
    RESPONSE: "application/timestamp-reply",
};

/**
 * Maximum supported PDF size in bytes (to prevent DoS)
 * Default: 250MB
 */
export const MAX_PDF_SIZE = 250 * 1024 * 1024;

/**
 * Default reserved size for the timestamp signature placeholder.
 * 8192 bytes (8KB) is typically sufficient for most DocTimeStamp tokens.
 */
export const DEFAULT_SIGNATURE_SIZE = 8192;

/**
 * Default reserved size for LTV (Long-Term Validation) signatures.
 * LTV requires significantly more space to embed certificate chains and revocation data (DSS).
 * We allocate double the default size to be safe.
 */
export const LTV_SIGNATURE_SIZE = DEFAULT_SIGNATURE_SIZE * 2;

/**
 * Constants for signature sizing and optimization.
 */
export const SIGNATURE_SIZE_OPTIMIZE_ADD = 32;
export const SIGNATURE_SIZE_OPTIMIZE_ALIGN = 32;
export const MAX_SIGNATURE_SIZE = 65536;
