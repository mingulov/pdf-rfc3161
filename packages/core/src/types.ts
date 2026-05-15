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
 * Options for building an RFC 3161 TimeStampReq.
 *
 * Decoupled from {@link TSAConfig}: this carries only what affects the
 * request body itself (hash algorithm, policy OID, certificate request flag).
 * Network details like URL, timeout, retry, and headers live on {@link TSAConfig}.
 */
export interface TimestampRequestOptions {
    /** Hash algorithm to use (default: "SHA-256") */
    hashAlgorithm?: HashAlgorithm;
    /** Optional TSA policy OID -- forwarded as the `reqPolicy` field */
    policy?: string;
    /** Whether to ask the TSA to include its certificate in the response (default: true) */
    requestCertificate?: boolean;
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
     * Whether to omit the modification time (/M) from the signature dictionary.
     * Some users prefer to omit this as the timestamp token already contains the authoritative time.
     */
    omitModificationTime?: boolean;
    /**
     * Whether to optimize the signature placeholder size.
     * If true, may perform an additional TSA request to determine exact token size,
     * reducing file size and padding.
     */
    optimizePlaceholder?: boolean;
    /**
     * Enable LTV (Long-Term Validation) by embedding DSS (Document Security Store).
     * This includes certificates, CRLs, and OCSP responses needed for offline validation.
     */
    enableLTV?: boolean;
    /**
     * Pre-fetched revocation data for LTV embedding.
     * Allows supplying certificates, CRLs, and OCSP responses directly without network calls.
     * Useful for air-gapped environments or when revocation data is obtained separately.
     *
     * When provided, this data is embedded in the DSS instead of fetching from network.
     * Takes precedence over automatic fetching when enableLTV is true.
     */
    revocationData?: {
        /** DER-encoded certificates to embed */
        certificates?: Uint8Array[];
        /** DER-encoded CRLs to embed */
        crls?: Uint8Array[];
        /** DER-encoded OCSP responses to embed */
        ocspResponses?: Uint8Array[];
    };
    /**
     * Whether to ignore PDF encryption when loading the document.
     * @default false
     */
    ignoreEncryption?: boolean;
    /**
     * When true, treat TSA status REVOCATION_WARNING (4) and
     * REVOCATION_NOTIFICATION (5) as fatal errors instead of accepting
     * the token with a warning.
     *
     * Per RFC 3161 these statuses indicate the TSA's signing key/cert
     * is being revoked, so the token MAY fail strict validation by
     * relying parties. Default is `false` for backward compatibility.
     *
     * @default false
     */
    rejectOnRevocationWarning?: boolean;
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
    /**
     * Set when the TSA returned REVOCATION_WARNING (4) or REVOCATION_NOTIFICATION (5).
     * The token was still embedded (unless `rejectOnRevocationWarning` was set);
     * relying parties may treat the resulting timestamp as untrusted.
     */
    tsaRevocationWarning?: TSAStatus;
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
    /** Hash algorithm used for ESSCertID (if detectable) */
    certIdHashAlgorithm?: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
    /** Whether ESSCertIDv2 (RFC 5816) was used instead of legacy ESSCertID */
    usesESSCertIDv2?: boolean;
    /**
     * Nonce echoed from the TimeStampReq (RFC 3161 Sec. 2.4.2).
     * Optional in the protocol; populated when the TSTInfo includes a nonce field.
     * Used for replay-attack defence -- compare against the nonce that was sent
     * with the original request via validateTimestampResponse(..., expectedNonce).
     */
    nonce?: Uint8Array;
}

/**
 * Error codes for timestamp operations
 */
export enum TimestampErrorCode {
    /** Network error communicating with TSA */
    NETWORK_ERROR = "NETWORK_ERROR",
    /** TSA returned an error status */
    TSA_ERROR = "TSA_ERROR",
    /** TSA response could not be parsed at all (outer ASN.1 failure or not a TimeStampResp) */
    INVALID_RESPONSE = "INVALID_RESPONSE",
    /** TSA response parsed but inner structure is broken (e.g. granted but no TSTInfo) */
    MALFORMED_RESPONSE = "MALFORMED_RESPONSE",
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
    /** Operation called in an invalid session/object state */
    STATE_ERROR = "STATE_ERROR",
    /** Caller passed an invalid argument */
    INVALID_ARGUMENT = "INVALID_ARGUMENT",
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
 * Internal representation of a parsed TimeStampResp.
 *
 * Granted-class statuses (`GRANTED`, `GRANTED_WITH_MODS`, `REVOCATION_WARNING`,
 * `REVOCATION_NOTIFICATION`) carry a non-optional `token` and `info`.
 * Rejection-class statuses (`REJECTION`, `WAITING`) have neither but may
 * carry a `failInfo` bit and human-readable `statusString`.
 *
 * Narrow on the `status` field to access the right branch.
 */
export type ParsedTimestampResponse =
    | {
          status:
              | TSAStatus.GRANTED
              | TSAStatus.GRANTED_WITH_MODS
              | TSAStatus.REVOCATION_WARNING
              | TSAStatus.REVOCATION_NOTIFICATION;
          statusString?: string;
          token: Uint8Array;
          info: TimestampInfo;
          failInfo?: undefined;
      }
    | {
          status: TSAStatus.REJECTION | TSAStatus.WAITING;
          statusString?: string;
          failInfo?: number;
          token?: undefined;
          info?: undefined;
      };

/**
 * Options for extracting timestamps or inspecting LTV info from a PDF
 */
export interface ExtractOptions {
    /**
     * Whether to ignore PDF encryption when loading the document.
     * @default false
     */
    ignoreEncryption?: boolean;
}

/**
 * Options for verifying a timestamp
 */
export interface VerificationOptions {
    /**
     * Trust store to use for chain validation.
     * If provided, the verification will fail if the signer is not trusted.
     * If omitted or set explicitly to `null`, only cryptographic integrity
     * is checked (no chain validation). The `null` form lets callers
     * explicitly opt out -- useful because `getDefaultTrustStore()` throws
     * on an empty bundle since 0.2.0, and `{ trustStore: null }` is the
     * documented escape hatch.
     */
    trustStore?: TrustStore | null;

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

    /**
     * Require the signing TSA certificate to carry the id-kp-timeStamping
     * ExtendedKeyUsage (1.3.6.1.5.5.7.3.8) per RFC 3161 Sec. 2.3, or
     * anyExtendedKeyUsage (2.5.29.37.0) as a catch-all.
     * When true, a token signed by a cert without one of those EKU values
     * is rejected with TimestampError.
     *
     * Default `true` since 0.2.0. Pass `false` to verify legacy tokens that
     * pre-date the RFC 3161 EKU requirement.
     */
    requireTimestampingEKU?: boolean;

    /**
     * Require the signing TSA certificate to be valid (notBefore <= genTime
     * <= notAfter) at the timestamp's genTime. Without this check, a token
     * signed with an expired or not-yet-valid cert passes verification.
     *
     * Default `true` since 0.2.0. Pass `false` to verify tokens signed with
     * a TSA cert that was outside its validity window at signing time.
     */
    requireCertValidAtGenTime?: boolean;
}
