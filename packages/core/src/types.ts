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

/** Options for authenticating a manual RFC 3161 response before PDF embedding. */
export interface TimestampResponseValidationOptions {
    /** DER X.509 candidates required for a manual certReq=false response. */
    signerCertificates?: readonly Uint8Array[];
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
    /**
     * Optional requested base name for the signature field. A numeric suffix may be added to
     * avoid an existing fully qualified field name.
     */
    signatureFieldName?: string;
    /** Maximum allowed PDF size in bytes (default: 250MB) */
    maxSize?: number;
    /**
     * Initial size reserved for the timestamp token in bytes (default: 8192).
     * Omit or set to 0 to use that default; timestampPdf retries with a larger
     * placeholder if the token does not fit.
     */
    signatureSize?: number;
    /**
     * Whether to omit the modification time (/M) from the signature dictionary.
     * The field is omitted by default because the timestamp token contains a signed `genTime`;
     * explicit `false` restores the legacy metadata.
     */
    omitModificationTime?: boolean;
    /**
     * Whether to optimize the signature placeholder size.
     * If true, may perform an additional TSA request to determine exact token size,
     * reducing file size and padding.
     */
    optimizePlaceholder?: boolean;
    /**
     * Embed DSS (Document Security Store) candidate material, including certificates,
     * CRLs, and OCSP responses. This supplies validation inputs but does not establish
     * revocation trust, TSA trust, or long-term-validity sufficiency.
     */
    enableLTV?: boolean;
    /**
     * Pre-fetched revocation candidate material for LTV embedding.
     * Allows supplying certificates, CRLs, and OCSP responses directly without network calls.
     * Useful for air-gapped environments or when revocation data is obtained separately.
     *
     * When provided, this data is embedded in the DSS instead of fetching from network.
     * It is caller-responsible raw material: the library does not claim it has
     * validated its signature, issuer/responder authorization, freshness,
     * scope, CertID, or revocation status.
     * Takes precedence over automatic fetching when enableLTV is true.
     */
    revocationData?: {
        /** DER-encoded certificate candidate material to embed */
        certificates?: Uint8Array[];
        /** Caller-responsible DER-encoded CRL candidate material to embed */
        crls?: Uint8Array[];
        /** Caller-responsible DER-encoded OCSP candidate material to embed */
        ocspResponses?: Uint8Array[];
    };
    /**
     * Whether to ignore PDF encryption when loading the document.
     * @default false
     */
    ignoreEncryption?: boolean;
    /**
     * @deprecated All non-granted TSA statuses are fatal before embedding.
     * Retained only for source compatibility and has no effect.
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
    /**
     * LTV candidate material embedded when enableLTV was true. Its presence
     * does not by itself establish revocation trust or indefinite validity.
     */
    ltvData?: {
        /** Certificates embedded for LTV */
        certificates: Uint8Array[];
        /** CRLs embedded for LTV */
        crls: Uint8Array[];
        /** OCSP responses embedded for LTV */
        ocspResponses: Uint8Array[];
    };
    /** @deprecated Successful timestamp operations never set this field. */
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
     * Used by TimestampSession's request-bound replay defence when it compares
     * the response with the nonce from the original request.
     * Extracted fields that inherit one selected PDF /V may share this buffer;
     * treat it as read-only and copy it before mutation.
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
 * Only successful statuses (0/1) are returned. All other TSA statuses throw
 * `TimestampErrorCode.TSA_ERROR` before a token can be used.
 */
export interface ParsedTimestampResponse {
    status: TSAStatus.GRANTED | TSAStatus.GRANTED_WITH_MODS;
    /** Optional TSA status text preserved for accepted statuses 0 and 1. */
    statusString?: string;
    token: Uint8Array;
    info: TimestampInfo;
    /** Present only for source compatibility; successful statuses have no failure bits. */
    failInfo?: undefined;
}

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
     * Enforce strict PAdES ESS validation. If true, verifies the complete
     * signed SigningCertificate and/or SigningCertificateV2 binding to the
     * SID-selected signer certificate.
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
     * ExtendedKeyUsage (1.3.6.1.5.5.7.3.8) per RFC 3161 Sec. 2.3. The
     * certificate must have exactly one critical EKU extension containing
     * that sole purpose.
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
