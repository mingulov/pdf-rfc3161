import * as pkijs from "pkijs";

/**
 * Represents a single certificate requiring validation
 */
export interface CertificateToValidate {
    /** The certificate to check */
    cert: pkijs.Certificate;
    /**
     * Explicitly supplied issuer. Verified at use: it must have issued
     * `cert` (name match plus target signature verification), otherwise
     * issuer-dependent evidence is not attempted.
     */
    issuer?: pkijs.Certificate;
    /**
     * Candidate issuers stored by `queueChain` (name matches excluding the
     * target itself by exact bytes). Narrowed and signature-verified at
     * use; never treated as authoritative without verification.
     */
    issuerCandidates?: pkijs.Certificate[];
}

/**
 * Revocation status of a certificate relative to a verified issuing key.
 *
 * This API establishes revocation status only. It is not complete path
 * trust and does not cover every certificate-validity property (expiry,
 * name constraints, policy processing, and so on). Only authenticated
 * evaluators may produce "good" or "revoked": missing endpoints/issuers,
 * malformed, stale or unsupported evidence, and outages all yield
 * "unknown". Until the authenticated OCSP/CRL evaluators exist, structural
 * evidence alone always yields "unknown".
 */
export type RevocationStatus = "good" | "revoked" | "unknown";

/**
 * Internal per-source revocation evidence evaluation.
 *
 * Not part of the public API. Produced while combining OCSP/CRL evidence
 * inside ValidationSession; see RevocationStatus for the verdict rules.
 */
export interface RevocationEvidenceResult {
    /** Evaluated status for this evidence source */
    status: RevocationStatus;
    /** Evidence source that was evaluated */
    source: "OCSP" | "CRL";
    /** Diagnostics recorded while evaluating this source */
    errors: string[];
}

/**
 * Result of validating a single certificate
 */
export interface ValidationResult {
    /** Certificate that was validated */
    cert: pkijs.Certificate;
    /**
     * Revocation status relative to a verified issuing key (see
     * RevocationStatus). Until authenticated evaluators exist, structural
     * evidence alone yields "unknown".
     */
    revocationStatus: RevocationStatus;
    /**
     * Whether the certificate revocation status is authenticated good.
     *
     * @deprecated Compatibility alias for `revocationStatus === "good"`.
     * Its meaning changed: it used to default to true ("not known
     * revoked", even with no evidence at all) and is now true only for
     * authenticated good. Prefer `revocationStatus` directly.
     */
    isValid: boolean;
    /** Sources used for validation */
    sources: ("OCSP" | "CRL")[];
    /** Errors encountered */
    errors: string[];
    /**
     * DER-encoded OCSP responses fetched while validating this certificate.
     * Populated so exportLTVData() can embed them in the PDF DSS.
     */
    ocspResponses?: Uint8Array[];
    /**
     * DER-encoded CRLs fetched while validating this certificate.
     * Populated so exportLTVData() can embed them in the PDF DSS.
     */
    crls?: Uint8Array[];
}

/**
 * Fetch implementation interface - allows pluggable fetch.
 * Implement this interface to provide custom network behavior.
 *
 * @example
 * ```typescript
 * // Custom fetch-based implementation
 * class CustomFetcher implements RevocationDataFetcher {
 *     async fetchOCSP(url: string, request: Uint8Array): Promise<Uint8Array> {
 *         const response = await fetch(url, {
 *             method: "POST",
 *             headers: { "Content-Type": "application/ocsp-request" },
 *             body: request,
 *         });
 *         return new Uint8Array(await response.arrayBuffer());
 *     }
 *
 *     async fetchCRL(url: string): Promise<Uint8Array> {
 *         const response = await fetch(url);
 *         return new Uint8Array(await response.arrayBuffer());
 *     }
 * }
 * ```
 */
export interface RevocationDataFetcher {
    /**
     * Fetch OCSP response for a certificate
     * @param url OCSP responder URL
     * @param request DER-encoded OCSP request
     * @returns DER-encoded OCSP response
     */
    fetchOCSP(url: string, request: Uint8Array): Promise<Uint8Array>;

    /**
     * Fetch CRL from distribution point
     * @param url CRL URL
     * @returns DER-encoded CRL
     */
    fetchCRL(url: string): Promise<Uint8Array>;
}

/**
 * Cache for revocation data.
 * Implement this interface to provide custom caching behavior.
 */
export interface ValidationCache {
    /**
     * Get cached OCSP response
     * @param url OCSP responder URL
     * @param request DER-encoded OCSP request
     * @returns Cached response or null if not found
     */
    getOCSP(url: string, request: Uint8Array): Uint8Array | null;

    /**
     * Cache OCSP response
     * @param url OCSP responder URL
     * @param request DER-encoded OCSP request
     * @param response DER-encoded OCSP response
     */
    setOCSP(url: string, request: Uint8Array, response: Uint8Array): void;

    /**
     * Get cached CRL
     * @param url CRL URL
     * @returns Cached CRL or null if not found
     */
    getCRL(url: string): Uint8Array | null;

    /**
     * Cache CRL
     * @param url CRL URL
     * @param response DER-encoded CRL
     */
    setCRL(url: string, response: Uint8Array): void;

    /**
     * Clear all cached data
     */
    clear(): void;
}

/**
 * Default options for ValidationSession
 */
export interface ValidationSessionOptions {
    /** Fetch implementation (defaults to DefaultFetcher) */
    fetcher?: RevocationDataFetcher;
    /** Cache for previously fetched data */
    cache?: ValidationCache;
    /** Whether to prefer OCSP over CRL (default: true) */
    preferOCSP?: boolean;
}
