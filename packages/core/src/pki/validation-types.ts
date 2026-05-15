import * as pkijs from "pkijs";

/**
 * Represents a single certificate requiring validation
 */
export interface CertificateToValidate {
    /** The certificate to check */
    cert: pkijs.Certificate;
    /** Expected issuer (if known) */
    issuer?: pkijs.Certificate;
}

/**
 * Result of validating a single certificate
 */
export interface ValidationResult {
    /** Certificate that was validated */
    cert: pkijs.Certificate;
    /** Whether certificate is valid */
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
