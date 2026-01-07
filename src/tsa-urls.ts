/**
 * Known TSA (Time Stamping Authority) server URLs.
 *
 * This constant provides a curated list of known TSA server endpoints.
 * Usage of these services is governed by the respective providers' Terms of Service.
 *
 * All servers listed in the main section use certificates that chain to well-known CAs
 * included in standard system trust stores.
 *
 * @example
 * ```typescript
 * import { timestampPdf, KNOWN_TSA_URLS } from 'pdf-rfc3161';
 *
 * const result = await timestampPdf({
 *   pdf: pdfBytes,
 *   tsa: { url: KNOWN_TSA_URLS.DIGICERT },
 * });
 * ```
 */
export const KNOWN_TSA_URLS = {
    // Commercial TSA servers
    /**
     * DigiCert TSA - widely trusted.
     * Note: Public endpoint currently supports HTTP only.
     */
    DIGICERT: "http://timestamp.digicert.com",
    /**
     * Sectigo TSA - commercial, reliable.
     * Note: Requires 15s+ delay between requests when scripting.
     */
    SECTIGO: "https://timestamp.sectigo.com",
    /** Comodo TSA - Sectigo's legacy endpoint (HTTP only) */
    COMODO: "http://timestamp.comodoca.com",
    /** GlobalSign TSA - commercial (HTTP only) */
    GLOBALSIGN: "http://timestamp.globalsign.com/tsa/r6advanced1",
    /** Entrust TSA - commercial (HTTP only) */
    ENTRUST: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
    /** QuoVadis TSA - EU eIDAS (HTTP only) */
    QUOVADIS: "http://ts.quovadisglobal.com/eu",

    // Free/community TSA servers (may have rate limits or self-signed CAs)
    /** FreeTSA.org - free community TSA, uses self-signed CA */
    FREETSA: "https://freetsa.org/tsr",
    /**
     * CodeGic TSA - public test timestamp server.
     * Note: For integration testing only; not for production use.
     */
    CODEGIC: "http://pki.codegic.com/codegic-service/timestamp",
} as const;

/**
 * Type representing the keys of KNOWN_TSA_URLS
 */
export type KnownTSAName = keyof typeof KNOWN_TSA_URLS;

/**
 * Type representing a URL from KNOWN_TSA_URLS
 */
export type KnownTSAUrl = (typeof KNOWN_TSA_URLS)[KnownTSAName];
