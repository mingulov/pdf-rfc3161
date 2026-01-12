import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { CircuitBreakerMap, CircuitState, CircuitBreakerError } from "../utils/circuit-breaker.js";
import { getLogger } from "../utils/logger.js";

/**
 * CRL Extension OIDs
 */
const CRL_NUMBER_OID = "2.5.29.20"; // CRL Number
const DELTA_CRL_INDICATOR = "2.5.29.27"; // Delta CRL Indicator

/**
 * Parsed CRL information
 */
export interface CRLInfo {
    /** DER-encoded CRL bytes */
    crl: Uint8Array;
    /** Whether this is a delta-CRL */
    isDelta: boolean;
    /** CRL number if present */
    crlNumber?: number;
    /** Delta CRL number if present */
    deltaCrlNumber?: number;
}

/**
 * Determines if a CRL is a delta-CRL and extracts CRL numbers.
 *
 * @param crlBytes - DER-encoded CRL
 * @returns CRLInfo with delta status and CRL numbers
 */
export function parseCRLInfo(crlBytes: Uint8Array): CRLInfo {
    try {
        const asn1 = asn1js.fromBER(crlBytes.slice().buffer);
        if (asn1.offset === -1) {
            return { crl: crlBytes, isDelta: false };
        }

        const crl = new pkijs.CertificateRevocationList({ schema: asn1.result });

        let isDelta = false;
        let crlNumber: number | undefined;
        let deltaCrlNumber: number | undefined;

        // Check for extensions using crlExtensions
        const extensions = (crl as { crlExtensions?: pkijs.Extension[] }).crlExtensions;
        if (extensions) {
            for (const ext of extensions) {
                if (ext.extnID === DELTA_CRL_INDICATOR) {
                    isDelta = true;
                }
                if (ext.extnID === CRL_NUMBER_OID) {
                    // CRL Number is an integer - just note it exists
                    crlNumber = 1; // Placeholder - real parsing needs careful type handling
                }
            }
        }

        return {
            crl: crlBytes,
            isDelta,
            crlNumber,
            deltaCrlNumber,
        };
    } catch {
        return { crl: crlBytes, isDelta: false };
    }
}

/**
 * Fetches a CRL (Certificate Revocation List) from a URL.
 *
 * @param url - The CRL URL
 * @param options - Optional parameters for delta-CRL support
 * @returns The DER-encoded CRL bytes
 */
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1000; // CRLs are bigger/slower, allow more time between retries

/**
 * Shared circuit breaker map for CRL distribution points.
 * Tracks failures per-URL to prevent cascade failures.
 */
const crlCircuitBreakers = new CircuitBreakerMap({
    failureThreshold: 3,
    resetTimeoutMs: 120000, // 2 minutes for CRLs (they're more stable)
});

/**
 * Fetches a CRL (Certificate Revocation List) from a URL.
 *
 * @param url - The CRL URL
 * @param options - Optional parameters for delta-CRL support
 * @returns The DER-encoded CRL bytes
 */
export async function fetchCRL(
    url: string,
    options?: { fetchDeltaIfAvailable?: boolean }
): Promise<Uint8Array> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        // CRLs can be large, give them more time
        const timeoutMs = 15000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, timeoutMs);

        try {
            // Check circuit breaker state before making request
            const state = crlCircuitBreakers.getState(url);
            if (state === CircuitState.OPEN) {
                throw new CircuitBreakerError(
                    `Circuit breaker is OPEN for ${url}. Service may be down.`,
                    state
                );
            }

            const response = await fetch(url, {
                method: "GET",
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // Retry 5xx errors
                if (response.status >= 500) {
                    throw new Error(`HTTP ${String(response.status)}: ${response.statusText}`);
                }
                throw new TimestampError(
                    TimestampErrorCode.NETWORK_ERROR,
                    `CRL server returned HTTP ${String(response.status)}: ${response.statusText}`
                );
            }

            const arrayBuffer = await response.arrayBuffer();
            const responseBytes = new Uint8Array(arrayBuffer);

            if (responseBytes.length === 0) {
                throw new TimestampError(TimestampErrorCode.INVALID_RESPONSE, "Empty CRL received");
            }

            // Check if this is a delta-CRL
            if (options?.fetchDeltaIfAvailable) {
                const crlInfo = parseCRLInfo(responseBytes);
                if (crlInfo.isDelta && crlInfo.deltaCrlNumber) {
                    // TODO: Implement full delta-CRL merging with base CRL
                    // For now, we just return the delta-CRL and log a warning
                    // TODO: Implement full Delta CRL merging.
                    // Currently, we return the Delta CRL as-is. Consumers must handle merging relative to a Base CRL.
                    getLogger().warn(
                        `Delta-CRL received (delta number: ${String(crlInfo.deltaCrlNumber)}). ` +
                            "Full delta-CRL merging with base CRL is not yet implemented. Returning delta bytes for embedding."
                    );
                }
            }

            // Record successful response to potentially reset circuit breaker from HALF_OPEN to CLOSED
            crlCircuitBreakers.recordSuccess(url);

            return responseBytes;
        } catch (error) {
            clearTimeout(timeoutId);
            lastError = error;

            if (attempt < MAX_RETRIES) {
                const delay = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
                await new Promise((resolve) => setTimeout(resolve, delay));
                continue;
            }
        }
    }

    if (lastError instanceof TimestampError) {
        throw lastError;
    }

    if (lastError instanceof CircuitBreakerError) {
        throw lastError;
    }

    throw new TimestampError(
        TimestampErrorCode.NETWORK_ERROR,
        `Failed to fetch CRL from ${url} after ${String(MAX_RETRIES + 1)} attempts`,
        lastError
    );
}

/**
 * Get the circuit breaker state for a CRL URL
 * Useful for monitoring/debugging
 */
export function getCRLCircuitState(url: string): CircuitState | undefined {
    return crlCircuitBreakers.getState(url);
}

/**
 * Reset all CRL circuit breakers
 * Useful for testing or after service recovery
 */
export function resetCRLCircuits(): void {
    crlCircuitBreakers.reset();
}
