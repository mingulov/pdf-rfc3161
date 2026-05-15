import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { CircuitBreakerMap, CircuitState } from "../utils/circuit-breaker.js";
import { fetchBytesWithRetry } from "../utils/fetch-with-retry.js";
import { getLogger } from "../utils/logger.js";
import { DEFAULT_CRL_CONFIG } from "../constants.js";
import { toArrayBuffer } from "../utils.js";

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
        const asn1 = asn1js.fromBER(toArrayBuffer(crlBytes));
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
                try {
                    if (ext.extnID === DELTA_CRL_INDICATOR) {
                        isDelta = true;
                        // Delta CRL Indicator contains the Base CRL Number (Integer)
                        const extAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
                        if (extAsn1.result instanceof asn1js.Integer) {
                            deltaCrlNumber = extAsn1.result.valueBlock.valueDec;
                        }
                    }
                    if (ext.extnID === CRL_NUMBER_OID) {
                        // CRL Number is an Integer
                        const extAsn1 = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
                        if (extAsn1.result instanceof asn1js.Integer) {
                            crlNumber = extAsn1.result.valueBlock.valueDec;
                        }
                    }
                } catch {
                    // Ignore parsing errors for individual extensions
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
 * Shared circuit breaker map for CRL distribution points.
 * Tracks failures per-URL to prevent cascade failures.
 */
const crlCircuitBreakers = new CircuitBreakerMap({
    failureThreshold: 3,
    resetTimeoutMs: DEFAULT_CRL_CONFIG.resetTimeoutMs, // 2 minutes for CRLs (they're more stable)
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
    return fetchBytesWithRetry({
        url,
        method: "GET",
        config: DEFAULT_CRL_CONFIG,
        circuitBreakers: crlCircuitBreakers,
        serviceLabel: "CRL server",
        validateBytes: (bytes) => {
            if (options?.fetchDeltaIfAvailable) {
                const crlInfo = parseCRLInfo(bytes);
                if (crlInfo.isDelta) {
                    // TODO: Implement full delta-CRL merging with base CRL.
                    // Currently, we return the Delta CRL as-is. Consumers must handle merging.
                    getLogger().warn(
                        `Delta-CRL received (delta number: ${String(crlInfo.crlNumber ?? "unknown")}, base CRL number: ${String(crlInfo.deltaCrlNumber ?? "unknown")}). ` +
                            "Full delta-CRL merging with base CRL is not yet implemented. Returning delta bytes for embedding."
                    );
                }
            }
        },
    });
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
