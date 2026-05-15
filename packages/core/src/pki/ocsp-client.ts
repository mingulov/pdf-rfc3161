import { CircuitBreakerMap, CircuitState } from "../utils/circuit-breaker.js";
import { fetchBytesWithRetry } from "../utils/fetch-with-retry.js";
import { DEFAULT_OCSP_CONFIG } from "../constants.js";

/**
 * Shared circuit breaker map for OCSP responders.
 * Tracks failures per-URL to prevent cascade failures.
 */
const ocspCircuitBreakers = new CircuitBreakerMap({
    failureThreshold: 3,
    resetTimeoutMs: DEFAULT_OCSP_CONFIG.resetTimeoutMs,
});

/**
 * Fetches an OCSP response from a responder URL.
 *
 * @param url - The OCSP Responder URL
 * @param request - The DER-encoded OCSP Request
 * @returns The DER-encoded OCSP Response
 */
export async function fetchOCSPResponse(url: string, request: Uint8Array): Promise<Uint8Array> {
    return fetchBytesWithRetry({
        url,
        method: "POST",
        headers: { "Content-Type": "application/ocsp-request" },
        body: request as unknown as BodyInit,
        config: DEFAULT_OCSP_CONFIG,
        circuitBreakers: ocspCircuitBreakers,
        serviceLabel: "OCSP responder",
    });
}

/**
 * Get the circuit breaker state for an OCSP URL.
 * Useful for monitoring/debugging.
 */
export function getOCSPCircuitState(url: string): CircuitState | undefined {
    return ocspCircuitBreakers.getState(url);
}

/**
 * Reset all OCSP circuit breakers.
 * Useful for testing or after service recovery.
 */
export function resetOCSPCircuits(): void {
    ocspCircuitBreakers.reset();
}
