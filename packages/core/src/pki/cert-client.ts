import { CircuitBreakerMap, CircuitState } from "../utils/circuit-breaker.js";
import { fetchBytesWithRetry } from "../utils/fetch-with-retry.js";
import { DEFAULT_CERT_CONFIG } from "../constants.js";

/**
 * Shared circuit breaker map for Certificate URLs.
 */
const certCircuitBreakers = new CircuitBreakerMap({
    failureThreshold: 3,
    resetTimeoutMs: DEFAULT_CERT_CONFIG.resetTimeoutMs,
});

/**
 * Fetches a Certificate from a URL (AIA).
 *
 * @param url - The Certificate URL (usually .cer or .crt, DER or PEM)
 * @returns The certificate bytes
 */
export async function fetchCertificate(url: string): Promise<Uint8Array> {
    return fetchBytesWithRetry({
        url,
        method: "GET",
        config: DEFAULT_CERT_CONFIG,
        circuitBreakers: certCircuitBreakers,
        serviceLabel: "Cert server",
    });
}

/**
 * Returns the current circuit-breaker state for the given AIA URL, or
 * `undefined` if the URL has not been queried yet in this process.
 */
export function getCertCircuitState(url: string): CircuitState | undefined {
    return certCircuitBreakers.getState(url);
}

/**
 * Resets all per-URL certificate-fetch circuit breakers. Useful in tests, or
 * after a known transient outage when you want subsequent retries to be tried
 * immediately rather than waiting for the cooldown to elapse.
 */
export function resetCertCircuits(): void {
    certCircuitBreakers.reset();
}
