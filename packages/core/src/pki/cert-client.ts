import { TimestampError, TimestampErrorCode } from "../types.js";
import { CircuitBreakerMap, CircuitState, CircuitBreakerError } from "../utils/circuit-breaker.js";
import { getLogger } from "../utils/logger.js";

const MAX_RETRIES = 2;
const INITIAL_BACKOFF_MS = 500;

/**
 * Shared circuit breaker map for Certificate URLs.
 */
const certCircuitBreakers = new CircuitBreakerMap({
    failureThreshold: 3,
    resetTimeoutMs: 60000,
});

/**
 * Fetches a Certificate from a URL (AIA).
 *
 * @param url - The Certificate URL (usually .cer or .crt, DER or PEM)
 * @returns The certificate bytes
 */
export async function fetchCertificate(url: string): Promise<Uint8Array> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const timeoutMs = 10000;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, timeoutMs);

        try {
            const state = certCircuitBreakers.getState(url);
            if (state === CircuitState.OPEN) {
                throw new CircuitBreakerError(`Circuit breaker is OPEN for ${url}`, state);
            }

            const response = await fetch(url, {
                method: "GET",
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                if (response.status >= 500) {
                    throw new Error(`HTTP ${String(response.status)}`);
                }
                const msg = `Cert server returned HTTP ${String(response.status)}`;
                getLogger().warn(`[Cert-Client] ${msg}`);
                throw new TimestampError(TimestampErrorCode.NETWORK_ERROR, msg);
            }

            const arrayBuffer = await response.arrayBuffer();
            const responseBytes = new Uint8Array(arrayBuffer);

            if (responseBytes.length === 0) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "Empty certificate received"
                );
            }

            // Check content-type? optional.
            // Often "application/pkix-cert" or "application/x-x509-ca-cert"

            certCircuitBreakers.recordSuccess(url);
            return responseBytes;
        } catch (error) {
            clearTimeout(timeoutId);
            lastError = error;

            if (attempt < MAX_RETRIES) {
                const delay = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
                await new Promise((resolve) => setTimeout(resolve, delay));
                continue;
            }

            // Record failure only on final attempt or if it's a hard error
            certCircuitBreakers.recordFailure(url);
        }
    }

    if (lastError instanceof TimestampError || lastError instanceof CircuitBreakerError) {
        throw lastError;
    }

    throw new TimestampError(
        TimestampErrorCode.NETWORK_ERROR,
        `Failed to fetch Certificate from ${url}`,
        lastError
    );
}

export function getCertCircuitState(url: string): CircuitState | undefined {
    return certCircuitBreakers.getState(url);
}

export function resetCertCircuits(): void {
    certCircuitBreakers.reset();
}
