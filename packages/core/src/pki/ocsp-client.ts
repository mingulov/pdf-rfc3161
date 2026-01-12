import { TimestampError, TimestampErrorCode } from "../types.js";
import { CircuitBreakerMap, CircuitState, CircuitBreakerError } from "../utils/circuit-breaker.js";

/**
 * Fetches an OCSP response from a responder URL.
 *
 * @param url - The OCSP Responder URL
 * @param request - The DER-encoded OCSP Request
 * @returns The DER-encoded OCSP Response
 */
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 500;

/**
 * Shared circuit breaker map for OCSP responders.
 * Tracks failures per-URL to prevent cascade failures.
 */
const ocspCircuitBreakers = new CircuitBreakerMap({
    failureThreshold: 3,
    resetTimeoutMs: 60000, // 1 minute
});

/**
 * Fetches an OCSP response from a responder URL.
 *
 * @param url - The OCSP Responder URL
 * @param request - The DER-encoded OCSP Request
 * @returns The DER-encoded OCSP Response
 */
export async function fetchOCSPResponse(url: string, request: Uint8Array): Promise<Uint8Array> {
    let lastError: unknown;

    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, 5000);

        try {
            // Check circuit breaker state before making request
            const state = ocspCircuitBreakers.getState(url);
            if (state === CircuitState.OPEN) {
                throw new CircuitBreakerError(
                    `Circuit breaker is OPEN for ${url}. Service may be down.`,
                    state
                );
            }

            const response = await fetch(url, {
                method: "POST",
                headers: {
                    "Content-Type": "application/ocsp-request",
                },
                body: request as unknown as BodyInit,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // If 5xx error, retry. If 4xx, likely fatal.
                if (response.status >= 500) {
                    throw new Error(`HTTP ${String(response.status)}: ${response.statusText}`);
                }
                throw new TimestampError(
                    TimestampErrorCode.NETWORK_ERROR,
                    `OCSP responder returned HTTP ${String(response.status)}: ${response.statusText}`
                );
            }

            const arrayBuffer = await response.arrayBuffer();
            const responseBytes = new Uint8Array(arrayBuffer);

            if (responseBytes.length === 0) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "Empty OCSP response received"
                );
            }

            // Record successful response to potentially reset circuit breaker from HALF_OPEN to CLOSED
            ocspCircuitBreakers.recordSuccess(url);

            return responseBytes;
        } catch (error) {
            clearTimeout(timeoutId);
            lastError = error;

            // Don't retry on abort/timeout unless we decide that timeouts ARE temporary
            // Generally timeouts are worth retrying

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
        `Failed to fetch OCSP response after ${String(MAX_RETRIES + 1)} attempts`,
        lastError
    );
}

/**
 * Get the circuit breaker state for an OCSP URL
 * Useful for monitoring/debugging
 */
export function getOCSPCircuitState(url: string): CircuitState | undefined {
    return ocspCircuitBreakers.getState(url);
}

/**
 * Reset all OCSP circuit breakers
 * Useful for testing or after service recovery
 */
export function resetOCSPCircuits(): void {
    ocspCircuitBreakers.reset();
}
