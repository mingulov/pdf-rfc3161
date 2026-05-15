import { TimestampError, TimestampErrorCode } from "../types.js";
import {
    CircuitBreakerError,
    CircuitState,
    type CircuitBreakerMap,
} from "./circuit-breaker.js";
import { validateUrl } from "./url.js";
import { readResponseBounded } from "./bounded-fetch.js";

/**
 * Per-call retry / timeout / size-cap configuration.
 */
export interface FetchWithRetryConfig {
    /** Total number of retry attempts after the initial one (so total attempts = retry + 1). */
    retry: number;
    /** Initial backoff in ms; doubles each subsequent retry. */
    retryDelay: number;
    /** Per-attempt timeout in ms; aborts the in-flight fetch. */
    timeout: number;
    /** Maximum allowed response body size in bytes; H5 cap. */
    maxResponseBytes: number;
}

/**
 * Inputs for one fetchBytesWithRetry call.
 */
export interface FetchWithRetryOptions {
    url: string;
    method: "GET" | "POST";
    headers?: Record<string, string>;
    body?: BodyInit;
    config: FetchWithRetryConfig;
    /**
     * Optional per-URL circuit-breaker map. When supplied, the helper:
     *   1. Short-circuits with CircuitBreakerError if the URL is OPEN.
     *   2. Records success on a non-retryable response.
     *   3. Records failure when all retries exhaust.
     */
    circuitBreakers?: CircuitBreakerMap;
    /**
     * Label used in error messages, e.g. "OCSP responder", "TSA". Falls
     * back to "service" when omitted.
     */
    serviceLabel?: string;
    /**
     * Optional caller-side validator that runs after the bytes are read
     * and the response is otherwise OK. Throw a TimestampError to
     * reject; throw any other Error and we'll wrap it.
     */
    validateBytes?: (bytes: Uint8Array, response: Response) => void;
}

/**
 * Shared HTTP-with-retry shell used by TSA / OCSP / CRL / cert / fetcher
 * clients (L4 from REVIEW-2026-02-09). Wraps:
 *
 *   - validateUrl (H4)
 *   - per-attempt AbortController timeout
 *   - optional circuit breaker (CLOSED -> OPEN -> HALF_OPEN)
 *   - HTTP-status classification: 5xx -> retry, 4xx -> hard fail,
 *     2xx -> success
 *   - readResponseBounded (H5)
 *   - exponential backoff between attempts
 *   - empty-body rejection
 *
 * Returns the response bytes on success. Throws TimestampError or
 * CircuitBreakerError on failure -- never the underlying fetch error
 * directly.
 */
export async function fetchBytesWithRetry(options: FetchWithRetryOptions): Promise<Uint8Array> {
    const { url, method, headers, body, config, circuitBreakers, validateBytes } = options;
    const serviceLabel = options.serviceLabel ?? "service";

    // H4: validate once up-front so a bad URL fails fast instead of consuming
    // the full retry budget.
    validateUrl(url);

    let lastError: unknown;

    for (let attempt = 0; attempt <= config.retry; attempt++) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, config.timeout);

        try {
            if (circuitBreakers) {
                const state = circuitBreakers.getState(url);
                if (state === CircuitState.OPEN) {
                    throw new CircuitBreakerError(
                        `Circuit breaker is OPEN for ${url}. Service may be down.`,
                        state
                    );
                }
            }

            const response = await fetch(url, {
                method,
                headers,
                body,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // 5xx -> transient -> retry. Plain Error is used as the
                // retry-signal here: the surrounding loop catches it and tries
                // again with backoff. A TimestampError would short-circuit.
                if (response.status >= 500) {
                    throw new Error(
                        `HTTP ${String(response.status)}: ${response.statusText}`
                    );
                }
                // 4xx -> hard fail
                throw new TimestampError(
                    TimestampErrorCode.NETWORK_ERROR,
                    `${serviceLabel} returned HTTP ${String(response.status)}: ${response.statusText}`
                );
            }

            const responseBytes = await readResponseBounded(response, config.maxResponseBytes);

            if (responseBytes.length === 0) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    `${serviceLabel} returned empty response`
                );
            }

            if (validateBytes) {
                validateBytes(responseBytes, response);
            }

            circuitBreakers?.recordSuccess(url);
            return responseBytes;
        } catch (error) {
            clearTimeout(timeoutId);
            lastError = error;

            if (attempt < config.retry) {
                const delay = config.retryDelay * Math.pow(2, attempt);
                await new Promise((resolve) => setTimeout(resolve, delay));
                continue;
            }

            // Final attempt failed. Record failure unless the error was
            // already the circuit breaker short-circuiting (don't double-count).
            if (circuitBreakers && !(error instanceof CircuitBreakerError)) {
                circuitBreakers.recordFailure(url);
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
        `Failed to fetch from ${serviceLabel} (${url}) after ${String(config.retry + 1)} attempts`,
        lastError
    );
}
