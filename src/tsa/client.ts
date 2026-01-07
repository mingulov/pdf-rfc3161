import { TSA_CONTENT_TYPE, DEFAULT_TSA_CONFIG } from "../constants.js";
import { TimestampError, TimestampErrorCode, type TSAConfig } from "../types.js";

/**
 * Sends a timestamp request to a TSA server and returns the response.
 *
 * This function uses the Fetch API which is available in:
 * - Modern browsers
 * - Node.js 18+
 * - Cloudflare Workers
 * - Deno
 * - Vercel Edge Runtime
 *
 * @param request - The DER-encoded TimeStampReq
 * @param config - TSA configuration
 * @returns The DER-encoded TimeStampResp
 * @throws TimestampError on network or protocol errors
 */
export async function sendTimestampRequest(
    request: Uint8Array,
    config: TSAConfig
): Promise<Uint8Array> {
    const timeout = config.timeout ?? DEFAULT_TSA_CONFIG.timeout;
    const maxRetries = config.retry ?? DEFAULT_TSA_CONFIG.retry;
    const baseDelay = config.retryDelay ?? DEFAULT_TSA_CONFIG.retryDelay;

    let lastError: unknown;

    for (let attempt = 0; attempt <= maxRetries; attempt++) {
        // Create abort controller for timeout
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, timeout);

        try {
            const response = await fetch(config.url, {
                method: "POST",
                headers: {
                    "Content-Type": TSA_CONTENT_TYPE.REQUEST,
                    ...config.headers,
                },
                // Create a copy to get a plain ArrayBuffer (not SharedArrayBuffer)
                body: new Uint8Array(request).buffer,
                signal: controller.signal,
            });

            clearTimeout(timeoutId);

            if (!response.ok) {
                // If it's a 5xx error, we might want to retry
                if (response.status >= 500 && attempt < maxRetries) {
                    throw new TimestampError(
                        TimestampErrorCode.TSA_ERROR,
                        `TSA returned HTTP status ${response.status.toString()}: ${response.statusText}`
                    );
                }

                // For 4xx errors, retrying usually doesn't help unless it's 429 (Too Many Requests)
                if (response.status === 429 && attempt < maxRetries) {
                    throw new TimestampError(
                        TimestampErrorCode.TSA_ERROR,
                        `TSA returned HTTP status ${response.status.toString()}: ${response.statusText}`
                    );
                }

                throw new TimestampError(
                    TimestampErrorCode.TSA_ERROR,
                    `TSA returned HTTP status ${response.status.toString()}: ${response.statusText}`
                );
            }

            // Validate content type
            const contentType = response.headers.get("content-type");
            if (contentType && !contentType.includes(TSA_CONTENT_TYPE.RESPONSE)) {
                // Some TSAs return generic content types, so just warn but continue
                console.warn(
                    `TSA returned unexpected content-type: ${contentType}, expected ${TSA_CONTENT_TYPE.RESPONSE}`
                );
            }

            const responseBuffer = await response.arrayBuffer();
            return new Uint8Array(responseBuffer);
        } catch (error) {
            clearTimeout(timeoutId);
            lastError = error;

            // Determine if we should retry

            // If it's the last attempt, don't wait, just loop to throw
            if (attempt === maxRetries) {
                break;
            }

            // Calculate delay: base * 2^attempt (exponential backoff)
            const delay = baseDelay * Math.pow(2, attempt);

            // Log retry (could be optional or verbose only)
            // console.debug(`TSA request failed (attempt ${attempt + 1}/${maxRetries + 1}), retrying in ${delay}ms...`, error);

            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }

    // If we're here, we failed all attempts
    if (lastError instanceof TimestampError) {
        throw lastError;
    }

    if (lastError instanceof Error) {
        if (lastError.name === "AbortError") {
            throw new TimestampError(
                TimestampErrorCode.TIMEOUT,
                `TSA request timed out after ${timeout.toString()}ms (${(maxRetries + 1).toString()} attempts)`
            );
        }

        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Network error communicating with TSA: ${lastError.message}`,
            lastError
        );
    }

    throw new TimestampError(
        TimestampErrorCode.NETWORK_ERROR,
        `Unknown error communicating with TSA: ${String(lastError)}`,
        lastError
    );
}
