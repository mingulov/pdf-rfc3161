import {
    TSA_CONTENT_TYPE,
    DEFAULT_TSA_CONFIG,
    DEFAULT_TSA_MAX_RESPONSE_BYTES,
} from "../constants.js";
import { type TSAConfig } from "../types.js";
import { getLogger } from "../utils/logger.js";
import { fetchBytesWithRetry } from "../utils/fetch-with-retry.js";

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
    return fetchBytesWithRetry({
        url: config.url,
        method: "POST",
        headers: {
            "Content-Type": TSA_CONTENT_TYPE.REQUEST,
            ...config.headers,
        },
        // Copy into a fresh ArrayBuffer (not SharedArrayBuffer).
        body: new Uint8Array(request).buffer,
        config: {
            retry: config.retry ?? DEFAULT_TSA_CONFIG.retry,
            retryDelay: config.retryDelay ?? DEFAULT_TSA_CONFIG.retryDelay,
            timeout: config.timeout ?? DEFAULT_TSA_CONFIG.timeout,
            maxResponseBytes: DEFAULT_TSA_MAX_RESPONSE_BYTES,
        },
        serviceLabel: "TSA",
        // Some TSAs return generic content types (e.g. application/octet-stream).
        // Warn but don't reject -- relying on this would break too many TSAs.
        validateBytes: (_bytes, response) => {
            const contentType = response.headers.get("content-type");
            if (contentType && !contentType.includes(TSA_CONTENT_TYPE.RESPONSE)) {
                getLogger().warn(
                    `TSA returned unexpected content-type: ${contentType}, expected ${TSA_CONTENT_TYPE.RESPONSE}`
                );
            }
        },
    });
}
