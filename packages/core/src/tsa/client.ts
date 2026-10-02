import {
    TSA_CONTENT_TYPE,
    DEFAULT_TSA_CONFIG,
    DEFAULT_TSA_MAX_RESPONSE_BYTES,
} from "../constants.js";
import { type TSAConfig } from "../types.js";
import { getLogger } from "../utils/logger.js";
import { formatDiagnosticUrl } from "../utils/url.js";
import { fetchBytesWithRetry } from "../utils/fetch-with-retry.js";

/**
 * Sends a timestamp request to a TSA server and returns the response.
 *
 * This function uses the Fetch API which is available in:
 * - Modern browsers
 * - Node.js 22.12.0+
 * - Cloudflare Workers
 * - Deno
 * - Vercel Edge Runtime
 *
 * @param request - The DER-encoded TimeStampReq
 * @param config - TSA configuration
 * @returns The DER-encoded TimeStampResp
 * @throws TimestampError on network or protocol errors
 */
/**
 * Loopback check for the plain-HTTP warning only: loopback traffic never
 * leaves the host, so there is nothing network-visible to warn about.
 * `*.localhost` resolves to loopback (RFC 6761, secure-context
 * treatment); private-network addresses (RFC 1918 etc.) still warn.
 * Unparseable input is not loopback.
 */
function isLoopbackHttpTarget(urlString: string): boolean {
    let hostname: string;
    try {
        hostname = new URL(urlString).hostname.toLowerCase();
    } catch {
        return false;
    }
    if (hostname.endsWith(".")) hostname = hostname.slice(0, -1);
    if (hostname === "localhost" || hostname.endsWith(".localhost")) return true;
    if (hostname === "::1" || hostname === "[::1]") return true;
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function isPlainHttp(urlString: string): boolean {
    try {
        return new URL(urlString).protocol === "http:";
    } catch {
        return true;
    }
}

export async function sendTimestampRequest(
    request: Uint8Array,
    config: TSAConfig
): Promise<Uint8Array> {
    // Plain-HTTP requests are readable on the network; warn once per
    // operation (retries do not re-warn), except for loopback targets.
    // This says nothing about token authentication, which verification
    // handles independently.
    if (isPlainHttp(config.url) && !isLoopbackHttpTarget(config.url)) {
        getLogger().warn(`TSA request uses plain HTTP: ${formatDiagnosticUrl(config.url)}`);
    }
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
