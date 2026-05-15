import type { RevocationDataFetcher } from "../validation-types.js";
import { fetchBytesWithRetry } from "../../utils/fetch-with-retry.js";
import { DEFAULT_OCSP_CONFIG, DEFAULT_CRL_CONFIG } from "../../constants.js";

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 500;

/**
 * Default fetcher using the Web Fetch API.
 * Suitable for browsers, Cloudflare Workers, Deno, and modern Node.js.
 */
export class DefaultFetcher implements RevocationDataFetcher {
    private timeout: number;
    private maxRetries: number;

    constructor(options: { timeout?: number; maxRetries?: number } = {}) {
        this.timeout = options.timeout ?? DEFAULT_TIMEOUT_MS;
        this.maxRetries = options.maxRetries ?? MAX_RETRIES;
    }

    async fetchOCSP(url: string, request: Uint8Array): Promise<Uint8Array> {
        return fetchBytesWithRetry({
            url,
            method: "POST",
            headers: { "Content-Type": "application/ocsp-request" },
            body: request as unknown as BodyInit,
            config: {
                retry: this.maxRetries,
                retryDelay: INITIAL_BACKOFF_MS,
                timeout: this.timeout,
                maxResponseBytes: DEFAULT_OCSP_CONFIG.maxResponseBytes,
            },
            serviceLabel: "OCSP responder",
        });
    }

    async fetchCRL(url: string): Promise<Uint8Array> {
        return fetchBytesWithRetry({
            url,
            method: "GET",
            config: {
                retry: this.maxRetries,
                retryDelay: INITIAL_BACKOFF_MS,
                timeout: this.timeout,
                maxResponseBytes: DEFAULT_CRL_CONFIG.maxResponseBytes,
            },
            serviceLabel: "CRL server",
        });
    }
}
