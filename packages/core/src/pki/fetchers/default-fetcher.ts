import { TimestampError, TimestampErrorCode } from "../../types.js";
import type { RevocationDataFetcher } from "../validation-types.js";

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
        let lastError: unknown;

        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => {
                controller.abort();
            }, this.timeout);

            try {
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

                return responseBytes;
            } catch (error) {
                clearTimeout(timeoutId);
                lastError = error;

                if (attempt < this.maxRetries) {
                    const delay = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
                    await new Promise((resolve) => setTimeout(resolve, delay));
                    continue;
                }
            }
        }

        if (lastError instanceof TimestampError) {
            throw lastError;
        }

        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Failed to fetch OCSP response after ${String(this.maxRetries + 1)} attempts`,
            lastError
        );
    }

    async fetchCRL(url: string): Promise<Uint8Array> {
        let lastError: unknown;

        for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => {
                controller.abort();
            }, this.timeout);

            try {
                const response = await fetch(url, {
                    method: "GET",
                    signal: controller.signal,
                });

                clearTimeout(timeoutId);

                if (!response.ok) {
                    if (response.status >= 500) {
                        throw new Error(`HTTP ${String(response.status)}: ${response.statusText}`);
                    }
                    throw new TimestampError(
                        TimestampErrorCode.NETWORK_ERROR,
                        `CRL server returned HTTP ${String(response.status)}: ${response.statusText}`
                    );
                }

                const arrayBuffer = await response.arrayBuffer();
                const responseBytes = new Uint8Array(arrayBuffer);

                if (responseBytes.length === 0) {
                    throw new TimestampError(
                        TimestampErrorCode.INVALID_RESPONSE,
                        "Empty CRL received"
                    );
                }

                return responseBytes;
            } catch (error) {
                clearTimeout(timeoutId);
                lastError = error;

                if (attempt < this.maxRetries) {
                    const delay = INITIAL_BACKOFF_MS * Math.pow(2, attempt);
                    await new Promise((resolve) => setTimeout(resolve, delay));
                    continue;
                }
            }
        }

        if (lastError instanceof TimestampError) {
            throw lastError;
        }

        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Failed to fetch CRL from ${url} after ${String(this.maxRetries + 1)} attempts`,
            lastError
        );
    }
}
