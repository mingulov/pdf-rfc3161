import type { RevocationDataFetcher, RevocationFetchContext } from "../validation-types.js";
import { fetchBytesWithRetry } from "../../utils/fetch-with-retry.js";
import { fetchOCSPResponse } from "../ocsp-client.js";
import { fetchCRL } from "../crl-client.js";
import { DEFAULT_OCSP_CONFIG, DEFAULT_CRL_CONFIG } from "../../constants.js";
import type { OperationBudget } from "../../utils/operation-budget.js";

const DEFAULT_TIMEOUT_MS = 5000;
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 500;

/**
 * Default fetcher using the Web Fetch API.
 * Suitable for browsers, Cloudflare Workers, Deno, and modern Node.js.
 *
 * With default options both methods share the OCSP/CRL clients' default
 * transport policy (including their singleton breaker maps); that moves
 * the default CRL per-attempt timeout from 5 s to the client's 15 s and
 * its backoff from 500 ms to 1 s. Explicit timeout/maxRetries keep the
 * historical direct policy instead.
 */
export class DefaultFetcher implements RevocationDataFetcher {
    private readonly timeout: number | undefined;
    private readonly maxRetries: number | undefined;

    constructor(options: { timeout?: number; maxRetries?: number } = {}) {
        this.timeout = options.timeout;
        this.maxRetries = options.maxRetries;
    }

    async fetchOCSP(
        url: string,
        request: Uint8Array,
        context?: RevocationFetchContext
    ): Promise<Uint8Array> {
        return this.fetchOCSPInner(url, request, { signal: context?.signal });
    }

    /**
     * Built-in OCSP fetch with the completion's budget threaded into the
     * retry shell, so every physical attempt (retries included) and every
     * received chunk is counted.
     *
     * Deliberately spoofing this entry from caller-own code (a fake
     * fetchOCSPWithBudget on a foreign fetcher) is self-sabotage that
     * gains nothing: caller I/O is already unboundable by documented
     * design, and only the caller's own bytes would flow through it.
     *
     * @internal For ValidationSession's capability dispatch only. Not part
     * of the public fetcher contract.
     */
    async fetchOCSPWithBudget(
        url: string,
        request: Uint8Array,
        budget: OperationBudget
    ): Promise<Uint8Array> {
        // Same-realm override self-check: a subclass overriding fetchOCSP
        // is caller I/O, not built-in transport, so it falls back to the
        // custom path itself (one attempt, return bytes counted, the
        // override invoked with a fresh signal-only context), exactly as
        // if the session had dispatched there. The comparison is against
        // this realm's prototype, so it holds across the supported
        // ESM/CJS mixing where constructor identity differs.
        if (this.fetchOCSP !== DefaultFetcher.prototype.fetchOCSP) {
            return budget.countCustomFetch(
                "OCSP",
                DEFAULT_OCSP_CONFIG.maxResponseBytes,
                ({ signal }) => this.fetchOCSP(url, request, { signal })
            );
        }
        return this.fetchOCSPInner(url, request, { signal: budget.signal, budget });
    }

    private async fetchOCSPInner(
        url: string,
        request: Uint8Array,
        options: { signal?: AbortSignal; budget?: OperationBudget }
    ): Promise<Uint8Array> {
        if (this.timeout === undefined && this.maxRetries === undefined) {
            return fetchOCSPResponse(url, request, options);
        }
        return fetchBytesWithRetry({
            url,
            method: "POST",
            headers: { "Content-Type": "application/ocsp-request" },
            body: request as unknown as BodyInit,
            config: {
                retry: this.maxRetries ?? MAX_RETRIES,
                retryDelay: INITIAL_BACKOFF_MS,
                timeout: this.timeout ?? DEFAULT_TIMEOUT_MS,
                maxResponseBytes: DEFAULT_OCSP_CONFIG.maxResponseBytes,
            },
            serviceLabel: "OCSP responder",
            signal: options.signal,
            budget: options.budget,
        });
    }

    async fetchCRL(url: string, context?: RevocationFetchContext): Promise<Uint8Array> {
        return this.fetchCRLInner(url, { signal: context?.signal });
    }

    /**
     * Built-in CRL fetch with the completion's budget threaded into the
     * retry shell, so every physical attempt (retries included) and every
     * received chunk is counted.
     *
     * Deliberately spoofing this entry from caller-own code is
     * self-sabotage that gains nothing (see fetchOCSPWithBudget).
     *
     * @internal For ValidationSession's capability dispatch only. Not part
     * of the public fetcher contract.
     */
    async fetchCRLWithBudget(url: string, budget: OperationBudget): Promise<Uint8Array> {
        // Same-realm override self-check, mirroring fetchOCSPWithBudget.
        if (this.fetchCRL !== DefaultFetcher.prototype.fetchCRL) {
            return budget.countCustomFetch(
                "CRL",
                DEFAULT_CRL_CONFIG.maxResponseBytes,
                ({ signal }) => this.fetchCRL(url, { signal })
            );
        }
        return this.fetchCRLInner(url, { signal: budget.signal, budget });
    }

    private async fetchCRLInner(
        url: string,
        options: { signal?: AbortSignal; budget?: OperationBudget }
    ): Promise<Uint8Array> {
        if (this.timeout === undefined && this.maxRetries === undefined) {
            return fetchCRL(url, options);
        }
        return fetchBytesWithRetry({
            url,
            method: "GET",
            config: {
                retry: this.maxRetries ?? MAX_RETRIES,
                retryDelay: INITIAL_BACKOFF_MS,
                timeout: this.timeout ?? DEFAULT_TIMEOUT_MS,
                maxResponseBytes: DEFAULT_CRL_CONFIG.maxResponseBytes,
            },
            serviceLabel: "CRL server",
            signal: options.signal,
            budget: options.budget,
        });
    }
}
