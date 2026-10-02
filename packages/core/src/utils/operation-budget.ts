import { TimestampError, TimestampErrorCode } from "../types.js";
import { monotonicNow, type MonotonicClock } from "./clock.js";
import { ResponseTooLargeError } from "./bounded-fetch.js";

/**
 * Caller-overridable per-completion collection limits. Every field is
 * optional; omitted fields take the `DEFAULT_OPERATION_BUDGET_LIMITS`
 * values. All limits accept 0 (collect nothing of that kind).
 */
export interface OperationBudgetLimits {
    /** Network attempts including retries (built-in and custom fetches). */
    maxAttempts?: number;
    /** Returned network bytes, counted even for rejected evidence. */
    maxBytes?: number;
    /** Certificates admitted into collection. */
    maxCertificates?: number;
    /** Unique AIA URLs attempted per certificate. */
    maxUrlsPerCertificate?: number;
    /** Elapsed wall of one completion in ms, backoff included. */
    maxElapsedMs?: number;
}

/**
 * Default per-completion budget: 32 network attempts, 20 MiB returned
 * bytes, 32 certificates, 8 unique AIA URLs per certificate, 60 s
 * elapsed. Tuned only with recorded corpus/compatibility evidence.
 */
export const DEFAULT_OPERATION_BUDGET_LIMITS = {
    maxAttempts: 32,
    maxBytes: 20 * 1024 * 1024,
    maxCertificates: 32,
    maxUrlsPerCertificate: 8,
    maxElapsedMs: 60000,
};

/**
 * Largest delay the platform timer accepts (mirrors the fetch shell's
 * cap; defined here to avoid a module cycle).
 */
const MAX_TIMER_DELAY_MS = 2147483647;

const COUNT_LIMIT_KEYS = [
    "maxAttempts",
    "maxBytes",
    "maxCertificates",
    "maxUrlsPerCertificate",
] as const;

/**
 * Per-call context handed to OUR accounting closure by
 * `countCustomFetch`. Internal only: it carries the live budget, so
 * the closure must hand the fetcher a fresh signal-only object (R19),
 * never this context itself.
 */
export interface CustomFetchContext {
    signal: AbortSignal;
    budget: OperationBudget;
}

/** Rejects invalid budget limits before any collection or network use. */
export function assertValidOperationBudgetLimits(limits: OperationBudgetLimits): void {
    for (const key of COUNT_LIMIT_KEYS) {
        const value = limits[key];
        if (value !== undefined && (!Number.isSafeInteger(value) || value < 0)) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_ARGUMENT,
                `Invalid operation budget ${key} ${String(value)}: integer >= 0`
            );
        }
    }
    const elapsed = limits.maxElapsedMs;
    if (
        elapsed !== undefined &&
        (!Number.isFinite(elapsed) || elapsed < 0 || elapsed > MAX_TIMER_DELAY_MS)
    ) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            `Invalid operation budget maxElapsedMs ${String(elapsed)}: finite number ` +
                `in [0, ${MAX_TIMER_DELAY_MS.toString()}]`
        );
    }
}

/**
 * Aggregate operation budget for one LTV completion or validation run.
 * Every collection path (built-in fetch/retry, custom fetchers,
 * repeated AIA URLs, cache refetches) consumes attempts / bytes /
 * certificates / elapsed from this one object. Exhaustion aborts
 * `signal` (wired into built-in I/O as real cancellation, and handed
 * to custom fetchers for cooperative cancellation) and refuses further
 * work; already-consumed bytes stay delivered. Carries the single
 * check-time capture for the completion alongside the monotonic clock.
 */
export class OperationBudget {
    /** The one validation check-time of this completion (never mutated). */
    readonly checkTime: Date;
    /** Aborts with the exhaustion error once the budget is spent. */
    readonly signal: AbortSignal;
    readonly maxAttempts: number;
    readonly maxBytes: number;
    readonly maxCertificates: number;
    readonly maxUrlsPerCertificate: number;
    readonly maxElapsedMs: number;
    private readonly clock: MonotonicClock;
    private readonly deadline: number;
    private readonly controller = new AbortController();
    private readonly timer: ReturnType<typeof setTimeout>;
    private readonly urlsByCert = new Map<string, Set<string>>();
    private attempts = 0;
    private bytes = 0;
    private certificates = 0;
    private done = false;

    constructor(
        limits: OperationBudgetLimits = {},
        options: { checkTime?: Date; clock?: MonotonicClock } = {}
    ) {
        assertValidOperationBudgetLimits(limits);
        if (
            options.checkTime !== undefined &&
            (!(options.checkTime instanceof Date) || !Number.isFinite(options.checkTime.getTime()))
        ) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_ARGUMENT,
                "OperationBudget checkTime must be a finite date"
            );
        }
        this.checkTime =
            options.checkTime === undefined ? new Date() : new Date(options.checkTime.getTime());
        this.maxAttempts = limits.maxAttempts ?? DEFAULT_OPERATION_BUDGET_LIMITS.maxAttempts;
        this.maxBytes = limits.maxBytes ?? DEFAULT_OPERATION_BUDGET_LIMITS.maxBytes;
        this.maxCertificates =
            limits.maxCertificates ?? DEFAULT_OPERATION_BUDGET_LIMITS.maxCertificates;
        this.maxUrlsPerCertificate =
            limits.maxUrlsPerCertificate ?? DEFAULT_OPERATION_BUDGET_LIMITS.maxUrlsPerCertificate;
        this.maxElapsedMs = limits.maxElapsedMs ?? DEFAULT_OPERATION_BUDGET_LIMITS.maxElapsedMs;
        this.clock = options.clock ?? monotonicNow;
        this.deadline = this.clock() + this.maxElapsedMs;
        this.signal = this.controller.signal;
        // Real cancellation, not a timeout race: the deadline abort lands
        // on the same signal built-in I/O and custom fetchers observe.
        this.timer = setTimeout(() => {
            this.exhaust();
        }, this.maxElapsedMs);
        // Never hold a Node process open past the completion's own life.
        (this.timer as unknown as { unref?: () => void }).unref?.();
    }

    /** True once any limit is spent (further dispatches are refused). */
    get exhausted(): boolean {
        return (
            this.done ||
            this.attempts >= this.maxAttempts ||
            this.bytes > this.maxBytes ||
            this.isElapsed()
        );
    }

    /** True once the monotonic elapsed deadline has passed. */
    isElapsed(): boolean {
        return this.clock() >= this.deadline;
    }

    /**
     * Claims one network attempt. Returns false (and exhausts, aborting
     * in-flight I/O) when the budget is already spent; the caller must
     * issue no fetch then. Attempts are counted, never refunded.
     */
    tryStartAttempt(): boolean {
        if (this.exhausted) {
            this.exhaust();
            return false;
        }
        this.attempts++;
        return true;
    }

    /**
     * Counts consumed bytes, including evidence later rejected. Tipping
     * over the cap only flags exhaustion: the call that delivered the
     * bytes still returns them, the next dispatch is refused.
     */
    addBytes(count: number): void {
        this.bytes += count;
    }

    /**
     * Admits one certificate into collection. Beyond the cap the caller
     * skips the certificate with a diagnostic (never a verdict).
     */
    admitCertificate(): boolean {
        if (this.certificates >= this.maxCertificates) return false;
        this.certificates++;
        return true;
    }

    /** True while another certificate may still be admitted. */
    canAdmitCertificate(): boolean {
        return this.certificates < this.maxCertificates;
    }

    /** Refusal diagnostic for a certificate past the admission cap. */
    certificateRefusal(): string {
        return (
            `operation budget exhausted: certificate limit ` +
            `(${this.maxCertificates.toString()}) reached; skipping certificate`
        );
    }

    /** Refusal diagnostic for AIA URLs past the per-certificate cap. */
    urlRefusal(): string {
        return (
            `operation budget exhausted: URL limit ` +
            `(${this.maxUrlsPerCertificate.toString()} unique AIA URLs per certificate) ` +
            `reached; skipping remaining URLs`
        );
    }

    /**
     * Runs one custom fetch under the budget: claims the attempt up
     * front (refusing when spent), hands the fetch the abort context,
     * then accounts the return. Bytes are always consumed, even late or
     * over-cap ones; late returns arriving after exhaustion are
     * discarded, and returns over the service cap are rejected.
     */
    async countCustomFetch(
        label: string,
        maxBytes: number,
        call: (context: CustomFetchContext) => Promise<Uint8Array>
    ): Promise<Uint8Array> {
        if (!this.tryStartAttempt()) throw this.exhaustionError();
        const response = await call({ signal: this.signal, budget: this });
        this.addBytes(response.length);
        // Signal state alone cannot observe a deadline the event loop
        // never got to run (a fetcher holding the loop starves the
        // timer), so the elapsed clock is read directly too.
        if (this.signal.aborted || this.isElapsed()) throw this.exhaustionError();
        if (response.length > maxBytes) {
            throw new ResponseTooLargeError(
                `custom ${label} fetcher response (${response.length.toString()} bytes) ` +
                    `exceeds the ${maxBytes.toString()}-byte cap`,
                maxBytes,
                response.length
            );
        }
        return response;
    }

    /** True when this certificate already attempted this exact URL. */
    seenUrl(certKey: string, url: string): boolean {
        return this.urlsByCert.get(certKey)?.has(url) ?? false;
    }

    /**
     * Claims one unique URL for a certificate. False means the per-cert
     * cap is spent and no fetch may be issued for the remaining URLs.
     */
    claimUrl(certKey: string, url: string): boolean {
        let claimed = this.urlsByCert.get(certKey);
        if (claimed === undefined) {
            claimed = new Set();
            this.urlsByCert.set(certKey, claimed);
        }
        if (claimed.size >= this.maxUrlsPerCertificate) return false;
        claimed.add(url);
        return true;
    }

    /** Local-policy exhaustion error: elapsed reads as TIMEOUT, counts as NETWORK_ERROR. */
    exhaustionError(): TimestampError {
        const elapsed = this.isElapsed();
        const reason = elapsed
            ? `elapsed limit (${this.maxElapsedMs.toString()} ms) exceeded`
            : this.attempts >= this.maxAttempts
              ? `attempt limit (${this.maxAttempts.toString()}) reached`
              : this.bytes > this.maxBytes
                ? `byte limit (${this.maxBytes.toString()}) exceeded after ${this.bytes.toString()} bytes`
                : "already spent";
        return new TimestampError(
            elapsed ? TimestampErrorCode.TIMEOUT : TimestampErrorCode.NETWORK_ERROR,
            `operation budget exhausted: ${reason}; no further fetches`
        );
    }

    /** Releases the deadline timer; completions call this in a finally. */
    dispose(): void {
        clearTimeout(this.timer);
    }

    private exhaust(): void {
        if (this.done) return;
        this.done = true;
        this.controller.abort(this.exhaustionError());
    }
}
