import { TimestampError, TimestampErrorCode } from "../types.js";
import { CircuitState, type CircuitBreakerMap } from "./circuit-breaker.js";
import { validateUrl, formatDiagnosticUrl, sanitizeTransportCause } from "./url.js";
import { readResponseBounded, assertResponseCap } from "./bounded-fetch.js";
import { monotonicNow, type MonotonicClock } from "./clock.js";

/**
 * Largest delay the platform timer accepts: 2^31 - 1 ms. Larger values
 * warn (Node TimeoutOverflowWarning) and misfire as ~1 ms, so timer
 * inputs above this are rejected and calculated backoffs are capped.
 */
export const MAX_TIMER_DELAY_MS = 2147483647;

/**
 * Per-call retry / timeout / size-cap configuration.
 */
export interface FetchWithRetryConfig {
    /** Total number of retry attempts after the initial one (so total attempts = retry + 1). */
    retry: number;
    /** Initial backoff in ms; doubles each subsequent retry. */
    retryDelay: number;
    /** Per-attempt timeout in ms; covers headers and body. */
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
     * Optional per-URL circuit-breaker map. OPEN short-circuits with
     * TimestampError(CIRCUIT_OPEN): zero fetches, no backoff. Success
     * records success; exhausted retryables record one failure. Terminal
     * rejections and caller cancellation never record a remote outage.
     */
    circuitBreakers?: CircuitBreakerMap;
    /**
     * Label used in error messages, e.g. "OCSP responder", "TSA". Falls
     * back to "service" when omitted.
     */
    serviceLabel?: string;
    /**
     * Optional validator over the accepted bytes. Throw a TimestampError
     * to reject (terminal); any other error is wrapped as
     * INVALID_RESPONSE (also terminal, never retried or recorded).
     */
    validateBytes?: (bytes: Uint8Array, response: Response) => void;
    /**
     * Optional caller abort signal. Cancellation always wins and never
     * retries or records an outage; it stays distinct from the retryable
     * per-attempt timeout owned by this helper.
     */
    signal?: AbortSignal;
    /**
     * Monotonic clock (ms) for elapsed-deadline checks. Defaults to the
     * shared monotonic clock; tests inject a manual clock to control
     * elapsed time without depending on timer mocking.
     */
    clock?: MonotonicClock;
}

/** Rejects invalid numeric retry/timeout/size config before any fetch. */
function assertValidFetchConfig(config: FetchWithRetryConfig): void {
    if (!Number.isSafeInteger(config.retry) || config.retry < 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            `Invalid retry ${String(config.retry)}: integer >= 0`
        );
    }
    if (
        !Number.isFinite(config.retryDelay) ||
        config.retryDelay < 0 ||
        config.retryDelay > MAX_TIMER_DELAY_MS
    ) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            `Invalid retryDelay ${String(config.retryDelay)}: finite number ` +
                `in [0, ${MAX_TIMER_DELAY_MS.toString()}]`
        );
    }
    if (
        !Number.isFinite(config.timeout) ||
        config.timeout <= 0 ||
        config.timeout > MAX_TIMER_DELAY_MS
    ) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            `Invalid timeout ${String(config.timeout)}: finite number ` +
                `in (0, ${MAX_TIMER_DELAY_MS.toString()}]`
        );
    }
    assertResponseCap(config.maxResponseBytes);
}

/** Rejects with the caller's reason when the caller already cancelled. */
function throwIfCallerAborted(callerSignal: AbortSignal | undefined): void {
    if (callerSignal?.aborted === true) throw callerSignal.reason;
}

/**
 * Best-effort release of a rejected response body so failed statuses do
 * not hold connections or stream resources. Fire-and-observe: an arbitrary
 * cancel() is initiated with rejection handling but settlement never waits
 * for it, so a never-settling or rejecting cancel can neither hang the
 * caller past abort/deadline nor corrupt the verdict.
 */
function discardBody(response: Response): void {
    try {
        const body = response.body;
        if (body !== null) {
            void body.cancel().catch(() => undefined);
        }
    } catch {
        // Best effort only; the classification error below is what matters.
    }
}

/** Backoff sleep that stays cancellable by the caller. */
function sleepAbortable(ms: number, callerSignal: AbortSignal | undefined): Promise<void> {
    throwIfCallerAborted(callerSignal);
    return new Promise<void>((resolve, reject) => {
        const timer = setTimeout(() => {
            callerSignal?.removeEventListener("abort", onAbort);
            resolve();
        }, ms);
        const onAbort = (): void => {
            clearTimeout(timer);
            // The caller's abort reason propagates verbatim (even a
            // non-Error), matching platform fetch cancellation semantics.
            // eslint-disable-next-line @typescript-eslint/prefer-promise-reject-errors
            reject(callerSignal?.reason);
        };
        callerSignal?.addEventListener("abort", onAbort, { once: true });
    });
}

/**
 * Shared HTTP-with-retry shell for TSA / OCSP / CRL / cert / fetcher
 * clients. redirect:manual (3xx/opaque rejected, never followed); 5xx
 * retried, every 4xx terminal; one per-attempt deadline covers headers
 * and body; caller-cancelable backoff; empty/validator failures
 * terminal. Exhaustion throws TIMEOUT (deadline) or NETWORK_ERROR.
 */
export async function fetchBytesWithRetry(options: FetchWithRetryOptions): Promise<Uint8Array> {
    const { url, method, headers, body, config, circuitBreakers, validateBytes } = options;
    const serviceLabel = options.serviceLabel ?? "service";
    const callerSignal = options.signal;

    assertValidFetchConfig(config);
    // H4: validate once up-front so a bad URL fails fast instead of consuming
    // the full retry budget.
    validateUrl(url);
    // Caller cancellation wins over every other local verdict, including
    // an already-open breaker.
    throwIfCallerAborted(callerSignal);

    if (circuitBreakers !== undefined) {
        const state = circuitBreakers.getState(url);
        if (state === CircuitState.OPEN) {
            throw new TimestampError(
                TimestampErrorCode.CIRCUIT_OPEN,
                `Circuit breaker OPEN for ${formatDiagnosticUrl(url)}; ` +
                    `${serviceLabel} not attempted.`
            );
        }
    }

    const totalAttempts = config.retry + 1;
    const clock: MonotonicClock = options.clock ?? monotonicNow;

    // One retryable failure: back off and continue, or (final attempt)
    // record the single circuit failure and throw the classified error.
    const failRetryable = async (
        kind: "timeout" | "network",
        error: unknown,
        attempt: number
    ): Promise<void> => {
        // Caller cancellation wins over every retryable verdict, including
        // an abort landing in the `await discardBody` window on the final
        // attempt where there is no backoff sleep to re-check. Placed here
        // it covers the fetch-rejection, 5xx, and body-failure paths
        // uniformly, before any circuit record or classified throw.
        throwIfCallerAborted(callerSignal);
        if (attempt < config.retry) {
            // Exponential backoff capped at the platform timer range so a
            // large retryDelay cannot overflow into a ~1 ms misfire.
            const backoffMs = Math.min(config.retryDelay * 2 ** attempt, MAX_TIMER_DELAY_MS);
            await sleepAbortable(backoffMs, callerSignal);
            return;
        }
        circuitBreakers?.recordFailure(url);
        if (error instanceof TimestampError) {
            throw error;
        }
        const diagnosticUrl = formatDiagnosticUrl(url);
        // Native fetch failures echo the request URL into the message, so
        // the attached cause is sanitized like the outer message. Causes
        // without embedded secrets keep their identity.
        const cause = sanitizeTransportCause(error);
        if (kind === "timeout") {
            throw new TimestampError(
                TimestampErrorCode.TIMEOUT,
                `Timed out fetching from ${serviceLabel} (${diagnosticUrl}) ` +
                    `after ${String(totalAttempts)} attempts`,
                cause
            );
        }
        throw new TimestampError(
            TimestampErrorCode.NETWORK_ERROR,
            `Failed to fetch from ${serviceLabel} (${diagnosticUrl}) ` +
                `after ${String(totalAttempts)} attempts`,
            cause
        );
    };

    // Every iteration ends in return, throw, or backoff-continue; the
    // final retryable failure always throws, so this cannot spin forever.
    for (let attempt = 0; ; attempt++) {
        // Attempt entry re-check: an abort landing between backoff
        // resolution and this dispatch must not start another fetch with
        // a fresh, unaborted signal.
        throwIfCallerAborted(callerSignal);
        // Absolute per-attempt deadline on the monotonic clock, alongside
        // the armed timer. Signal state alone cannot observe a deadline
        // the event loop never got to run, so elapsed time is checked
        // directly before bytes are accepted or success is recorded. The
        // clock is monotonic (never Date.now()): a backward wall-clock
        // step must not turn an elapsed deadline into accepted success.
        const attemptDeadline = clock() + config.timeout;
        const controller = new AbortController();
        const timeoutId = setTimeout(() => {
            controller.abort();
        }, config.timeout);
        // Owned deadline expiry is identified from deadline state (timer
        // fired or elapsed), never from an error name: a bare AbortError
        // with a live signal and unexpired deadline is not our timeout.
        const isAttemptExpired = (): boolean =>
            controller.signal.aborted || clock() >= attemptDeadline;
        // Caller aborts are told apart from the per-attempt timeout by
        // checking the caller signal first wherever an abort surfaces.
        const onCallerAbort = (): void => {
            controller.abort(callerSignal?.reason);
        };
        callerSignal?.addEventListener("abort", onCallerAbort, { once: true });
        try {
            let response: Response;
            try {
                response = await fetch(url, {
                    method,
                    headers,
                    body,
                    signal: controller.signal,
                    redirect: "manual",
                });
            } catch (error) {
                throwIfCallerAborted(callerSignal);
                await failRetryable(isAttemptExpired() ? "timeout" : "network", error, attempt);
                continue;
            }

            // redirect:manual hands 3xx (Node) or opaqueredirect (browsers)
            // to us instead of following. Reject terminally; never fetch
            // Location. Opaque first: those carry no usable status.
            if (response.type === "opaqueredirect" || response.type === "opaque") {
                discardBody(response);
                // An abort landing in discard wins over the terminal verdict.
                throwIfCallerAborted(callerSignal);
                throw new TimestampError(
                    TimestampErrorCode.NETWORK_ERROR,
                    `${serviceLabel} returned an unreadable opaque redirect; ` +
                        `redirects are never followed`
                );
            }
            const status = response.status;
            if (status >= 300 && status <= 399) {
                discardBody(response);
                throwIfCallerAborted(callerSignal);
                throw new TimestampError(
                    TimestampErrorCode.NETWORK_ERROR,
                    `${serviceLabel} returned redirect HTTP ${String(status)}; ` +
                        `redirects are never followed`
                );
            }
            if (status >= 500 && status <= 599) {
                discardBody(response);
                await failRetryable(
                    "network",
                    new Error(`HTTP ${String(status)}: ${response.statusText}`),
                    attempt
                );
                continue;
            }
            // Every 4xx (incl. 408/429) is terminal: without
            // Retry-After handling, retrying 429 hammers a struggling
            // responder. Changing that policy is a separate decision.
            // Any other non-ok status fails closed the same way.
            if (!response.ok) {
                discardBody(response);
                throwIfCallerAborted(callerSignal);
                throw new TimestampError(
                    TimestampErrorCode.NETWORK_ERROR,
                    `${serviceLabel} returned HTTP ${String(status)}: ${response.statusText}`
                );
            }

            // The per-attempt deadline stays armed across the body read, so
            // a stalled body trips the same timeout as hung headers. The
            // absolute deadline travels with it for elapsed enforcement
            // when the timer callback cannot run in time.
            let responseBytes: Uint8Array;
            try {
                responseBytes = await readResponseBounded(response, config.maxResponseBytes, {
                    signal: controller.signal,
                    deadlineMs: attemptDeadline,
                    clock,
                });
            } catch (error) {
                throwIfCallerAborted(callerSignal);
                // Over-cap reads arrive here as TimestampErrors; terminal.
                if (error instanceof TimestampError) {
                    throw error;
                }
                await failRetryable(isAttemptExpired() ? "timeout" : "network", error, attempt);
                continue;
            }
            // Never report success after the caller cancelled, and never
            // accept bytes past the attempt deadline: genuine exhaustion
            // retries through the normal timeout policy instead.
            throwIfCallerAborted(callerSignal);
            if (isAttemptExpired()) {
                await failRetryable(
                    "timeout",
                    new Error("per-attempt deadline elapsed before the response completed"),
                    attempt
                );
                continue;
            }

            if (responseBytes.length === 0) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    `${serviceLabel} returned empty response`
                );
            }

            if (validateBytes !== undefined) {
                try {
                    validateBytes(responseBytes, response);
                } catch (error) {
                    // A validator that aborts and then throws must surface
                    // the caller reason, not a validation wrapper.
                    throwIfCallerAborted(callerSignal);
                    if (error instanceof TimestampError) throw error;
                    throw new TimestampError(
                        TimestampErrorCode.INVALID_RESPONSE,
                        `${serviceLabel} response failed validation`,
                        error
                    );
                }
            }
            // A validator that aborts and returns must not read as success,
            // and synchronous validation past the deadline is exhaustion,
            // not an accepted verdict: re-check before recording success.
            throwIfCallerAborted(callerSignal);
            if (isAttemptExpired()) {
                await failRetryable(
                    "timeout",
                    new Error("per-attempt deadline elapsed during response validation"),
                    attempt
                );
                continue;
            }

            circuitBreakers?.recordSuccess(url);
            return responseBytes;
        } finally {
            clearTimeout(timeoutId);
            callerSignal?.removeEventListener("abort", onCallerAbort);
        }
    }
}
