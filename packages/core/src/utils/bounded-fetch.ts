import { TimestampError, TimestampErrorCode } from "../types.js";
import { monotonicNow, type MonotonicClock } from "./clock.js";

/**
 * Absolute ceiling for any bounded response cap: 250 MiB. Caps above this
 * are rejected as invalid before any byte is read.
 */
export const MAX_BOUNDED_RESPONSE_BYTES = 250 * 1024 * 1024;

/**
 * Thrown when a fetched response exceeds the configured size cap.
 * Extends TimestampError so existing catch blocks that look for
 * TimestampError(NETWORK_ERROR) still trip.
 */
export class ResponseTooLargeError extends TimestampError {
    constructor(
        message: string,
        public readonly maxBytes: number,
        public readonly actualBytes: number | undefined
    ) {
        super(TimestampErrorCode.NETWORK_ERROR, message);
        this.name = "ResponseTooLargeError";
    }
}

/**
 * Thrown when a bounded read observes its attempt deadline (see
 * {@link BoundedReadOptions.deadlineMs}) before the body completes. A plain
 * Error, deliberately not a TimestampError, so the retry shell routes it
 * through the normal timeout retry/accounting policy instead of treating
 * it as a terminal rejection.
 */
export class AttemptDeadlineExceededError extends Error {
    constructor(public readonly deadlineMs: number) {
        super("attempt deadline elapsed before the response body completed");
        this.name = "AttemptDeadlineExceededError";
    }
}

/**
 * Options for {@link readResponseBounded}. An object (rather than a bare
 * signal) so later tasks can thread operation budgets through it.
 */
export interface BoundedReadOptions {
    /** Attempt signal: abort cancels the reader, reason propagates. */
    signal?: AbortSignal;
    /**
     * Absolute attempt deadline on the {@link clock} timebase (monotonic
     * milliseconds by default). Timer callbacks cannot be relied on to
     * observe it (a stalled event loop may never run them before the body
     * completes), so the read loop checks the elapsed time directly and
     * stops promptly with {@link AttemptDeadlineExceededError} once it is
     * reached.
     */
    deadlineMs?: number;
    /**
     * Monotonic clock (ms) the deadline is expressed on. Defaults to the
     * shared monotonic clock; tests inject a manual clock to control
     * elapsed time without depending on timer mocking.
     */
    clock?: MonotonicClock;
}

/** Rejects non-positive-safe-integer or over-ceiling caps before reading. */
export function assertResponseCap(maxBytes: number): void {
    if (!Number.isSafeInteger(maxBytes) || maxBytes <= 0 || maxBytes > MAX_BOUNDED_RESPONSE_BYTES) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_ARGUMENT,
            `Invalid maxBytes ${String(maxBytes)}: positive safe integer ` +
                `<= ${MAX_BOUNDED_RESPONSE_BYTES.toString()}`
        );
    }
}

/**
 * Initiate stream cancellation without awaiting it. Custom fetchers can
 * return arbitrary streams, so settlement must never depend on an
 * arbitrary cancel(): never-settling implementations would hang the
 * verdict, and rejections must not corrupt error identity. Rejections
 * (async or sync) are swallowed; the caller's verdict is what matters.
 */
function cancelStreamBestEffort(stream: ReadableStream<Uint8Array> | null): void {
    if (stream === null) {
        return;
    }
    try {
        void stream.cancel().catch(() => undefined);
    } catch {
        // Best effort only.
    }
}

/**
 * Read a fetch Response body into a Uint8Array, rejecting bodies larger
 * than `maxBytes` (H5 cap: a hostile server must not OOM the host).
 * Declared over-cap Content-Length rejects before reading; otherwise the
 * body streams through a reader with the cap enforced incrementally
 * (missing/lying/malformed length all end up here), cancelling the
 * stream once retained bytes exceed the cap. An aborted signal cancels
 * the reader and propagates the reason; the lock is always released.
 * A null body reads as empty; the caller classifies emptiness.
 */
export async function readResponseBounded(
    response: Response,
    maxBytes: number,
    options?: BoundedReadOptions
): Promise<Uint8Array> {
    assertResponseCap(maxBytes);
    const signal = options?.signal;
    signal?.throwIfAborted();

    // Defensive: some test mocks provide a Response-shape without a real
    // Headers object. Cast to a permissive shape so the runtime guard works
    // without TS warning that headers is non-nullable per the official type.
    const headers = (response as { headers?: Headers | null }).headers ?? null;
    const declared = headers ? headers.get("content-length") : null;
    if (declared !== null) {
        const declaredNum = Number(declared);
        if (Number.isFinite(declaredNum) && declaredNum > maxBytes) {
            // Best-effort release like every other rejection path: the
            // unwanted response must not stay active. Fire-and-observe so
            // a hostile cancel() can neither stall nor break this throw.
            cancelStreamBestEffort(
                (response as { body?: ReadableStream<Uint8Array> | null }).body ?? null
            );
            throw new ResponseTooLargeError(
                `Content-Length ${declaredNum.toString()} exceeds cap ${maxBytes.toString()}`,
                maxBytes,
                declaredNum
            );
        }
    }

    // Permissive shape: foreign Response-shapes may omit body even
    // though the DOM type marks it non-optional.
    const body = (response as { body?: ReadableStream<Uint8Array> | null }).body ?? null;
    if (body === null) {
        return new Uint8Array(0);
    }

    const reader = body.getReader();
    const onAbort = (): void => {
        // Cancel unblocks a stalled read(); the loop then throws the
        // abort reason instead of reading the cancel as clean EOF.
        void reader.cancel().catch(() => undefined);
    };
    // Elapsed-deadline enforcement independent of timer delivery: signal
    // state alone cannot observe a deadline the event loop never got to
    // run. Checked after the signal so caller cancellation keeps priority.
    const deadlineMs = options?.deadlineMs;
    const clock: MonotonicClock = options?.clock ?? monotonicNow;
    const throwIfDeadlineExceeded = (): void => {
        if (deadlineMs !== undefined && clock() >= deadlineMs) {
            void reader.cancel().catch(() => undefined);
            throw new AttemptDeadlineExceededError(deadlineMs);
        }
    };
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
        const chunks: Uint8Array[] = [];
        let total = 0;
        for (;;) {
            signal?.throwIfAborted();
            throwIfDeadlineExceeded();
            const { done, value } = await reader.read();
            // Cancel resolves a pending read done:true; re-check first.
            signal?.throwIfAborted();
            throwIfDeadlineExceeded();
            if (done) {
                break;
            }
            total += value.byteLength;
            if (total > maxBytes) {
                // Drop the tipping chunk and stop the source. Initiated,
                // never awaited: a never-settling cancel() must not hang
                // this throw with the reader lock held.
                void reader.cancel().catch(() => undefined);
                throw new ResponseTooLargeError(
                    `response body over ${maxBytes.toString()}-byte cap`,
                    maxBytes,
                    total
                );
            }
            chunks.push(value);
        }
        const out = new Uint8Array(total);
        let offset = 0;
        for (const chunk of chunks) {
            out.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return out;
    } finally {
        signal?.removeEventListener("abort", onAbort);
        reader.releaseLock();
    }
}
