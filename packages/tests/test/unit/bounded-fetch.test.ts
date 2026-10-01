import { describe, it, expect, vi } from "vitest";
import {
    readResponseBounded,
    ResponseTooLargeError,
} from "../../../core/src/utils/bounded-fetch.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

// Absolute ceiling from the transport contract: maxSize is a positive safe
// integer at most 250 MiB. Kept literal here so the red run does not depend
// on new exports from the implementation under test.
const MAX_ABSOLUTE = 250 * 1024 * 1024;
const STILL_PENDING = Symbol("still-pending");

interface Settled<T> {
    settled: true;
    value?: T;
    error?: unknown;
}

/**
 * Race a promise against a wall-clock bound. Resolves to STILL_PENDING when
 * the promise never settles (the hang this task must eliminate); otherwise
 * reports the fulfillment value or rejection reason.
 */
async function settleWithin(
    promise: Promise<unknown>,
    boundMs: number
): Promise<Settled<unknown> | typeof STILL_PENDING> {
    return Promise.race([
        promise.then(
            (value: unknown): Settled<unknown> => ({ settled: true, value }),
            (error: unknown): Settled<unknown> => ({ settled: true, error })
        ),
        new Promise<typeof STILL_PENDING>((resolve) => {
            setTimeout(() => {
                resolve(STILL_PENDING);
            }, boundMs);
        }),
    ]);
}

interface CountingStream {
    stream: ReadableStream<Uint8Array>;
    pulls: () => number;
    cancelled: () => boolean;
}

function countingStream(chunks: Uint8Array[], stallAfter = false): CountingStream {
    let pulls = 0;
    let cancelled = false;
    let index = 0;
    const stream = new ReadableStream<Uint8Array>({
        pull(controller) {
            pulls++;
            if (index < chunks.length) {
                const next = chunks[index];
                index++;
                controller.enqueue(next!);
            } else if (!stallAfter) {
                controller.close();
            }
            // stallAfter: never enqueue or close again, the read hangs.
        },
        cancel() {
            cancelled = true;
        },
    });
    return {
        stream,
        pulls: () => pulls,
        cancelled: () => cancelled,
    };
}

function chunkOf(size: number, fill = 0xab): Uint8Array {
    return new Uint8Array(size).fill(fill);
}

/**
 * undici pulls a Response stream once on the macrotask after construction.
 * Flush that eager pull so snapshots only count reader-driven pulls.
 */
async function settledPulls(counted: CountingStream): Promise<number> {
    await new Promise((resolve) => setTimeout(resolve, 0));
    return counted.pulls();
}

describe("readResponseBounded streaming retention (R4)", () => {
    it("accepts a body of exactly the cap", async () => {
        const data = chunkOf(16);
        const result = await readResponseBounded(new Response(data as BodyInit), 16);
        expect(result).toEqual(data);
    });

    it("rejects a body of cap+1 with cap metadata", async () => {
        const error = await readResponseBounded(new Response(chunkOf(17) as BodyInit), 16).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
        const tooLarge = error as ResponseTooLargeError;
        expect(tooLarge.maxBytes).toBe(16);
        expect(tooLarge.actualBytes).toBe(17);
        expect(tooLarge.code).toBe(TimestampErrorCode.NETWORK_ERROR);
    });

    it("stops pulling early on a lying Content-Length instead of buffering everything", async () => {
        const chunkBytes = 1024;
        const capBytes = 10 * 1024;
        const chunks: Uint8Array[] = [];
        for (let i = 0; i < 100; i++) {
            chunks.push(chunkOf(chunkBytes, i));
        }
        const counted = countingStream(chunks);
        const response = new Response(counted.stream, {
            status: 200,
            headers: { "content-length": "1024" },
        });
        const error = await readResponseBounded(response, capBytes).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
        // Byte-derived stopping point: the 11th 1 KiB chunk tips a 10 KiB
        // cap. Measured pulls are exactly 11 (no prefetch beyond the
        // tipping chunk on this runtime); allow one extra pull for
        // Response-wrapper prefetch elsewhere.
        const tippingPull = Math.floor(capBytes / chunkBytes) + 1;
        expect(counted.pulls()).toBeLessThanOrEqual(tippingPull + 1);
    });

    it("bounds retention against a large stream", async () => {
        // 3 MiB over a 64 KiB cap: full buffering pulls ~3000 chunks, a
        // streaming reader stops after ~65. Finite so the old arrayBuffer
        // path terminates instead of OOMing the worker.
        const chunkBytes = 1024;
        const capBytes = 64 * 1024;
        const chunks: Uint8Array[] = [];
        for (let i = 0; i < 3000; i++) {
            chunks.push(chunkOf(chunkBytes));
        }
        const counted = countingStream(chunks);
        const error = await readResponseBounded(new Response(counted.stream), capBytes).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
        // Byte-derived stopping point (65th chunk) plus one prefetch pull;
        // measured pulls are exactly 65.
        const tippingPull = Math.floor(capBytes / chunkBytes) + 1;
        expect(counted.pulls()).toBeLessThanOrEqual(tippingPull + 1);
    });

    it("rejects before the first read-driven pull when Content-Length exceeds the cap", async () => {
        const counted = countingStream([chunkOf(4)]);
        const response = new Response(counted.stream, {
            status: 200,
            headers: { "content-length": String(10 * 1024 * 1024) },
        });
        // Response construction itself may pull eagerly; only reads driven
        // by the bounded reader count here.
        const pullsAtConstruction = await settledPulls(counted);
        const error = await readResponseBounded(response, 1024).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
        expect(counted.pulls()).toBe(pullsAtConstruction);
        // The early rejection still releases the unwanted response.
        expect(counted.cancelled()).toBe(true);
    });

    it("rejects an over-cap body with no Content-Length", async () => {
        const counted = countingStream([chunkOf(2048)]);
        const error = await readResponseBounded(new Response(counted.stream), 1024).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
    });

    it("ignores a malformed Content-Length and streams within the cap", async () => {
        const data = chunkOf(2);
        const response = new Response(data as BodyInit, {
            status: 200,
            headers: { "content-length": "not-a-number" },
        });
        const result = await readResponseBounded(response, 1024);
        expect(result).toEqual(data);
    });

    it("accepts a within-cap body with no Content-Length", async () => {
        const data = chunkOf(2);
        const result = await readResponseBounded(new Response(data as BodyInit), 1024);
        expect(result).toEqual(data);
    });

    it("returns empty bytes for a null body", async () => {
        const result = await readResponseBounded(new Response(null, { status: 200 }), 1024);
        expect(result).toEqual(new Uint8Array(0));
    });

    it("returns empty bytes for an empty body", async () => {
        const result = await readResponseBounded(new Response(new Uint8Array(0) as BodyInit), 1024);
        expect(result.length).toBe(0);
    });

    it("concatenates chunks in order", async () => {
        const counted = countingStream([
            new Uint8Array([1, 2]),
            new Uint8Array([3]),
            new Uint8Array([4, 5, 6]),
        ]);
        const result = await readResponseBounded(new Response(counted.stream), 1024);
        expect(result).toEqual(new Uint8Array([1, 2, 3, 4, 5, 6]));
    });

    it("cancels the stream when the cap is exceeded", async () => {
        const counted = countingStream([chunkOf(600), chunkOf(600)]);
        const error = await readResponseBounded(new Response(counted.stream), 1024).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
        expect(counted.cancelled()).toBe(true);
    });

    it("releases the reader lock after success and after cap rejection", async () => {
        const okResponse = new Response(chunkOf(4) as BodyInit);
        await readResponseBounded(okResponse, 1024);
        expect(okResponse.body?.locked).toBe(false);

        const bigResponse = new Response(chunkOf(2048) as BodyInit);
        await readResponseBounded(bigResponse, 1024).then(
            () => null,
            () => null
        );
        expect(bigResponse.body?.locked).toBe(false);
    });

    it("accepts the 250 MiB absolute ceiling as a cap", async () => {
        const result = await readResponseBounded(
            new Response(chunkOf(4) as BodyInit),
            MAX_ABSOLUTE
        );
        expect(result.length).toBe(4);
    });

    it.each([0, -1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, MAX_ABSOLUTE + 1])(
        "rejects invalid maxBytes %s before reading",
        async (maxBytes: number) => {
            const counted = countingStream([chunkOf(4)]);
            const response = new Response(counted.stream);
            const pullsAtConstruction = await settledPulls(counted);
            const error = await readResponseBounded(response, maxBytes).then(
                () => null,
                (e: unknown) => e
            );
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_ARGUMENT);
            expect(counted.pulls()).toBe(pullsAtConstruction);
        }
    );
});

describe("readResponseBounded cancellation (R24)", () => {
    it("rejects without read-driven pulls when the signal is already aborted", async () => {
        const controller = new AbortController();
        const reason = new Error("caller stopped");
        controller.abort(reason);
        const counted = countingStream([chunkOf(4)]);
        const response = new Response(counted.stream);
        const pullsAtConstruction = await settledPulls(counted);
        const error = await readResponseBounded(response, 1024, {
            signal: controller.signal,
        }).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBe(reason);
        expect(counted.pulls()).toBe(pullsAtConstruction);
    });

    it("aborts a stalled read and releases the lock", async () => {
        const controller = new AbortController();
        const counted = countingStream([new Uint8Array([9])], true);
        const response = new Response(counted.stream);
        setTimeout(() => {
            controller.abort(new DOMException("stalled", "AbortError"));
        }, 20);
        const verdict = await settleWithin(
            readResponseBounded(response, 1024, { signal: controller.signal }),
            2000
        );
        expect(verdict).not.toBe(STILL_PENDING);
        if (verdict === STILL_PENDING) {
            return;
        }
        expect(verdict.settled).toBe(true);
        expect((verdict.error as Error).name).toBe("AbortError");
        expect(response.body?.locked).toBe(false);
    });
});

describe("readResponseBounded hostile cleanup (I1)", () => {
    it("rejects promptly with the lock released when cap-exceeded cancel() never settles", async () => {
        let cancelled = false;
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new Uint8Array([1, 2, 3, 4, 5]));
            },
            cancel() {
                cancelled = true;
                return new Promise<never>(() => {
                    // Never settles: settlement must not wait for it.
                });
            },
        });
        const response = new Response(stream);
        const verdict = await settleWithin(readResponseBounded(response, 4), 2000);
        expect(verdict).not.toBe(STILL_PENDING);
        if (verdict === STILL_PENDING) {
            return;
        }
        expect(verdict.settled).toBe(true);
        expect(verdict.error).toBeInstanceOf(ResponseTooLargeError);
        expect(cancelled).toBe(true);
        expect(response.body?.locked).toBe(false);
    });

    it("preserves the cap verdict when cancel() rejects", async () => {
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new Uint8Array([1, 2, 3, 4, 5]));
            },
            cancel() {
                return Promise.reject(new Error("cancel blew up"));
            },
        });
        const response = new Response(stream);
        const error = await readResponseBounded(response, 4).then(
            () => null,
            (e: unknown) => e
        );
        expect(error).toBeInstanceOf(ResponseTooLargeError);
        expect(response.body?.locked).toBe(false);
    });
});

describe("readResponseBounded elapsed deadline (I4)", () => {
    // The marker is asserted by name (not a static import) so these
    // regressions also run against pre-fix code for RED evidence.
    // Elapsed time is driven by an injected manual clock, never by timer
    // mocking; wall-clock steps are simulated with a Date.now spy.
    function manualClock(startMs: number): { now: number; clock: () => number } {
        const state = { now: startMs, clock: () => state.now };
        return state;
    }

    it("rejects immediately when the deadline already passed", async () => {
        const manual = manualClock(1000);
        const error = await readResponseBounded(new Response(chunkOf(4) as BodyInit), 1024, {
            deadlineMs: 999,
            clock: manual.clock,
        }).then(
            () => null,
            (e: unknown) => e
        );
        expect((error as Error | null)?.name).toBe("AttemptDeadlineExceededError");
    });

    it("stops a mid-stream read when the clock passes the deadline without timer callbacks", async () => {
        const manual = manualClock(1000);
        const stream = new ReadableStream<Uint8Array>({
            start(controller) {
                controller.enqueue(new Uint8Array([7, 7]));
            },
            pull(controller) {
                // Advance the clock without firing any timer callback.
                manual.now += 5000;
                controller.close();
            },
        });
        const response = new Response(stream);
        const error = await readResponseBounded(response, 1024, {
            deadlineMs: 1050,
            clock: manual.clock,
        }).then(
            () => null,
            (e: unknown) => e
        );
        expect((error as Error | null)?.name).toBe("AttemptDeadlineExceededError");
        expect(response.body?.locked).toBe(false);
    });

    it("reads normally when the deadline is in the future", async () => {
        const manual = manualClock(1000);
        const data = chunkOf(4);
        const result = await readResponseBounded(new Response(data as BodyInit), 1024, {
            deadlineMs: 61000,
            clock: manual.clock,
        });
        expect(result).toEqual(data);
    });

    it("ignores a backward wall-clock step once the deadline elapsed", async () => {
        const realStart = Date.now();
        const nowSpy = vi.spyOn(Date, "now").mockReturnValue(realStart);
        try {
            const manual = manualClock(realStart);
            const stream = new ReadableStream<Uint8Array>({
                start(controller) {
                    controller.enqueue(new Uint8Array([7, 7]));
                },
                pull(controller) {
                    manual.now += 5000;
                    // A backward wall-clock step must not mask the elapsed
                    // monotonic deadline.
                    nowSpy.mockReturnValue(realStart - 1000);
                    controller.close();
                },
            });
            const response = new Response(stream);
            const error = await readResponseBounded(response, 1024, {
                deadlineMs: realStart + 50,
                clock: manual.clock,
            }).then(
                () => null,
                (e: unknown) => e
            );
            expect((error as Error | null)?.name).toBe("AttemptDeadlineExceededError");
            expect(response.body?.locked).toBe(false);
        } finally {
            nowSpy.mockRestore();
        }
    });
});
