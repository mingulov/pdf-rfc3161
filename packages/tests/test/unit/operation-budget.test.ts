// test/unit/operation-budget.test.ts - T08 OperationBudget unit coverage.
//
// The aggregate per-completion tracker every collection path consumes:
// attempts / bytes / certificates / per-cert URLs / elapsed deadline,
// with real AbortSignal cancellation on exhaustion.
import { afterEach, describe, expect, it, vi } from "vitest";
import {
    DEFAULT_OPERATION_BUDGET_LIMITS,
    OperationBudget,
    assertValidOperationBudgetLimits,
    type CustomFetchContext,
} from "../../../core/src/utils/operation-budget.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

describe("OperationBudget (T08)", () => {
    const owned: OperationBudget[] = [];

    function own(budget: OperationBudget): OperationBudget {
        owned.push(budget);
        return budget;
    }

    afterEach(() => {
        vi.useRealTimers();
        for (const budget of owned.splice(0)) {
            budget.dispose();
        }
    });

    describe("defaults and validation", () => {
        it("uses the plan-mandated defaults", () => {
            expect(DEFAULT_OPERATION_BUDGET_LIMITS).toEqual({
                maxAttempts: 32,
                maxBytes: 20 * 1024 * 1024,
                maxCertificates: 32,
                maxUrlsPerCertificate: 8,
                maxElapsedMs: 60000,
            });
            const budget = own(new OperationBudget());
            expect(budget.maxAttempts).toBe(32);
            expect(budget.maxBytes).toBe(20 * 1024 * 1024);
            expect(budget.maxCertificates).toBe(32);
            expect(budget.maxUrlsPerCertificate).toBe(8);
            expect(budget.maxElapsedMs).toBe(60000);
            expect(budget.exhausted).toBe(false);
        });

        it("rejects invalid limits before any use", () => {
            for (const limits of [
                { maxAttempts: -1 },
                { maxBytes: 1.5 },
                { maxCertificates: Number.NaN },
                { maxUrlsPerCertificate: Number.POSITIVE_INFINITY },
                { maxElapsedMs: -1 },
                { maxElapsedMs: Number.NaN },
                { maxElapsedMs: 2147483648 },
            ]) {
                expect(() => assertValidOperationBudgetLimits(limits)).toThrow(TimestampError);
                expect(() => new OperationBudget(limits)).toThrow(TimestampError);
                try {
                    assertValidOperationBudgetLimits(limits);
                    expect.unreachable();
                } catch (error) {
                    expect((error as TimestampError).code).toBe(
                        TimestampErrorCode.INVALID_ARGUMENT
                    );
                }
            }
        });

        it("accepts zero limits (collect nothing of that kind)", () => {
            const budget = own(
                new OperationBudget({
                    maxAttempts: 0,
                    maxBytes: 0,
                    maxCertificates: 0,
                    maxUrlsPerCertificate: 0,
                    maxElapsedMs: 0,
                })
            );
            expect(budget.tryStartAttempt()).toBe(false);
            expect(budget.admitCertificate()).toBe(false);
            expect(budget.claimUrl("cert", "http://aia.example.com/ca.cer")).toBe(false);
        });

        it("rejects a non-finite checkTime", () => {
            expect(() => new OperationBudget({}, { checkTime: new Date(Number.NaN) })).toThrow(
                TimestampError
            );
        });
    });

    describe("attempts and bytes", () => {
        it("admits exactly maxAttempts attempts, then refuses and aborts", () => {
            const budget = own(new OperationBudget({ maxAttempts: 2 }));
            expect(budget.tryStartAttempt()).toBe(true);
            expect(budget.tryStartAttempt()).toBe(true);
            expect(budget.signal.aborted).toBe(false);
            expect(budget.tryStartAttempt()).toBe(false);
            expect(budget.exhausted).toBe(true);
            expect(budget.signal.aborted).toBe(true);
            expect(budget.signal.reason).toBeInstanceOf(TimestampError);
        });

        it("flags exhaustion on tipping bytes without aborting the delivering call", () => {
            const budget = own(new OperationBudget({ maxBytes: 150 }));
            budget.addBytes(100);
            expect(budget.exhausted).toBe(false);
            budget.addBytes(100);
            // Tipped over: flagged, but the delivering call is not suicided.
            expect(budget.exhausted).toBe(true);
            expect(budget.signal.aborted).toBe(false);
            // The next dispatch is refused, and only then is I/O aborted.
            expect(budget.tryStartAttempt()).toBe(false);
            expect(budget.signal.aborted).toBe(true);
        });

        it("reports NETWORK_ERROR for spent counts and TIMEOUT for elapsed", () => {
            const attempts = own(new OperationBudget({ maxAttempts: 1 }));
            attempts.tryStartAttempt();
            attempts.tryStartAttempt();
            expect(attempts.exhaustionError().code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(attempts.exhaustionError().message).toMatch(/attempt limit/);

            const bytes = own(new OperationBudget({ maxBytes: 10 }));
            bytes.addBytes(11);
            expect(bytes.exhaustionError().code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(bytes.exhaustionError().message).toMatch(/byte limit/);

            let now = 1000;
            const elapsed = own(new OperationBudget({ maxElapsedMs: 50 }, { clock: () => now }));
            now = 2000;
            expect(elapsed.isElapsed()).toBe(true);
            expect(elapsed.exhaustionError().code).toBe(TimestampErrorCode.TIMEOUT);
            expect(elapsed.exhaustionError().message).toMatch(/elapsed limit/);
        });

        it("treats bytes exactly at the cap as not yet exhausted", () => {
            // M4: the byte cap trips on tipping OVER (bytes > maxBytes);
            // exact-cap is pinned against drift.
            const budget = own(new OperationBudget({ maxBytes: 150 }));
            budget.addBytes(150);
            expect(budget.exhausted).toBe(false);
            budget.addBytes(1);
            expect(budget.exhausted).toBe(true);
        });

        it("reports a neutral reason when spent with no counter or elapsed clock", async () => {
            // P2-4: the deadline timer can fire while an injected clock
            // stays frozen (mixed clocks): done with no spent counter and
            // no elapsed validation clock must not masquerade as a
            // byte-limit breach.
            const budget = own(new OperationBudget({ maxElapsedMs: 10 }, { clock: () => 5000 }));
            await new Promise((resolve) => setTimeout(resolve, 50));
            expect(budget.signal.aborted).toBe(true);
            expect(budget.isElapsed()).toBe(false);
            const error = budget.exhaustionError();
            expect(error.code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(error.message).toMatch(/already spent/);
        });
    });

    describe("certificates and per-cert URLs", () => {
        it("admits exactly maxCertificates certificates", () => {
            const budget = own(new OperationBudget({ maxCertificates: 1 }));
            expect(budget.admitCertificate()).toBe(true);
            expect(budget.admitCertificate()).toBe(false);
            // Admission refusals are not global exhaustion: in-flight I/O
            // is untouched.
            expect(budget.signal.aborted).toBe(false);
        });

        it("tracks unique URLs per certificate independently", () => {
            const budget = own(new OperationBudget({ maxUrlsPerCertificate: 1 }));
            expect(budget.seenUrl("cert-a", "http://aia.example.com/1.cer")).toBe(false);
            expect(budget.claimUrl("cert-a", "http://aia.example.com/1.cer")).toBe(true);
            expect(budget.seenUrl("cert-a", "http://aia.example.com/1.cer")).toBe(true);
            // Same cert, second unique URL: refused.
            expect(budget.claimUrl("cert-a", "http://aia.example.com/2.cer")).toBe(false);
            // Another cert gets its own allowance.
            expect(budget.claimUrl("cert-b", "http://aia.example.com/2.cer")).toBe(true);
        });
    });

    describe("elapsed deadline and check time", () => {
        it("aborts the signal with a TIMEOUT exhaustion error at the deadline", () => {
            vi.useFakeTimers();
            const budget = own(new OperationBudget({ maxElapsedMs: 50 }));
            expect(budget.signal.aborted).toBe(false);
            vi.advanceTimersByTime(49);
            expect(budget.signal.aborted).toBe(false);
            vi.advanceTimersByTime(1);
            expect(budget.signal.aborted).toBe(true);
            const reason = budget.signal.reason as TimestampError;
            expect(reason).toBeInstanceOf(TimestampError);
            expect(reason.code).toBe(TimestampErrorCode.TIMEOUT);
            expect(reason.message).toMatch(/operation budget exhausted/);
            expect(budget.tryStartAttempt()).toBe(false);
        });

        it("honours an injected monotonic clock", () => {
            let now = 5000;
            const budget = own(new OperationBudget({ maxElapsedMs: 100 }, { clock: () => now }));
            expect(budget.isElapsed()).toBe(false);
            expect(budget.tryStartAttempt()).toBe(true);
            now = 5100;
            expect(budget.isElapsed()).toBe(true);
            expect(budget.exhausted).toBe(true);
            expect(budget.tryStartAttempt()).toBe(false);
        });

        it("captures one check time per budget and never aliases the input", () => {
            const input = new Date("2024-06-01T12:00:00Z");
            const budget = own(new OperationBudget({}, { checkTime: input }));
            expect(budget.checkTime.getTime()).toBe(input.getTime());
            expect(budget.checkTime).not.toBe(input);
            input.setTime(0);
            expect(budget.checkTime.getTime()).toBe(new Date("2024-06-01T12:00:00Z").getTime());

            const before = Date.now();
            const implicit = own(new OperationBudget());
            expect(implicit.checkTime.getTime()).toBeGreaterThanOrEqual(before);
            expect(implicit.checkTime.getTime()).toBeLessThanOrEqual(Date.now());
        });

        it("dispose releases the deadline timer", () => {
            vi.useFakeTimers();
            const budget = new OperationBudget({ maxElapsedMs: 50 });
            budget.dispose();
            vi.advanceTimersByTime(1000);
            // No abort fires (timer released), but the clock still
            // enforces the deadline fail-closed on the next dispatch.
            expect(budget.signal.aborted).toBe(false);
            expect(budget.tryStartAttempt()).toBe(false);
        });
    });

    describe("countCustomFetch", () => {
        it("hands our accounting closure the live budget (internal only)", async () => {
            const budget = own(new OperationBudget({}));
            let observed: CustomFetchContext | undefined;
            const bytes = await budget.countCustomFetch("OCSP", 1024, async (context) => {
                observed = context;
                return new Uint8Array([1, 2, 3]);
            });
            expect(bytes).toEqual(new Uint8Array([1, 2, 3]));
            expect(observed?.signal).toBe(budget.signal);
            // Internal by design: the live budget reaches our closure
            // for accounting; the closure must hand the fetcher a fresh
            // signal-only object (pinned at session/LTV level, R19).
            expect(observed?.budget).toBe(budget);
        });

        it("refuses the call once the attempt budget is spent", async () => {
            const budget = own(new OperationBudget({ maxAttempts: 0 }));
            let called = false;
            await expect(
                budget.countCustomFetch("OCSP", 1024, () => {
                    called = true;
                    return Promise.resolve(new Uint8Array([1]));
                })
            ).rejects.toThrow(/operation budget exhausted/);
            expect(called).toBe(false);
        });

        it("rejects over-cap returns", async () => {
            const budget = own(new OperationBudget({}));
            await expect(
                budget.countCustomFetch("CRL", 2, () => Promise.resolve(new Uint8Array([1, 2, 3])))
            ).rejects.toThrow(/exceeds/);
        });

        it("refuses custom returns past the elapsed deadline with an unaborted signal (fix round 4, F2)", async () => {
            // F2c: a fetcher holding the event loop starves the deadline
            // timer, so signal state stays green; only the monotonic clock
            // observes the elapsed deadline.
            const budget = own(new OperationBudget({ maxElapsedMs: 5 }));
            await expect(
                budget.countCustomFetch("CRL", 1024, () => {
                    const start = Date.now();
                    while (Date.now() - start < 50) {
                        // Hold the loop past the deadline: the timer
                        // callback cannot run until this returns.
                    }
                    return Promise.resolve(new Uint8Array([1, 2, 3]));
                })
            ).rejects.toThrow(/operation budget exhausted/);
            // The timer never fired: the refusal came from the clock, not
            // the signal.
            expect(budget.signal.aborted).toBe(false);
        });
    });
});
