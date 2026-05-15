import { describe, it, expect, vi, beforeEach } from "vitest";
import type { TimestampOptions } from "../../../core/src/types.js";

// Audit L5: regression-protect the 0.2.0 `enableLTV = true` default in
// `timestampPdf`. The existing unified-api.test.ts test for enableLTV is a
// compile-time `keyof` check on the result type, not a runtime assertion.
// If someone reverts the destructuring default at index.ts:182, no test
// currently catches it.
//
// Strategy: mock the session module so we can observe what `enableLTV` value
// `timestampPdf` passes to the `TimestampSession` constructor. The session
// module is a separate file from index.ts, so vi.mock intercepts cleanly.
// We don't need a real TSA / valid token; the assertion fires on the
// constructor arg before the real signing flow runs.

 
const sessionConstructorSpy = vi.hoisted(() => vi.fn());

vi.mock("../../../core/src/session.js", () => {
    // The session is constructed twice in timestampPdf when optimizePlaceholder
    // is set, and once otherwise. We don't care -- we just want to know what
    // enableLTV was passed.
    // eslint-disable-next-line @typescript-eslint/no-extraneous-class
    class FakeSession {
        constructor(_pdf: Uint8Array, opts: TimestampOptions) {
            sessionConstructorSpy(opts);
            // Throw a sentinel error so timestampPdf bails out before the
            // network call. The sentinel won't be confused with a real
            // production error code.
            throw new Error("FakeSession-sentinel");
        }
        static calculateOptimalSize(): number {
            return 8192;
        }
    }
    return {
        TimestampSession: FakeSession,
    };
});

const { timestampPdf } = await import("../../../core/src/index.js");

describe("timestampPdf option defaults (audit L5)", () => {
    beforeEach(() => {
        sessionConstructorSpy.mockClear();
    });

    // We pass `optimizePlaceholder: true` so timestampPdf enters the
    // optimization branch first (index.ts:202), which constructs the
    // session with the destructured `enableLTV` value VERBATIM. The
    // non-optimize path at line 231 hardcodes `enableLTV: false` (LTV is
    // managed manually downstream); that wouldn't observe the destructure.
    const baseOpts = {
        pdf: new Uint8Array([0x25, 0x50, 0x44, 0x46]),
        tsa: { url: "http://mock.test" },
        optimizePlaceholder: true,
    } as const;

    it("defaults enableLTV to true when caller omits it (0.2.0 flip)", async () => {
        // Optimize-branch swallows the sentinel; non-optimize branch then
        // also throws via the same FakeSession; we expect the rejection.
        await expect(timestampPdf({ ...baseOpts })).rejects.toThrow();

        expect(sessionConstructorSpy).toHaveBeenCalled();
        const firstCallOpts = sessionConstructorSpy.mock.calls[0]?.[0] as {
            enableLTV: boolean;
        };
        // First construction is the optimize-probe; it carries the destructured value.
        expect(firstCallOpts.enableLTV).toBe(true);
    });

    it("preserves enableLTV: false when caller sets it explicitly", async () => {
        await expect(
            timestampPdf({ ...baseOpts, enableLTV: false })
        ).rejects.toThrow();

        const firstCallOpts = sessionConstructorSpy.mock.calls[0]?.[0] as {
            enableLTV: boolean;
        };
        expect(firstCallOpts.enableLTV).toBe(false);
    });

    it("preserves enableLTV: true when caller sets it explicitly", async () => {
        await expect(
            timestampPdf({ ...baseOpts, enableLTV: true })
        ).rejects.toThrow();

        const firstCallOpts = sessionConstructorSpy.mock.calls[0]?.[0] as {
            enableLTV: boolean;
        };
        expect(firstCallOpts.enableLTV).toBe(true);
    });
});
