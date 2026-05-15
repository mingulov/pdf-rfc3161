import { describe, it, expect } from "vitest";
import { TimestampSession } from "../../../core/src/session.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

// Synthetic PDF bytes for the smallest valid signed-PDF skeleton suffice -- we
// only care about the session state machine, never the cryptographic payload.
const SYNTHETIC_PDF = new Uint8Array([
    0x25, 0x50, 0x44, 0x46, 0x2d, 0x31, 0x2e, 0x37, 0x0a, // %PDF-1.7
]);

describe("TimestampSession dispose() semantics", () => {
    it("dispose before createTimestampRequest blocks the call", async () => {
        const session = new TimestampSession(SYNTHETIC_PDF);
        session.dispose();

        let caught: unknown;
        try {
            await session.createTimestampRequest();
        } catch (e) {
            caught = e;
        }
        expect(caught).toBeInstanceOf(TimestampError);
        expect((caught as TimestampError).code).toBe(TimestampErrorCode.STATE_ERROR);
    });

    it("dispose between createTimestampRequest and embedTimestampToken blocks the embed", async () => {
        const session = new TimestampSession(SYNTHETIC_PDF);
        // We don't need the request to actually succeed -- mid-session dispose
        // is the part under test. Wrap in try since prepare may also throw on
        // this synthetic PDF; either way the session's internal state is set.
        try {
            await session.createTimestampRequest();
        } catch {
            // expected: prepare may fail on synthetic PDF
        }
        session.dispose();

        let caught: unknown;
        try {
            await session.embedTimestampToken(new Uint8Array([0x30]));
        } catch (e) {
            caught = e;
        }
        expect(caught).toBeInstanceOf(TimestampError);
        expect((caught as TimestampError).code).toBe(TimestampErrorCode.STATE_ERROR);
        expect((caught as TimestampError).message).toContain("disposed");
    });

    it("dispose is idempotent", () => {
        const session = new TimestampSession(SYNTHETIC_PDF);
        expect(() => {
            session.dispose();
            session.dispose();
        }).not.toThrow();
    });
});
