import { describe, it, expect, beforeEach } from "vitest";
import {
    getDefaultTrustStore,
    resetDefaultTrustStoreCache,
} from "../../../core/src/pki/default-trust-store.js";
import {
    TimestampError,
    TimestampErrorCode,
    type VerificationOptions,
} from "../../../core/src/types.js";

// Audit H3 (0.2.0): getDefaultTrustStore() previously returned an empty
// "usable" store with a one-time warn when the bundle was empty. This
// invited misuse -- a custom TrustStore wrapping the empty default might
// return `true` from verifyChain on no roots, silently accepting any chain.
// The fix: throw STATE_ERROR until the bundle is populated.

describe("getDefaultTrustStore (audit H3)", () => {
    beforeEach(() => {
        resetDefaultTrustStoreCache();
    });

    it("throws STATE_ERROR when the bundle is empty", () => {
        let caught: unknown;
        try {
            getDefaultTrustStore();
        } catch (e) {
            caught = e;
        }
        expect(caught).toBeInstanceOf(TimestampError);
        expect((caught as TimestampError).code).toBe(TimestampErrorCode.STATE_ERROR);
        expect((caught as TimestampError).message).toMatch(/empty/);
    });

    it("error message guides callers to the three correct responses", () => {
        let caught: unknown;
        try {
            getDefaultTrustStore();
        } catch (e) {
            caught = e;
        }
        const msg = (caught as TimestampError).message;
        // Help text should point to SimpleTrustStore custom-pin, the
        // explicit-null opt-out, and the future curated bundle.
        expect(msg).toMatch(/SimpleTrustStore/);
        expect(msg).toMatch(/addCertificate/);
        expect(msg).toMatch(/trustStore: null/);
    });

    it("is idempotent: subsequent calls also throw (no cached empty store)", () => {
        expect(() => getDefaultTrustStore()).toThrow(TimestampError);
        expect(() => getDefaultTrustStore()).toThrow(TimestampError);
    });

    it("resetDefaultTrustStoreCache() does not change throw behaviour on empty bundle", () => {
        expect(() => getDefaultTrustStore()).toThrow(TimestampError);
        resetDefaultTrustStoreCache();
        expect(() => getDefaultTrustStore()).toThrow(TimestampError);
    });

    // Audit F3: the error message and MIGRATION.md recommend
    // `{ trustStore: null }` as the explicit opt-out. The
    // `VerificationOptions.trustStore` type was originally `TrustStore | undefined`
    // (optional only), so passing `null` failed type-checking. The fix widens
    // the type to `TrustStore | null`; this test ensures the recommended
    // migration compiles.
    it("VerificationOptions.trustStore accepts `null` per audit F3 escape hatch", () => {
        // Compile-time: this line must typecheck against current
        // VerificationOptions. If `trustStore?: TrustStore` ever narrows
        // again, tsc will reject this assignment.
        const optsWithNull: VerificationOptions = { trustStore: null };
        expect(optsWithNull.trustStore).toBeNull();

        // The omitted form must also still typecheck.
        const optsOmitted: VerificationOptions = {};
        expect(optsOmitted.trustStore).toBeUndefined();
    });
});
