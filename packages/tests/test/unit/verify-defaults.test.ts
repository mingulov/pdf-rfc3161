import { describe, expect, it, vi } from "vitest";
import { verifyTimestamp, type ExtractedTimestamp } from "../../../core/src/pdf/extract.js";
import { TimestampError, TimestampErrorCode, type TimestampInfo } from "../../../core/src/types.js";
import type { TrustStore } from "../../../core/src/pki/trust-store.js";
import type { ParsedTimestampToken } from "../../../core/src/tsa/token-validation.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

// Partial mock: every strict-parser call delegates to the real
// implementation unless a test overrides it once. Existing tests in this
// file keep exercising the production parser.
const parseStrictHolder = vi.hoisted(() => ({
    real: undefined as unknown as (bytes: Uint8Array) => unknown,
}));
const parseStrictSpy = vi.hoisted(() =>
    vi.fn((bytes: Uint8Array) => parseStrictHolder.real(bytes))
);

vi.mock(
    "../../../core/src/tsa/token-validation.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => {
        const original =
            await importOriginal<typeof import("../../../core/src/tsa/token-validation.js")>();
        parseStrictHolder.real = original.parseTimestampToken as (bytes: Uint8Array) => unknown;
        return { ...original, parseTimestampToken: parseStrictSpy };
    }
);

function extracted(token: Uint8Array): ExtractedTimestamp {
    return {
        token,
        contentsValueBytes: token.slice(),
        info: {} as TimestampInfo,
        fieldName: "Timestamp",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
}

describe("verifyTimestamp legacy opt-outs", () => {
    it("accepts a self-consistent strict-profile token without assuming TSA trust", async () => {
        const fixture = await createRFC3161TokenFixture();
        const result = await verifyTimestamp(extracted(fixture.rawToken));

        expect(result.verified).toBe(true);
    });

    it("defaults to a critical, exclusive timestamping EKU", async () => {
        const fixture = await createRFC3161TokenFixture({ eku: "noncritical" });

        const strict = await verifyTimestamp(extracted(fixture.rawToken));
        expect(strict.verified).toBe(false);
        expect(strict.verificationError).toMatch(/critical exclusive/i);
        expect(strict.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);

        const legacy = await verifyTimestamp(extracted(fixture.rawToken), {
            requireTimestampingEKU: false,
        });
        expect(legacy.verified).toBe(true);
    });

    it("defaults to checking the SID-selected certificate at the token generation time", async () => {
        const fixture = await createRFC3161TokenFixture({ certificateValidity: "expired" });

        const strict = await verifyTimestamp(extracted(fixture.rawToken));
        expect(strict.verified).toBe(false);
        expect(strict.verificationError).toMatch(/not valid at genTime/i);
        expect(strict.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);

        const legacy = await verifyTimestamp(extracted(fixture.rawToken), {
            requireCertValidAtGenTime: false,
        });
        expect(legacy.verified).toBe(true);
    });

    it("allows both post-embed historical opt-outs together without weakening the embed gate", async () => {
        const fixture = await createRFC3161TokenFixture({
            eku: "noncritical",
            certificateValidity: "expired",
        });
        const result = await verifyTimestamp(extracted(fixture.rawToken), {
            requireTimestampingEKU: false,
            requireCertValidAtGenTime: false,
        });

        expect(result.verified).toBe(true);
    });

    it("codes a token with no genTime as VERIFICATION_FAILED", async () => {
        const fixture = await createRFC3161TokenFixture();
        parseStrictSpy.mockImplementationOnce((bytes: Uint8Array) => {
            const parsed = parseStrictHolder.real(bytes) as ParsedTimestampToken;
            return {
                ...parsed,
                info: { ...parsed.info, genTime: "not-a-date" as unknown as Date },
            };
        });

        const result = await verifyTimestamp(extracted(fixture.rawToken));

        expect(result.verified).toBe(false);
        expect(result.verificationError).toMatch(/no genTime/);
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.VERIFICATION_FAILED);
    });

    it("maps a TimestampError thrown inside verification to its own code", async () => {
        const fixture = await createRFC3161TokenFixture();
        const store = {
            addCertificate: () => undefined,
            verifyChain: async () => {
                throw new TimestampError(TimestampErrorCode.TSA_ERROR, "boom-tsa");
            },
        } as TrustStore;

        const result = await verifyTimestamp(extracted(fixture.rawToken), {
            trustStore: store,
        });

        expect(result.verified).toBe(false);
        expect(result.verificationError).toBe("boom-tsa");
        expect(result.verificationErrorCode).toBe(TimestampErrorCode.TSA_ERROR);
    });
});
