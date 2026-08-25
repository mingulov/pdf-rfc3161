import { describe, expect, it } from "vitest";
import { verifyTimestamp, type ExtractedTimestamp } from "../../../core/src/pdf/extract.js";
import type { TimestampInfo } from "../../../core/src/types.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

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
});
