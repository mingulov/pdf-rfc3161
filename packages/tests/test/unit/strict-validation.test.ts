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

describe("Strict PAdES Validation", () => {
    it("checks the complete signed ESS binding when strictESSValidation is enabled", async () => {
        const missing = await createRFC3161TokenFixture({ ess: "missing" });
        const result = await verifyTimestamp(extracted(missing.rawToken), { strictESSValidation: true });

        expect(result.verified).toBe(false);
        expect(result.verificationError).toMatch(/ESS|signing-certificate/i);
    });

    it("accepts a real CMS token whose ESS v1 and v2 both bind the selected signer", async () => {
        const fixture = await createRFC3161TokenFixture({
            certificates: "decoyFirst",
            ess: "both",
        });
        const result = await verifyTimestamp(extracted(fixture.rawToken), { strictESSValidation: true });

        expect(result.verified).toBe(true);
        expect(result.certificates).toHaveLength(2);
    });

    it("keeps the historical ESS opt-out only in post-embed verification", async () => {
        const missing = await createRFC3161TokenFixture({ ess: "missing" });
        const result = await verifyTimestamp(extracted(missing.rawToken), { strictESSValidation: false });

        expect(result.verified).toBe(true);
    });
});
