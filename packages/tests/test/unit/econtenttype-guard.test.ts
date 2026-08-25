import { describe, it, expect } from "vitest";
import { verifyTimestamp, type ExtractedTimestamp } from "../../../core/src/pdf/extract.js";
import { type TimestampInfo } from "../../../core/src/types.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

function makeExtractedTimestamp(token: Uint8Array): ExtractedTimestamp {
    return {
        token,
        contentsValueBytes: token.slice(),
        info: {} as TimestampInfo,
        fieldName: "Test",
        coversWholeDocument: true,
        verified: false,
        byteRange: [0, 0, 0, 0],
    };
}

describe("eContentType guard (H2)", () => {
    it("rejects a SignedData whose eContentType is not id-ct-TSTInfo", async () => {
        const fixture = await createRFC3161TokenFixture({ eContentType: "data" });
        const result = await verifyTimestamp(makeExtractedTimestamp(fixture.rawToken));

        expect(result.verified).toBe(false);
        expect(result.verificationError ?? "").toMatch(/content.?type|TSTInfo/i);
    });

    it("does not reject a SignedData whose eContentType is id-ct-TSTInfo", async () => {
        const fixture = await createRFC3161TokenFixture();
        const result = await verifyTimestamp(makeExtractedTimestamp(fixture.rawToken));

        expect(result.verified).toBe(true);
    });
});
