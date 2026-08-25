import { describe, it, expect } from "vitest";
import * as pkijs from "pkijs";
import { verifyTimestamp, ExtractedTimestamp } from "../../../core/src/pdf/extract.js";
import { TimestampInfo } from "../../../core/src/types.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";

describe("Certificate Export", () => {
    it("should return certificates in validation result", async () => {
        const fixture = await createRFC3161TokenFixture();

        const timestamp: ExtractedTimestamp = {
            token: fixture.rawToken,
            contentsValueBytes: fixture.rawToken.slice(),
            info: {} as TimestampInfo,
            fieldName: "Test",
            coversWholeDocument: true,
            verified: true,
            byteRange: [0, 0, 0, 0],
        };

        const result = await verifyTimestamp(timestamp);

        expect(result.verified).toBe(true);
        expect(result.certificates).toBeDefined();
        const certs = result.certificates ?? [];
        expect(certs).toHaveLength(1);
        expect(certs[0]).toBeInstanceOf(pkijs.Certificate);
    });
});
