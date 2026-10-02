import { describe, it, expect } from "vitest";
import { KNOWN_TSA_URLS } from "../../../core/src/tsa-urls.js";

describe("KNOWN_TSA_URLS", () => {
    it("should contain all expected TSA entries", () => {
        // Pinned exhaustively: the registry is the library's TSA
        // address book, so a renamed key or a changed endpoint must
        // fail here rather than silently pointing elsewhere.
        expect(KNOWN_TSA_URLS).toEqual({
            DIGICERT: "http://timestamp.digicert.com",
            SECTIGO: "https://timestamp.sectigo.com",
            COMODO: "http://timestamp.comodoca.com",
            GLOBALSIGN: "http://timestamp.globalsign.com/tsa/r6advanced1",
            ENTRUST: "http://timestamp.entrust.net/TSS/RFC3161sha2TS",
            QUOVADIS: "http://ts.quovadisglobal.com/eu",
            FREETSA: "https://freetsa.org/tsr",
            AIMODA: "https://rfc3161.ai.moda/tsa",
            CODEGIC: "http://pki.codegic.com/codegic-service/timestamp",
        });
    });

    it("should have valid URLs for all entries", () => {
        for (const url of Object.values(KNOWN_TSA_URLS)) {
            const parsed = new URL(url);
            expect(parsed.protocol === "http:" || parsed.protocol === "https:").toBe(true);
            expect(parsed.hostname.length).toBeGreaterThan(0);
        }
    });
});
