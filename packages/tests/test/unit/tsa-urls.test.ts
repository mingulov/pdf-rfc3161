import { describe, it, expect } from "vitest";
import { KNOWN_TSA_URLS } from "../../../core/src/tsa-urls.js";

describe("KNOWN_TSA_URLS", () => {
    it("should contain all expected TSA entries", () => {
        const expectedKeys = [
            "DIGICERT",
            "SECTIGO",
            "COMODO",
            "GLOBALSIGN",
            "ENTRUST",
            "QUOVADIS",
            "FREETSA",
            "AIMODA",
            "CODEGIC",
        ];
        for (const key of expectedKeys) {
            expect(KNOWN_TSA_URLS).toHaveProperty(key);
        }
    });

    it("should have valid URLs for all entries", () => {
        for (const url of Object.values(KNOWN_TSA_URLS)) {
            expect(typeof url).toBe("string");
            expect(url.startsWith("http://") || url.startsWith("https://")).toBe(true);
            // Basic URL validation
            expect(() => new URL(url)).not.toThrow();
        }
    });

    it("should have correct values for key TSAs", () => {
        expect(KNOWN_TSA_URLS.DIGICERT).toBe("http://timestamp.digicert.com");
        expect(KNOWN_TSA_URLS.SECTIGO).toBe("https://timestamp.sectigo.com");
        expect(KNOWN_TSA_URLS.GLOBALSIGN).toBe("http://timestamp.globalsign.com/tsa/r6advanced1");
    });
});
