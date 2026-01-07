import { describe, it, expect } from "vitest";
import {
    HASH_ALGORITHM_TO_OID,
    OID_TO_HASH_ALGORITHM,
    DEFAULT_TSA_CONFIG,
    TSA_CONTENT_TYPE,
} from "../../src/constants.js";

describe("Constants", () => {
    describe("HASH_ALGORITHM_TO_OID", () => {
        it("should map SHA-256 to correct OID", () => {
            expect(HASH_ALGORITHM_TO_OID["SHA-256"]).toBe("2.16.840.1.101.3.4.2.1");
        });

        it("should map SHA-384 to correct OID", () => {
            expect(HASH_ALGORITHM_TO_OID["SHA-384"]).toBe("2.16.840.1.101.3.4.2.2");
        });

        it("should map SHA-512 to correct OID", () => {
            expect(HASH_ALGORITHM_TO_OID["SHA-512"]).toBe("2.16.840.1.101.3.4.2.3");
        });
    });

    describe("OID_TO_HASH_ALGORITHM", () => {
        it("should reverse map OIDs to algorithms", () => {
            expect(OID_TO_HASH_ALGORITHM["2.16.840.1.101.3.4.2.1"]).toBe("SHA-256");
            expect(OID_TO_HASH_ALGORITHM["2.16.840.1.101.3.4.2.2"]).toBe("SHA-384");
            expect(OID_TO_HASH_ALGORITHM["2.16.840.1.101.3.4.2.3"]).toBe("SHA-512");
        });
    });

    describe("DEFAULT_TSA_CONFIG", () => {
        it("should have sensible defaults", () => {
            expect(DEFAULT_TSA_CONFIG.hashAlgorithm).toBe("SHA-256");
            expect(DEFAULT_TSA_CONFIG.timeout).toBe(30000);
        });
    });

    describe("TSA_CONTENT_TYPE", () => {
        it("should have correct content types", () => {
            expect(TSA_CONTENT_TYPE.REQUEST).toBe("application/timestamp-query");
            expect(TSA_CONTENT_TYPE.RESPONSE).toBe("application/timestamp-reply");
        });
    });
});
