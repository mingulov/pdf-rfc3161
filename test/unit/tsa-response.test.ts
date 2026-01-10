import { describe, it, expect } from "vitest";
import { parseTimestampResponse, validateTimestampResponse } from "../../src/tsa/response.js";
import { TimestampError, TSAStatus } from "../../src/types.js";

// A minimal valid TimeStampResp with status=2 (rejection) but no token
// This is for testing error cases
const MINIMAL_REJECTED_RESPONSE = new Uint8Array([
    0x30,
    0x0b, // SEQUENCE (11 bytes)
    0x30,
    0x09, // PKIStatusInfo SEQUENCE (9 bytes)
    0x02,
    0x01,
    0x02, // INTEGER status=2 (rejection)
    0x30,
    0x04, // statusString SEQUENCE (4 bytes)
    0x0c,
    0x02,
    0x65,
    0x72, // UTF8String "er"
]);

describe("TSA Response", () => {
    describe("parseTimestampResponse", () => {
        it("should throw on invalid ASN.1", () => {
            const invalidData = new Uint8Array([0x00, 0x01, 0x02]);

            expect(() => parseTimestampResponse(invalidData)).toThrow(TimestampError);
        });

        it("should throw on empty input", () => {
            const emptyData = new Uint8Array(0);

            expect(() => parseTimestampResponse(emptyData)).toThrow(TimestampError);
        });

        it("should parse rejected response", () => {
            const result = parseTimestampResponse(MINIMAL_REJECTED_RESPONSE);

            expect(result.status).toBe(TSAStatus.REJECTION);
            expect(result.token).toBeUndefined();
        });

        it("should handle malformed responses gracefully", () => {
            // Random bytes that look like ASN.1 but are invalid
            const malformed = new Uint8Array([0x30, 0x82, 0x00, 0x10]);

            expect(() => parseTimestampResponse(malformed)).toThrow(TimestampError);
        });
    });

    describe("validateTimestampResponse", () => {
        it("should validate matching hash", () => {
            const hash = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "01020304",
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, hash, "SHA-256");
            expect(result).toBe(true);
        });

        it("should reject mismatched hash", () => {
            const hash = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "deadbeef", // Different hash
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, hash, "SHA-256");
            expect(result).toBe(false);
        });

        it("should reject mismatched algorithm", () => {
            const hash = new Uint8Array([0x01, 0x02, 0x03, 0x04]);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-384", // Different algorithm
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.2",
                messageDigest: "01020304",
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, hash, "SHA-256");
            expect(result).toBe(false);
        });
    });
});
