import { describe, it, expect } from "vitest";
import { parseTimestampResponse, validateTimestampResponse } from "../../../core/src/tsa/response.js";
import { TimestampError, TSAStatus } from "../../../core/src/types.js";

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

        it("should handle responses with minimum valid size boundary", () => {
            // Test exactly at the boundary of minimum size check
            const boundaryResponse = new Uint8Array(10); // Just under 11 bytes
            expect(() => parseTimestampResponse(boundaryResponse)).toThrow("too small");

            const validMinResponse = new Uint8Array(11); // Exactly 11 bytes
            expect(() => parseTimestampResponse(validMinResponse)).toThrow(TimestampError);
            expect(() => parseTimestampResponse(validMinResponse)).not.toThrow("too small");
        });

        it("should handle responses with various invalid status codes", () => {
            // Test different invalid status scenarios
            const invalidStatuses = [
                new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x03]), // status = 3
                new Uint8Array([0x30, 0x05, 0x02, 0x01, 0x06]), // status = 6
            ];

            invalidStatuses.forEach((invalidResponse) => {
                expect(() => parseTimestampResponse(invalidResponse)).toThrow(TimestampError);
            });
        });

        it("should allow status 4 (REVOCATION_WARNING) and 5 (REVOCATION_NOTIFICATION)", () => {
            // Mock responses with status 4 and 5 (at least 11 bytes to pass size check)
            // SEQUENCE(0x30) len 0x09 -> PKIStatusInfo SEQUENCE(0x30) len 0x03 -> status(0x02, 0x01, 0x04)
            // We'll just pad it to 11 bytes.
            const warningResponse = new Uint8Array([0x30, 0x09, 0x30, 0x03, 0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x00]);
            const notificationResponse = new Uint8Array([0x30, 0x09, 0x30, 0x03, 0x02, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00]);

            expect(() => parseTimestampResponse(warningResponse)).toThrow("no token found");
            expect(() => parseTimestampResponse(notificationResponse)).toThrow("no token found");
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

        it("should handle case insensitive hex comparison", () => {
            const hash = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "deadbeef", // lowercase
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, hash, "SHA-256");
            expect(result).toBe(true);
        });

        it("should handle uppercase hex in response", () => {
            const hash = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "DEADBEEF", // uppercase
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, hash, "SHA-256");
            expect(result).toBe(true);
        });

        it("should handle different hash lengths", () => {
            // SHA-384 (48 bytes)
            const sha384Hash = new Uint8Array(48).fill(0xab);
            const sha384Hex = "ab".repeat(48);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-384",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.2",
                messageDigest: sha384Hex,
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, sha384Hash, "SHA-384");
            expect(result).toBe(true);
        });

        it("should reject when hash lengths don't match hex string", () => {
            // 32-byte hash but 40-character hex (should be 64 for 32 bytes)
            const hash = new Uint8Array(32).fill(0x01);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "01".repeat(20), // Only 40 chars instead of 64
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, hash, "SHA-256");
            expect(result).toBe(false);
        });

        it("should handle empty hash arrays", () => {
            const emptyHash = new Uint8Array(0);
            const info = {
                genTime: new Date(),
                policy: "1.2.3",
                serialNumber: "1234",
                hashAlgorithm: "SHA-256",
                hashAlgorithmOID: "2.16.840.1.101.3.4.2.1",
                messageDigest: "",
                hasCertificate: true,
            };

            const result = validateTimestampResponse(info, emptyHash, "SHA-256");
            expect(result).toBe(true);
        });
    });
});
