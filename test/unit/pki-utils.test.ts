import { describe, it, expect } from "vitest";
import { parseTimestampToken } from "../../src/pki/pki-utils.js";
import { TimestampError } from "../../src/types.js";

describe("PKI Utils", () => {
    describe("parseTimestampToken", () => {
        it("should throw error for invalid ASN.1 data", () => {
            const invalidToken = new Uint8Array([0x00, 0x01, 0x02]); // Invalid ASN.1

            expect(() => parseTimestampToken(invalidToken)).toThrow();
        });

        it("should handle empty token", () => {
            const emptyToken = new Uint8Array([]);

            expect(() => parseTimestampToken(emptyToken)).toThrow(TimestampError);
        });

        it("should handle malformed token data", () => {
            // Token that's valid ASN.1 but not a proper ContentInfo
            const malformedToken = new Uint8Array([
                0x30,
                0x03, // SEQUENCE with length 3
                0x02,
                0x01,
                0x01, // INTEGER 1
            ]);

            expect(() => parseTimestampToken(malformedToken)).toThrow();
        });

        it("should throw errors for invalid tokens", () => {
            const invalidToken = new Uint8Array([0x00]);

            expect(() => parseTimestampToken(invalidToken)).toThrow();
        });

        it("should handle very large invalid tokens", () => {
            const largeInvalidToken = new Uint8Array(10000).fill(0xff);

            expect(() => parseTimestampToken(largeInvalidToken)).toThrow(TimestampError);
        });

        it("should handle tokens with unusual ASN.1 structures", () => {
            // Valid ASN.1 SEQUENCE but not ContentInfo
            const unusualToken = new Uint8Array([
                0x30,
                0x0a, // SEQUENCE
                0x06,
                0x03,
                0x2a,
                0x03,
                0x04, // OID
                0x04,
                0x03,
                0x01,
                0x02,
                0x03, // OCTET STRING
            ]);

            expect(() => parseTimestampToken(unusualToken)).toThrow(TimestampError);
        });

        it("should handle tokens with truncated data", () => {
            const truncatedToken = new Uint8Array([0x30, 0x10, 0x02, 0x01]); // Incomplete

            expect(() => parseTimestampToken(truncatedToken)).toThrow(TimestampError);
        });
    });

    describe("Error handling edge cases", () => {
        it("should handle null-like input", () => {
            // Test with zero-length array
            const emptyToken = new Uint8Array(0);

            expect(() => parseTimestampToken(emptyToken)).toThrow(TimestampError);
        });

        it("should handle tokens with specific invalid patterns", () => {
            // Test various invalid patterns that might cause different error paths
            const patterns = [
                new Uint8Array([0x30, 0x00]), // Empty sequence
                new Uint8Array([0x30, 0x01, 0x00]), // Sequence with invalid content
                new Uint8Array([0x06, 0x01, 0x00]), // Just an OID
                new Uint8Array([0x04, 0x01, 0x00]), // Just an octet string
            ];

            for (const pattern of patterns) {
                expect(() => parseTimestampToken(pattern)).toThrow(TimestampError);
            }
        });
    });

    describe("Function exports", () => {
        it("should export parseTimestampToken function", () => {
            expect(typeof parseTimestampToken).toBe("function");
        });

        it("should have correct function signature", () => {
            // Function should accept Uint8Array and return TimestampInfo
            expect(parseTimestampToken.length).toBe(1);
        });
    });

    describe("TimestampError integration", () => {
        it("should throw TimestampError with correct error codes", () => {
            const invalidToken = new Uint8Array([0x00]);

            try {
                parseTimestampToken(invalidToken);
                expect(true).toBe(false); // Should not reach here
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                const tsError = error as TimestampError;
                expect(tsError.code).toBeDefined();
                expect(typeof tsError.message).toBe("string");
            }
        });

        it("should include error cause when available", () => {
            const invalidToken = new Uint8Array([]);

            try {
                parseTimestampToken(invalidToken);
                expect(true).toBe(false); // Should not reach here
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                const tsError = error as TimestampError;
                expect(tsError.message).toContain("parse");
            }
        });
    });

    describe("Input validation", () => {
        it("should reject non-Uint8Array inputs", () => {
            // TypeScript prevents this at compile time, but test runtime behavior
            expect(() => {
                // @ts-expect-error Testing runtime behavior
                parseTimestampToken("not a uint8array");
            }).toThrow();
        });

        it("should handle sparse arrays", () => {
            const sparseArray = new Uint8Array(10);
            sparseArray[0] = 0x30; // SEQUENCE
            sparseArray[1] = 0x08; // Length

            expect(() => parseTimestampToken(sparseArray)).toThrow(TimestampError);
        });

        it("should handle arrays with only zeros", () => {
            const zeroArray = new Uint8Array(10).fill(0);

            expect(() => parseTimestampToken(zeroArray)).toThrow(TimestampError);
        });

        it("should handle arrays with only ones", () => {
            const onesArray = new Uint8Array(10).fill(0xff);

            expect(() => parseTimestampToken(onesArray)).toThrow(TimestampError);
        });
    });

    describe("ASN.1 parsing behavior", () => {
        it("should handle different ASN.1 tag classes", () => {
            // Universal class (0x00)
            const universalTag = new Uint8Array([0x30, 0x00]);
            expect(() => parseTimestampToken(universalTag)).toThrow(TimestampError);

            // Context-specific class (0x80)
            const contextTag = new Uint8Array([0xb0, 0x00]);
            expect(() => parseTimestampToken(contextTag)).toThrow(TimestampError);
        });

        it("should handle indefinite length encoding", () => {
            // Indefinite length (0x80)
            const indefiniteLength = new Uint8Array([0x30, 0x80, 0x00, 0x00]);
            expect(() => parseTimestampToken(indefiniteLength)).toThrow(TimestampError);
        });

        it("should handle long form length encoding", () => {
            // Long form length
            const longForm = new Uint8Array([0x30, 0x81, 0x01, 0x00]);
            expect(() => parseTimestampToken(longForm)).toThrow(TimestampError);
        });
    });

    describe("Memory and performance", () => {
        it("should handle reasonable token sizes", () => {
            // Test with various reasonable sizes
            const sizes = [100, 1000, 10000, 50000];

            for (const size of sizes) {
                const token = new Uint8Array(size).fill(0x30);
                expect(() => parseTimestampToken(token)).toThrow(TimestampError);
            }
        });

        it("should not cause stack overflow with deep structures", () => {
            // Create a token that might cause deep recursion
            const deepToken = new Uint8Array(1000);
            for (let i = 0; i < deepToken.length; i += 2) {
                deepToken[i] = 0x30; // SEQUENCE
                deepToken[i + 1] = 0x00; // Empty
            }

            expect(() => parseTimestampToken(deepToken)).toThrow(); // Can throw any error
        });
    });
});
