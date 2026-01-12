/**
 * Synthetic TSA Response Error Handling Tests
 *
 * This test suite covers error handling with synthetic responses:
 * - Malformed responses (truncated, invalid structure, wrong type, empty)
 * - Timeout scenarios
 * - Fixture validation
 */

import { describe, it, expect } from "vitest";
import { parseTimestampResponse } from "../../../core/src/tsa/response.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import {
    SYNTHETIC_FIXTURES,
    generateMalformedResponse,
    generateTimeoutResponse,
    FAIL_INFO_CODES,
} from "./synthetic-responses.js";

describe("TSA Response Parsing - Error Handling", () => {
    describe("Malformed Responses", () => {
        it("should throw INVALID_RESPONSE for truncated data", () => {
            const response = generateMalformedResponse("truncated");
            expect(() => parseTimestampResponse(response)).toThrow(TimestampError);
            try {
                parseTimestampResponse(response);
            } catch (error) {
                expect(error instanceof TimestampError).toBe(true);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            }
        });

        it("should handle empty response gracefully", () => {
            const response = generateMalformedResponse("empty");
            expect(() => parseTimestampResponse(response)).toThrow(TimestampError);
        });

        it("should throw for response too small to be valid", () => {
            const response = new Uint8Array([0x30, 0x02]);
            expect(() => parseTimestampResponse(response)).toThrow(TimestampError);
        });

        it("should throw for invalid ASN.1 structure", () => {
            const response = generateMalformedResponse("invalid");
            expect(() => parseTimestampResponse(response)).toThrow(TimestampError);
        });
    });

    describe("Timeout Handling", () => {
        it("should throw for empty timeout response", () => {
            const response = generateTimeoutResponse();
            expect(() => parseTimestampResponse(response)).toThrow(TimestampError);
        });
    });

    describe("Synthetic Fixtures Export", () => {
        it("should have all required fixture functions", () => {
            expect(typeof SYNTHETIC_FIXTURES.granted).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.grantedWithMods).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.rejection).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.waiting).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.timeout).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.malformedTruncated).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.malformedEmpty).toBe("function");
            expect(typeof SYNTHETIC_FIXTURES.malformedInvalidStructure).toBe("function");
        });

        it("should generate valid Uint8Array responses", () => {
            const granted = SYNTHETIC_FIXTURES.granted();
            expect(granted).toBeInstanceOf(Uint8Array);
            expect(granted.length).toBeGreaterThan(0);

            const rejection = SYNTHETIC_FIXTURES.rejection();
            expect(rejection).toBeInstanceOf(Uint8Array);
            expect(rejection.length).toBeGreaterThan(0);
        });

        it("should generate responses with minimum size", () => {
            const granted = SYNTHETIC_FIXTURES.granted();
            expect(granted.length).toBeGreaterThanOrEqual(11);
        });

        it("should generate malformed responses with expected sizes", () => {
            const truncated = generateMalformedResponse("truncated");
            expect(truncated.length).toBe(4);

            const empty = generateMalformedResponse("empty");
            expect(empty.length).toBe(0);

            const invalid = generateMalformedResponse("invalid");
            expect(invalid.length).toBe(3);
        });
    });

    describe("FAIL_INFO_CODES constants", () => {
        it("should have all expected fail info codes", () => {
            expect(FAIL_INFO_CODES.BAD_ALGORITHM).toBe(0);
            expect(FAIL_INFO_CODES.BAD_REQUEST).toBe(1);
            expect(FAIL_INFO_CODES.BAD_DATA_FORMAT).toBe(2);
            expect(FAIL_INFO_CODES.TIME_NOT_AVAILABLE).toBe(3);
            expect(FAIL_INFO_CODES.UNADDED_POLICY).toBe(4);
            expect(FAIL_INFO_CODES.UNSUPPORTED_OPTS).toBe(5);
            expect(FAIL_INFO_CODES.POLICY_MISMATCH).toBe(6);
            expect(FAIL_INFO_CODES.REQUEST_INITIALLY_REJECTED).toBe(7);
            expect(FAIL_INFO_CODES.REQUEST_RETRY).toBe(8);
        });
    });
});
