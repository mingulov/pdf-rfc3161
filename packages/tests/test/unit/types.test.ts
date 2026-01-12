import { describe, it, expect } from "vitest";
import { TimestampError, TimestampErrorCode, TSAStatus } from "../../../core/src/types.js";

describe("Types and Error Handling", () => {
    describe("TimestampError", () => {
        it("should create error with code and message", () => {
            const error = new TimestampError(TimestampErrorCode.NETWORK_ERROR, "Connection failed");

            expect(error).toBeInstanceOf(Error);
            expect(error).toBeInstanceOf(TimestampError);
            expect(error.code).toBe(TimestampErrorCode.NETWORK_ERROR);
            expect(error.message).toBe("Connection failed");
            expect(error.name).toBe("TimestampError");
        });

        it("should create error with cause", () => {
            const cause = new Error("Original error");
            const error = new TimestampError(TimestampErrorCode.TSA_ERROR, "TSA failed", cause);

            expect(error.cause).toBe(cause);
        });

        it("should have all error codes", () => {
            expect(TimestampErrorCode.NETWORK_ERROR).toBe("NETWORK_ERROR");
            expect(TimestampErrorCode.TSA_ERROR).toBe("TSA_ERROR");
            expect(TimestampErrorCode.INVALID_RESPONSE).toBe("INVALID_RESPONSE");
            expect(TimestampErrorCode.PDF_ERROR).toBe("PDF_ERROR");
            expect(TimestampErrorCode.TIMEOUT).toBe("TIMEOUT");
            expect(TimestampErrorCode.UNSUPPORTED_ALGORITHM).toBe("UNSUPPORTED_ALGORITHM");
        });
    });

    describe("TSAStatus", () => {
        it("should have correct status values", () => {
            expect(TSAStatus.GRANTED).toBe(0);
            expect(TSAStatus.GRANTED_WITH_MODS).toBe(1);
            expect(TSAStatus.REJECTION).toBe(2);
            expect(TSAStatus.WAITING).toBe(3);
            expect(TSAStatus.REVOCATION_WARNING).toBe(4);
            expect(TSAStatus.REVOCATION_NOTIFICATION).toBe(5);
        });
    });
});
