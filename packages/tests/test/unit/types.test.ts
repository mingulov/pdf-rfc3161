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

        it("pins every error code to its wire string", () => {
            // Error codes serialize into receipts and messages; each
            // member must equal its own key so the wire format cannot
            // drift for one code while the others still match.
            const entries = Object.entries(TimestampErrorCode);
            expect(entries.length).toBeGreaterThan(0);
            for (const [key, value] of entries) {
                expect(value).toBe(key);
            }
        });

        it("survives JSON serialization with the pinned code string", () => {
            const error = new TimestampError(TimestampErrorCode.TSA_ERROR, "TSA failed");
            const revived = JSON.parse(JSON.stringify(error)) as { code: unknown };

            expect(revived.code).toBe("TSA_ERROR");
        });
    });

    describe("TSAStatus", () => {
        it("pins the complete RFC 3161 PKIStatus wire mapping", () => {
            // RFC 3161 section 2.4.2: the status INTEGER on the wire.
            // Pinned exhaustively so a renumbered or added member fails
            // here; response handling keyed off these values is covered
            // in tsa-response.test.ts.
            // Numeric enums also carry reverse mappings; the forward
            // names are the non-numeric keys.
            const names = Object.keys(TSAStatus).filter((key) => Number.isNaN(Number(key)));
            expect(names.sort()).toEqual([
                "GRANTED",
                "GRANTED_WITH_MODS",
                "REJECTION",
                "REVOCATION_NOTIFICATION",
                "REVOCATION_WARNING",
                "WAITING",
            ]);
            expect({
                GRANTED: TSAStatus.GRANTED,
                GRANTED_WITH_MODS: TSAStatus.GRANTED_WITH_MODS,
                REJECTION: TSAStatus.REJECTION,
                WAITING: TSAStatus.WAITING,
                REVOCATION_WARNING: TSAStatus.REVOCATION_WARNING,
                REVOCATION_NOTIFICATION: TSAStatus.REVOCATION_NOTIFICATION,
            }).toEqual({
                GRANTED: 0,
                GRANTED_WITH_MODS: 1,
                REJECTION: 2,
                WAITING: 3,
                REVOCATION_WARNING: 4,
                REVOCATION_NOTIFICATION: 5,
            });
        });
    });
});
