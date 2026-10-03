import { describe, expect, it } from "vitest";
import { parseOCSPResponse } from "../../../core/src/pki/ocsp-utils.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { createOcspResponseCandidate } from "../fixtures/revocation-material.js";

describe("OCSP BasicOCSPResponse schema errors normalize to TimestampError (T16 fuzz)", () => {
    it("maps a non-conforming nested BasicOCSPResponse to INVALID_RESPONSE", () => {
        // Minimized from Jazzer.js crash-17a37...c37e1f69 (fuzz-ocsp, 52 runs
        // in): framing-valid outer OCSPResponse whose nested BasicOCSPResponse
        // content fails the pkijs schema. The escape was a raw pkijs AsnError.
        const bytes = createOcspResponseCandidate("good");
        // Precondition pins the fixture layout: certStatus good [0] IMPLICIT
        // NULL at this offset. Fails loudly if the builder changes shape.
        expect(bytes[0x91]).toBe(0x80);
        expect(bytes[0x92]).toBe(0x00);
        // One-byte flip: empty constructed [1] where the RevokedInfo SEQUENCE
        // is required. Canonical DER framing still passes (same size).
        bytes[0x91] = 0xa1;
        let thrown: unknown;
        try {
            parseOCSPResponse(bytes);
        } catch (error) {
            thrown = error;
        }
        expect(thrown).toBeInstanceOf(TimestampError);
        expect((thrown as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
    });

    it("maps a primitive-encoded ResponseBytes wrapper to INVALID_RESPONSE", () => {
        // Minimized from Jazzer.js crash-dc00...dcbb5 (fuzz-ocsp): asn1js
        // still yields a Sequence-shaped block for the primitive tag 0x10,
        // so the exact-grammar precheck passes, but pkijs schema
        // verification rejects it with a raw AsnError.
        const bytes = createOcspResponseCandidate("good");
        // Precondition pins the fixture layout: ResponseBytes SEQUENCE tag.
        expect(bytes[9]).toBe(0x30);
        // One-byte flip: constructed SEQUENCE -> primitive universal 16.
        bytes[9] = 0x10;
        let thrown: unknown;
        try {
            parseOCSPResponse(bytes);
        } catch (error) {
            thrown = error;
        }
        expect(thrown).toBeInstanceOf(TimestampError);
        expect((thrown as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
    });
});
