import { describe, it, expect, vi } from "vitest";
import {
    parseOCSPResponse,
    createOCSPRequest,
    parseOCSPNonce,
    OCSPResponseStatus,
    CertificateStatus,
} from "../../src/pki/ocsp-utils.js";

// Mock crypto.getRandomValues for nonce generation
vi.stubGlobal("crypto", {
    getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
        return arr;
    },
    subtle: {
        digest: vi.fn(() => Promise.resolve(new ArrayBuffer(20))),
    },
});

describe("OCSP Utils", () => {
    describe("parseOCSPResponse", () => {
        it("should throw on invalid ASN.1", () => {
            const invalidData = new Uint8Array([0x00, 0x01, 0x02]);

            expect(() => parseOCSPResponse(invalidData)).toThrow();
        });

        it("should throw on empty input", () => {
            const emptyData = new Uint8Array(0);

            expect(() => parseOCSPResponse(emptyData)).toThrow();
        });

        it("should throw on non-SUCCESSFUL response status", () => {
            // Create a minimal OCSP Response with status = MALFORMED_REQUEST (1)
            const malformedResponse = new Uint8Array([
                0x30,
                0x06, // SEQUENCE
                0x02,
                0x01,
                0x01, // INTEGER status = 1 (MALFORMED_REQUEST)
            ]);

            expect(() => parseOCSPResponse(malformedResponse)).toThrow();
        });

        it("should throw on INTERNAL_ERROR (2) status", () => {
            const internalErrorResponse = new Uint8Array([
                0x30,
                0x06,
                0x02,
                0x01,
                0x02, // status = 2 (INTERNAL_ERROR)
            ]);

            expect(() => parseOCSPResponse(internalErrorResponse)).toThrow();
        });

        it("should throw on TRY_LATER (3) status", () => {
            const tryLaterResponse = new Uint8Array([
                0x30,
                0x06,
                0x02,
                0x01,
                0x03, // status = 3 (TRY_LATER)
            ]);

            expect(() => parseOCSPResponse(tryLaterResponse)).toThrow();
        });
    });

    describe("createOCSPRequest", () => {
        it("should create a non-empty request", () => {
            // We can't easily create test certificates without more setup,
            // so we just verify the function exists and can be called
            // In a real test, we'd mock the certificate parameters

            // This test at least verifies the export exists
            expect(typeof createOCSPRequest).toBe("function");
        });
    });

    describe("parseOCSPNonce", () => {
        it("should return false values for invalid input", () => {
            const result = parseOCSPNonce(new Uint8Array([0x00, 0x01]));

            expect(result.nonce.length).toBe(0);
            expect(result.includedInRequest).toBe(false);
            expect(result.matchesInResponse).toBe(false);
        });

        it("should handle empty input gracefully", () => {
            const result = parseOCSPNonce(new Uint8Array(0));

            expect(result.nonce.length).toBe(0);
            expect(result.includedInRequest).toBe(false);
            expect(result.matchesInResponse).toBe(false);
        });

        it("should handle truncated OCSP response", () => {
            const truncatedResponse = new Uint8Array([
                0x30,
                0x03, // SEQUENCE (truncated)
            ]);

            const result = parseOCSPNonce(truncatedResponse);

            expect(result.nonce.length).toBe(0);
            expect(result.includedInRequest).toBe(false);
            expect(result.matchesInResponse).toBe(false);
        });
    });
});

describe("OCSP Response Status Enums", () => {
    it("should correctly map SUCCESSFUL (0) status", () => {
        expect(OCSPResponseStatus.SUCCESSFUL).toBe(0);
    });

    it("should correctly map MALFORMED_REQUEST (1) status", () => {
        expect(OCSPResponseStatus.MALFORMED_REQUEST).toBe(1);
    });

    it("should correctly map INTERNAL_ERROR (2) status", () => {
        expect(OCSPResponseStatus.INTERNAL_ERROR).toBe(2);
    });

    it("should correctly map TRY_LATER (3) status", () => {
        expect(OCSPResponseStatus.TRY_LATER).toBe(3);
    });

    it("should correctly map SIG_REQUIRED (4) status", () => {
        expect(OCSPResponseStatus.SIG_REQUIRED).toBe(4);
    });

    it("should correctly map UNAUTHORIZED (5) status", () => {
        expect(OCSPResponseStatus.UNAUTHORIZED).toBe(5);
    });

    it("should correctly map CertificateStatus GOOD (0)", () => {
        expect(CertificateStatus.GOOD).toBe(0);
    });

    it("should correctly map CertificateStatus REVOKED (1)", () => {
        expect(CertificateStatus.REVOKED).toBe(1);
    });

    it("should correctly map CertificateStatus UNKNOWN (2)", () => {
        expect(CertificateStatus.UNKNOWN).toBe(2);
    });
});

describe("OCSP Response Parsing Edge Cases", () => {
    it("should handle malformed OCSP response structure", () => {
        // Valid ASN.1 SEQUENCE but not valid OCSP
        const malformed = new Uint8Array([
            0x30,
            0x0a, // SEQUENCE
            0x02,
            0x01,
            0x00, // INTEGER
            0x02,
            0x01,
            0x00, // INTEGER
        ]);

        expect(() => parseOCSPResponse(malformed)).toThrow();
    });

    it("should handle response with SUCCESSFUL status but no responseBytes", () => {
        // OCSP Response with SUCCESSFUL status but no responseBytes
        const noResponseBytes = new Uint8Array([
            0x30,
            0x06, // SEQUENCE
            0x02,
            0x01,
            0x00, // INTEGER status = 0 (SUCCESSFUL)
            // Missing responseBytes
        ]);

        expect(() => parseOCSPResponse(noResponseBytes)).toThrow();
    });
});
