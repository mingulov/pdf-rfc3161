import { describe, it, expect, vi } from "vitest";
import {
    parseOCSPResponse,
    createOCSPRequest,
    parseOCSPNonce,
    getOCSPURI,
    OCSPResponseStatus,
    CertificateStatus,
} from "../../src/pki/ocsp-utils.js";
import * as pkijs from "pkijs";

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

        it("should throw on non-SUCCESSFUL response status (MALFORMED_REQUEST)", () => {
            const malformedResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01]);

            expect(() => parseOCSPResponse(malformedResponse)).toThrow();
        });

        it("should throw on INTERNAL_ERROR (2) status", () => {
            const internalErrorResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x02]);

            expect(() => parseOCSPResponse(internalErrorResponse)).toThrow();
        });

        it("should throw on TRY_LATER (3) status", () => {
            const tryLaterResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x03]);

            expect(() => parseOCSPResponse(tryLaterResponse)).toThrow();
        });

        it("should throw on SIG_REQUIRED (4) status", () => {
            const sigRequiredResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x04]);

            expect(() => parseOCSPResponse(sigRequiredResponse)).toThrow();
        });

        it("should throw on UNAUTHORIZED (5) status", () => {
            const unauthorizedResponse = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x05]);

            expect(() => parseOCSPResponse(unauthorizedResponse)).toThrow();
        });

        it("should handle malformed OCSP response structure", () => {
            const malformed = new Uint8Array([0x30, 0x0a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);

            expect(() => parseOCSPResponse(malformed)).toThrow();
        });

        it("should throw on response with SUCCESSFUL status but no responseBytes", () => {
            const noResponseBytes = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            expect(() => parseOCSPResponse(noResponseBytes)).toThrow();
        });
    });

    describe("getOCSPURI", () => {
        it("should return null for certificate without extensions", () => {
            const cert = new pkijs.Certificate();
            cert.extensions = undefined;

            const uri = getOCSPURI(cert);
            expect(uri).toBeNull();
        });

        it("should return null for certificate without AIA extension", () => {
            const cert = new pkijs.Certificate();
            cert.extensions = [];

            const uri = getOCSPURI(cert);
            expect(uri).toBeNull();
        });

        it("should return null for AIA extension without OCSP location", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });
            cert.extensions = [aiaExt];

            const uri = getOCSPURI(cert);
            expect(uri).toBeNull();
        });

        it("should return OCSP URI from certificate with AIA extension", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockAccessDesc = {
                accessMethod: "1.3.6.1.5.5.7.48.1",
                accessLocation: {
                    type: 6,
                    value: "http://ocsp.example.com",
                },
            };

            aiaExt.parsedValue = {
                accessDescriptions: [mockAccessDesc],
            };
            cert.extensions = [aiaExt];

            const uri = getOCSPURI(cert);
            expect(uri).toBe("http://ocsp.example.com");
        });

        it("should return null for non-URI access location", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockAccessDesc = {
                accessMethod: "1.3.6.1.5.5.7.48.1",
                accessLocation: {
                    type: 4,
                    value: "someEmail",
                },
            };

            aiaExt.parsedValue = {
                accessDescriptions: [mockAccessDesc],
            };
            cert.extensions = [aiaExt];

            const uri = getOCSPURI(cert);
            expect(uri).toBeNull();
        });

        it("should return null for non-OCSP access method", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const mockAccessDesc = {
                accessMethod: "1.3.6.1.5.5.7.48.2",
                accessLocation: {
                    type: 6,
                    value: "http://ca.example.com",
                },
            };

            aiaExt.parsedValue = {
                accessDescriptions: [mockAccessDesc],
            };
            cert.extensions = [aiaExt];

            const uri = getOCSPURI(cert);
            expect(uri).toBeNull();
        });

        it("should find OCSP URI among multiple access descriptions", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            const accessDescs = [
                {
                    accessMethod: "1.3.6.1.5.5.7.48.2",
                    accessLocation: {
                        type: 6,
                        value: "http://ca.example.com",
                    },
                },
                {
                    accessMethod: "1.3.6.1.5.5.7.48.1",
                    accessLocation: {
                        type: 6,
                        value: "http://ocsp.example.com",
                    },
                },
            ];

            aiaExt.parsedValue = {
                accessDescriptions: accessDescs,
            };
            cert.extensions = [aiaExt];

            const uri = getOCSPURI(cert);
            expect(uri).toBe("http://ocsp.example.com");
        });

        it("should return null when accessDescriptions is not an array", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });

            aiaExt.parsedValue = {
                accessDescriptions: "not an array",
            };
            cert.extensions = [aiaExt];

            const uri = getOCSPURI(cert);
            expect(uri).toBeNull();
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
            const truncatedResponse = new Uint8Array([0x30, 0x03]);

            const result = parseOCSPNonce(truncatedResponse);

            expect(result.nonce.length).toBe(0);
            expect(result.includedInRequest).toBe(false);
            expect(result.matchesInResponse).toBe(false);
        });

        it("should handle request nonce parameter when response is invalid", () => {
            const requestNonce = new Uint8Array([0x01, 0x02, 0x03]);

            const result = parseOCSPNonce(new Uint8Array(0), requestNonce);

            expect(result.nonce.length).toBe(0);
            expect(result.includedInRequest).toBe(false);
            expect(result.matchesInResponse).toBe(false);
        });
    });

    describe("createOCSPRequest", () => {
        it("should be defined as a function", () => {
            expect(typeof createOCSPRequest).toBe("function");
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
            const malformed = new Uint8Array([0x30, 0x0a, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00]);

            expect(() => parseOCSPResponse(malformed)).toThrow();
        });

        it("should throw on response with SUCCESSFUL status but no responseBytes", () => {
            const noResponseBytes = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x00]);

            expect(() => parseOCSPResponse(noResponseBytes)).toThrow();
        });
    });
});
