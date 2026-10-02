import { describe, it, expect, vi } from "vitest";
import {
    parseOCSPResponse,
    createOCSPRequest,
    getOCSPURI,
    OCSPResponseStatus,
    CertificateStatus,
} from "../../../core/src/pki/ocsp-utils.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { inspectOCSPRequest } from "../fixtures/signed-revocation-material.js";

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
        function responseWithStatus(statusContent: Uint8Array): Uint8Array {
            return Uint8Array.of(0x30, statusContent.length + 2, 0x0a, statusContent.length, ...statusContent);
        }

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

        it("reports SIG_REQUIRED for RFC 6960 response status 5", () => {
            const sigRequiredResponse = Uint8Array.of(0x30, 0x03, 0x0a, 0x01, 0x05);

            expect(() => parseOCSPResponse(sigRequiredResponse)).toThrow(
                "OCSP responder error: Signature Required (code: 5)"
            );
        });

        it("reports UNUSED for RFC 6960 response status 4", () => {
            const unusedResponse = Uint8Array.of(0x30, 0x03, 0x0a, 0x01, 0x04);

            expect(() => parseOCSPResponse(unusedResponse)).toThrow(
                "OCSP responder error: Unused (code: 4)"
            );
        });

        it("reports UNAUTHORIZED for RFC 6960 response status 6", () => {
            const unauthorizedResponse = Uint8Array.of(0x30, 0x03, 0x0a, 0x01, 0x06);

            expect(() => parseOCSPResponse(unauthorizedResponse)).toThrow(
                "OCSP responder error: Unauthorized (code: 6)"
            );
        });

        it.each([
            ["canonical large positive", Uint8Array.of(0x00, 0x80, 0x00, 0x00)],
            ["negative", Uint8Array.of(0xff)],
            ["undefined", Uint8Array.of(0x07)],
            ["canonical multi-byte", Uint8Array.of(0x00, 0x80)],
        ])(
            "rejects a %s responseStatus directly from its raw ENUMERATED content",
            (_label: string, content: Uint8Array) => {
            try {
                parseOCSPResponse(responseWithStatus(content));
                throw new Error("expected invalid OCSP responseStatus to throw");
            } catch (error) {
                expect(error).toMatchObject({ code: TimestampErrorCode.INVALID_RESPONSE });
                expect(error).toHaveProperty("message", expect.stringContaining("responseStatus"));
            }
            }
        );

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

        // T11 (R10): the claimed hostile-DER escape could not be
        // demonstrated -- pkijs yields AccessDescription instances or an
        // empty list for real AIA bytes, never hostile elements (see the
        // disposition vectors below, pinned with exact bytes). The shape
        // guard below is hygiene for programmatically-built certificates
        // only and claims no DER defect fixed.
        it("returns null (never throws) for hostile AIA DER through a real parse", () => {
            // Hand-built v3 certificate carrying the given AIA extension
            // value. No signature is minted: this path parses extensions
            // only and verifies nothing, so an unverifiable signature
            // changes nothing about the exercised behavior.
            function certDerWithAia(aiaInner: Uint8Array): Uint8Array {
                const name = (commonName: string): asn1js.Sequence =>
                    new asn1js.Sequence({
                        value: [
                            new asn1js.Set({
                                value: [
                                    new asn1js.Sequence({
                                        value: [
                                            new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                                            new asn1js.PrintableString({ value: commonName }),
                                        ],
                                    }),
                                ],
                            }),
                        ],
                    });
                const tbs = new asn1js.Sequence({
                    value: [
                        new asn1js.Constructed({
                            idBlock: { tagClass: 3, tagNumber: 0 },
                            value: [new asn1js.Integer({ value: 2 })],
                        }),
                        new asn1js.Integer({ value: 1 }),
                        new asn1js.Sequence({
                            value: [
                                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.11" }),
                                new asn1js.Null(),
                            ],
                        }),
                        name("T11 AIA"),
                        new asn1js.Sequence({
                            value: [
                                new asn1js.UTCTime({ valueDate: new Date("2020-01-01T00:00:00Z") }),
                                new asn1js.UTCTime({ valueDate: new Date("2030-01-01T00:00:00Z") }),
                            ],
                        }),
                        name("T11 AIA"),
                        new asn1js.Sequence({
                            value: [
                                new asn1js.Sequence({
                                    value: [
                                        new asn1js.ObjectIdentifier({
                                            value: "1.2.840.113549.1.1.1",
                                        }),
                                        new asn1js.Null(),
                                    ],
                                }),
                                new asn1js.BitString({ valueHex: new Uint8Array([0x00]).buffer }),
                            ],
                        }),
                        new asn1js.Constructed({
                            idBlock: { tagClass: 3, tagNumber: 3 },
                            value: [
                                new asn1js.Sequence({
                                    value: [
                                        new asn1js.Sequence({
                                            value: [
                                                new asn1js.ObjectIdentifier({
                                                    value: "1.3.6.1.5.5.7.1.1",
                                                }),
                                                new asn1js.OctetString({
                                                    valueHex: aiaInner.buffer as ArrayBuffer,
                                                }),
                                            ],
                                        }),
                                    ],
                                }),
                            ],
                        }),
                    ],
                });
                const cert = new asn1js.Sequence({
                    value: [
                        tbs,
                        new asn1js.Sequence({
                            value: [
                                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.11" }),
                                new asn1js.Null(),
                            ],
                        }),
                        new asn1js.BitString({ valueHex: new Uint8Array([0x00]).buffer }),
                    ],
                });
                return new Uint8Array(cert.toBER(false));
            }

            function uriForAiaInner(aiaInner: Uint8Array): string | null {
                const parsed = asn1js.fromBER(
                    new Uint8Array(certDerWithAia(aiaInner)).buffer as ArrayBuffer
                );
                expect(parsed.offset).not.toBe(-1);
                const cert = new pkijs.Certificate({ schema: parsed.result });
                return getOCSPURI(cert);
            }

            // Control: a well-formed OCSP accessDescription resolves.
            const validInner = new Uint8Array(
                new pkijs.InfoAccess({
                    accessDescriptions: [
                        new pkijs.AccessDescription({
                            accessMethod: "1.3.6.1.5.5.7.48.1",
                            accessLocation: new pkijs.GeneralName({
                                type: 6,
                                value: "http://ocsp.example.com",
                            }),
                        }),
                    ],
                })
                    .toSchema()
                    .toBER(false)
            );
            expect(uriForAiaInner(validInner)).toBe("http://ocsp.example.com");

            // Disposition vectors: hostile AIA shapes parse without
            // producing hostile elements, so no TypeError can escape.
            expect(uriForAiaInner(Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x05))).toBeNull();
            expect(uriForAiaInner(Uint8Array.of(0x02, 0x01, 0x05))).toBeNull();
            expect(uriForAiaInner(Uint8Array.of(0x30, 0x00))).toBeNull();
            expect(uriForAiaInner(Uint8Array.of(0x05, 0x00))).toBeNull();
            const mixedInner = new Uint8Array(
                new asn1js.Sequence({
                    value: [
                        new pkijs.AccessDescription({
                            accessMethod: "1.3.6.1.5.5.7.48.1",
                            accessLocation: new pkijs.GeneralName({
                                type: 6,
                                value: "http://ocsp.example.com",
                            }),
                        }).toSchema(),
                        new asn1js.Integer({ value: 9 }),
                    ],
                }).toBER(false)
            );
            expect(uriForAiaInner(mixedInner)).toBeNull();
        });

        it("skips null and non-object accessDescriptions instead of throwing", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });
            aiaExt.parsedValue = {
                accessDescriptions: [
                    null,
                    42,
                    {
                        accessMethod: "1.3.6.1.5.5.7.48.1",
                        accessLocation: { type: 6, value: "http://ocsp.example.com" },
                    },
                ],
            };
            cert.extensions = [aiaExt];

            expect(getOCSPURI(cert)).toBe("http://ocsp.example.com");
        });

        // T11 (0x18): asn1js throws a plain Error on corrupted
        // GeneralizedTime content; an undecodable AIA value yields no URI
        // (null), never an uncoded throw.
        it("returns null when the AIA value throws during DER decoding", () => {
            const cert = new pkijs.Certificate();
            const hostile = new Uint8Array([
                0x18, 0x0f, ...new TextEncoder().encode("2030010100000!Z"),
            ]);
            cert.extensions = [
                new pkijs.Extension({
                    extnID: "1.3.6.1.5.5.7.1.1",
                    critical: false,
                    extnValue: hostile.buffer,
                }),
            ];
            expect(getOCSPURI(cert)).toBeNull();
        });

        it("skips accessDescriptions with a missing accessLocation instead of throwing", () => {
            const cert = new pkijs.Certificate();
            const aiaExt = new pkijs.Extension({
                extnID: "1.3.6.1.5.5.7.1.1",
                critical: false,
                extnValue: new ArrayBuffer(0),
            });
            aiaExt.parsedValue = {
                accessDescriptions: [
                    { accessMethod: "1.3.6.1.5.5.7.48.1" },
                    { accessMethod: "1.3.6.1.5.5.7.48.1", accessLocation: null },
                ],
            };
            cert.extensions = [aiaExt];

            expect(getOCSPURI(cert)).toBeNull();
        });
    });

    describe("createOCSPRequest", () => {
        function minimalCertificate(commonName: string, serial: number): pkijs.Certificate {
            const cert = new pkijs.Certificate();
            cert.serialNumber = new asn1js.Integer({ value: serial });
            cert.subject.typesAndValues.push(
                new pkijs.AttributeTypeAndValue({
                    type: "2.5.4.3",
                    value: new asn1js.PrintableString({ value: commonName }),
                })
            );
            cert.subjectPublicKeyInfo = new pkijs.PublicKeyInfo();
            return cert;
        }

        // T06 (R22): the builder used to stash the nonce on
        // `tbsRequest.extensions`, which pkijs never serializes. The nonce
        // must reach the wire inside `requestExtensions` ([2] EXPLICIT).
        it("serializes requestExtensions with exactly 32 nonce bytes", async () => {
            const leaf = minimalCertificate("R22 Leaf", 2001);
            const issuer = minimalCertificate("R22 CA", 1001);
            const request = await createOCSPRequest(leaf, issuer);

            const inspected = inspectOCSPRequest(request);
            expect(inspected.requestCount).toBe(1);
            expect(inspected.certId).not.toBeNull();
            expect(inspected.nonces).toHaveLength(1);
            expect(inspected.nonces[0]?.length).toBe(32);
        });

        it("generates a fresh random nonce for every request", async () => {
            const leaf = minimalCertificate("R22 Leaf", 2001);
            const issuer = minimalCertificate("R22 CA", 1001);
            const first = await createOCSPRequest(leaf, issuer);
            const second = await createOCSPRequest(leaf, issuer);

            expect(first).not.toEqual(second);
            const firstNonce = inspectOCSPRequest(first).nonces[0];
            const secondNonce = inspectOCSPRequest(second).nonces[0];
            expect(firstNonce).not.toEqual(secondNonce);
        });

        it("omits requestExtensions when includeNonce is false", async () => {
            const leaf = minimalCertificate("R22 Leaf", 2001);
            const issuer = minimalCertificate("R22 CA", 1001);
            const request = await createOCSPRequest(leaf, issuer, { includeNonce: false });

            const inspected = inspectOCSPRequest(request);
            expect(inspected.requestCount).toBe(1);
            expect(inspected.nonces).toHaveLength(0);
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

        it("should correctly map UNUSED (4) status", () => {
            expect(OCSPResponseStatus.UNUSED).toBe(4);
        });

        it("should correctly map SIG_REQUIRED (5) status", () => {
            expect(OCSPResponseStatus.SIG_REQUIRED).toBe(5);
        });

        it("should correctly map UNAUTHORIZED (6) status", () => {
            expect(OCSPResponseStatus.UNAUTHORIZED).toBe(6);
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

        // T11 (0x18): corrupted GeneralizedTime inside the response must
        // reject coded (INVALID_RESPONSE), never as a plain asn1js Error.
        // Hand-built (no signature is minted: the collector parses only).
        it("codes undecodable BasicOCSPResponse content as INVALID_RESPONSE", () => {
            const certID = new asn1js.Sequence({
                value: [
                    new asn1js.Sequence({
                        value: [new asn1js.ObjectIdentifier({ value: "1.3.14.3.2.26" })],
                    }),
                    new asn1js.OctetString({ valueHex: new Uint8Array(20).fill(1).buffer }),
                    new asn1js.OctetString({ valueHex: new Uint8Array(20).fill(2).buffer }),
                    new asn1js.Integer({ value: 1 }),
                ],
            });
            const basic = new asn1js.Sequence({
                value: [
                    new asn1js.Sequence({
                        value: [
                            new asn1js.Constructed({
                                idBlock: { tagClass: 3, tagNumber: 0 },
                                value: [new asn1js.Integer({ value: 0 })],
                            }),
                            new asn1js.Primitive({
                                idBlock: { tagClass: 3, tagNumber: 2 },
                                valueHex: new Uint8Array(20).fill(3).buffer,
                            }),
                            new asn1js.GeneralizedTime({
                                valueDate: new Date("2026-05-01T11:00:00Z"),
                            }),
                            new asn1js.Sequence({
                                value: [
                                    new asn1js.Sequence({
                                        value: [
                                            certID,
                                            new asn1js.Primitive({
                                                idBlock: { tagClass: 3, tagNumber: 0 },
                                                valueHex: new ArrayBuffer(0),
                                            }),
                                            new asn1js.GeneralizedTime({
                                                valueDate: new Date("2026-05-01T11:00:00Z"),
                                            }),
                                        ],
                                    }),
                                ],
                            }),
                        ],
                    }),
                    new asn1js.Sequence({
                        value: [
                            new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.11" }),
                            new asn1js.Null(),
                        ],
                    }),
                    new asn1js.BitString({ valueHex: new Uint8Array([0x00]).buffer }),
                ],
            });
            const response = new Uint8Array(
                new asn1js.Sequence({
                    value: [
                        new asn1js.Enumerated({ value: 0 }),
                        new asn1js.Constructed({
                            idBlock: { tagClass: 3, tagNumber: 0 },
                            value: [
                                new asn1js.Sequence({
                                    value: [
                                        new asn1js.ObjectIdentifier({
                                            value: "1.3.6.1.5.5.7.48.1.1",
                                        }),
                                        new asn1js.OctetString({
                                            valueHex: new Uint8Array(basic.toBER(false)).buffer,
                                        }),
                                    ],
                                }),
                            ],
                        }),
                    ],
                }).toBER(false)
            );
            // Corrupt the first GeneralizedTime (producedAt) in place.
            let at = -1;
            for (let i = 0; i + 17 <= response.length; i++) {
                if (response[i] === 0x18 && response[i + 1] === 0x0f) {
                    at = i;
                    break;
                }
            }
            expect(at).toBeGreaterThan(-1);
            const bad = new Uint8Array(response);
            bad.set(new TextEncoder().encode("2026050111000!Z"), at + 2);
            try {
                parseOCSPResponse(bad);
            } catch (error) {
                expect(error).toBeInstanceOf(TimestampError);
                expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
                expect((error as TimestampError).message).toBe("BasicOCSPResponse: ASN.1 parse failed");
                return;
            }
            throw new Error("expected INVALID_RESPONSE for undecodable OCSP content");
        });
    });

    // Audit C: the "missing idBlock" warn-fallback in parseOCSPResponse
    // (ocsp-utils.ts:156-159) is defensive code meant to absorb future
    // pkijs representation changes. Direct coverage was attempted via
    // `vi.spyOn(pkijs, "BasicOCSPResponse")` to inject a malformed
    // SingleResponse, but pkijs's exports are non-configurable -- the
    // spy throws "Cannot redefine property". Other approaches (DER-level
    // crafting, vi.mock of the whole pkijs module) either fail pkijs
    // schema validation or break unrelated tests.
    //
    // The fallback path remains uncovered. This is a known gap; the
    // branch is defence-in-depth for a hypothetical pkijs major-version
    // shape change. Two follow-ups would unblock real coverage:
    //   1. Extract the certStatus -> CertificateStatus mapping into a
    //      pure function so it can be unit-tested directly.
    //   2. Refactor parseOCSPResponse to accept a pluggable response
    //      decoder so tests can inject controlled SingleResponse shapes.
    //
    // Until then, the audit gap is documented here so it doesn't
    // silently re-appear in future audits.
    describe.skip("missing idBlock fallback (audit C, requires refactor)", () => {
        it.todo("warns and returns UNKNOWN when certStatus lacks idBlock");
    });
});
