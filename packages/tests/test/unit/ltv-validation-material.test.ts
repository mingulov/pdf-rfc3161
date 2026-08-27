import { beforeEach, describe, expect, it, vi } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { completeLTVData } from "../../../core/src/pdf/ltv.js";
import { getCRLDistributionPoints } from "../../../core/src/pki/crl-utils.js";
import { getOCSPURI } from "../../../core/src/pki/ocsp-utils.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";
import {
    createCrlCandidate,
    createOcspResponseCandidate,
} from "../fixtures/revocation-material.js";

vi.mock(
    "../../../core/src/pki/ocsp-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof import("../../../core/src/pki/ocsp-utils.js")>()),
        getOCSPURI: vi.fn(),
    })
);

vi.mock(
    "../../../core/src/pki/crl-utils.js",
    async (importOriginal: <T = unknown>() => Promise<T>) => ({
        ...(await importOriginal<typeof import("../../../core/src/pki/crl-utils.js")>()),
        getCRLDistributionPoints: vi.fn(),
    })
);

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return bytes.slice().buffer;
}

async function certificatePair(): Promise<Uint8Array[]> {
    const fixture = await createRFC3161TokenFixture({ certificates: "decoyFirst" });
    const signerAsn1 = asn1js.fromBER(toArrayBuffer(fixture.signerCertificate));
    const issuerAsn1 = asn1js.fromBER(toArrayBuffer(fixture.decoyCertificate));
    if (
        signerAsn1.offset !== fixture.signerCertificate.length ||
        issuerAsn1.offset !== fixture.decoyCertificate.length
    ) {
        throw new Error("fixture certificates must be complete DER");
    }
    const signer = new pkijs.Certificate({ schema: signerAsn1.result });
    const issuer = new pkijs.Certificate({ schema: issuerAsn1.result });
    signer.issuer = issuer.subject;
    return [
        new Uint8Array(signer.toSchema(true).toBER(false)),
        new Uint8Array(issuer.toSchema().toBER(false)),
    ];
}

function sequenceContents(bytes: Uint8Array): Uint8Array {
    if (bytes[0] !== 0x30) throw new Error("test fixture must be a sequence");

    const firstLength = bytes[1];
    if (firstLength === undefined) throw new Error("test fixture sequence has no length");
    if (firstLength < 0x80) return bytes.slice(2);

    const lengthOctets = firstLength & 0x7f;
    if (lengthOctets === 0 || bytes.length < 2 + lengthOctets) {
        throw new Error("test fixture sequence has an invalid length");
    }
    return bytes.slice(2 + lengthOctets);
}

function indefiniteLengthSequence(bytes: Uint8Array): Uint8Array {
    return Uint8Array.of(0x30, 0x80, ...sequenceContents(bytes), 0x00, 0x00);
}

function nonMinimalLengthSequence(bytes: Uint8Array): Uint8Array {
    const firstLength = bytes[1];
    if (firstLength === undefined) throw new Error("test fixture sequence has no length");
    const contents = sequenceContents(bytes);
    if (firstLength < 0x80) return Uint8Array.of(0x30, 0x81, firstLength, ...contents);

    const lengthOctets = firstLength & 0x7f;
    return Uint8Array.of(
        0x30,
        firstLength + 1,
        0x00,
        ...bytes.slice(2, 2 + lengthOctets),
        ...contents
    );
}

function derSequence(contents: Uint8Array): Uint8Array {
    if (contents.length < 0x80) return Uint8Array.of(0x30, contents.length, ...contents);

    const lengthOctets: number[] = [];
    for (let length = contents.length; length > 0; length = Math.floor(length / 0x100)) {
        lengthOctets.unshift(length & 0xff);
    }
    return Uint8Array.of(0x30, 0x80 | lengthOctets.length, ...lengthOctets, ...contents);
}

function tlvLength(bytes: Uint8Array): number {
    const firstLength = bytes[1];
    if (firstLength === undefined) throw new Error("test fixture TLV has no length");
    if (firstLength < 0x80) return 2 + firstLength;

    const lengthOctets = firstLength & 0x7f;
    let length = 0;
    for (let index = 0; index < lengthOctets; index++) {
        const octet = bytes[2 + index];
        if (octet === undefined) throw new Error("test fixture TLV length is truncated");
        length = length * 0x100 + octet;
    }
    return 2 + lengthOctets + length;
}

function canonicalOuterWithIndefiniteFirstChild(bytes: Uint8Array): Uint8Array {
    const contents = sequenceContents(bytes);
    const childLength = tlvLength(contents);
    return derSequence(
        Uint8Array.of(
            ...indefiniteLengthSequence(contents.slice(0, childLength)),
            ...contents.slice(childLength)
        )
    );
}

function outerSequenceWithExtraNull(bytes: Uint8Array): Uint8Array {
    return derSequence(Uint8Array.of(...sequenceContents(bytes), 0x05, 0x00));
}

function nonMinimalOcspStatus(bytes: Uint8Array): Uint8Array {
    const parsed = asn1js.fromBER(toArrayBuffer(bytes));
    if (parsed.offset !== bytes.length || !(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("test fixture must be a complete OCSPResponse sequence");
    }
    const responseStatus = parsed.result.valueBlock.value[0];
    if (!(responseStatus instanceof asn1js.Enumerated)) {
        throw new Error("test fixture OCSPResponse must begin with ENUMERATED status");
    }
    responseStatus.valueBlock.valueHexView = Uint8Array.of(0x00, 0x00);
    return new Uint8Array(parsed.result.toBER(false));
}

function ocspResponseWithStatusContent(bytes: Uint8Array, statusContent: Uint8Array): Uint8Array {
    const parsed = asn1js.fromBER(toArrayBuffer(bytes));
    if (parsed.offset !== bytes.length || !(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("test fixture must be a complete OCSPResponse sequence");
    }
    const responseStatus = parsed.result.valueBlock.value[0];
    if (!(responseStatus instanceof asn1js.Enumerated)) {
        throw new Error("test fixture OCSPResponse must begin with ENUMERATED status");
    }
    responseStatus.valueBlock.valueHexView = statusContent;
    return new Uint8Array(parsed.result.toBER(false));
}

function firstInteger(value: asn1js.BaseBlock): asn1js.Integer | undefined {
    if (value instanceof asn1js.Integer) return value;
    if (value instanceof asn1js.Constructed) {
        for (const child of value.valueBlock.value) {
            const found = firstInteger(child);
            if (found) return found;
        }
    }
    return undefined;
}

function nonMinimalFirstInteger(bytes: Uint8Array): Uint8Array {
    const parsed = asn1js.fromBER(toArrayBuffer(bytes));
    if (parsed.offset !== bytes.length) throw new Error("test fixture must be complete DER");
    const integer = firstInteger(parsed.result);
    if (!integer) throw new Error("test fixture must contain an INTEGER");
    integer.valueBlock.valueHexView = Uint8Array.of(0x00, 0x01);
    return new Uint8Array(parsed.result.toBER(false));
}

describe("network LTV validation material", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("skips malformed OCSP bytes and falls back to a structurally complete CRL candidate", async () => {
        vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
        vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    ocspFetcher: async () => Uint8Array.of(0x30, 0x01),
                    crlFetcher: async () => crl,
                },
            }
        );

        expect(result.data.ocspResponses).toEqual([]);
        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.join(" ")).toMatch(/OCSP.*structural/i);
    });

    it("does not accept a non-good OCSP response and uses the CRL fallback", async () => {
        vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
        vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    ocspFetcher: async () => createOcspResponseCandidate("revoked"),
                    crlFetcher: async () => crl,
                },
            }
        );

        expect(result.data.ocspResponses).toEqual([]);
        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.join(" ")).toContain("not good");
    });

    for (const status of ["good-constructed", "good-nonempty"] as const) {
        it(`rejects malformed ${status} OCSP CertStatus and uses the CRL fallback`, async () => {
            vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
            vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
            const crl = createCrlCandidate();

            const result = await completeLTVData(
                { certificates: await certificatePair(), crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: async () => createOcspResponseCandidate(status),
                        crlFetcher: async () => crl,
                    },
                }
            );

            expect(result.data.ocspResponses).toEqual([]);
            expect(result.data.crls).toEqual([crl]);
            expect(result.errors.join(" ")).toMatch(/structural parsing/i);
        });
    }

    for (const [description, transform] of [
        ["indefinite-length", indefiniteLengthSequence],
        ["non-minimal-length", nonMinimalLengthSequence],
    ] as const) {
        it(`rejects a ${description} OCSP response and uses the CRL fallback`, async () => {
            vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
            vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
            const crl = createCrlCandidate();

            const result = await completeLTVData(
                { certificates: await certificatePair(), crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: async () => transform(createOcspResponseCandidate("good")),
                        crlFetcher: async () => crl,
                    },
                }
            );

            expect(result.data.ocspResponses).toEqual([]);
            expect(result.data.crls).toEqual([crl]);
            expect(result.errors.join(" ")).toMatch(/OCSP.*structural/i);
        });
    }

    it("rejects an OCSP response with canonical outer DER and indefinite ResponseData", async () => {
        vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
        vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    ocspFetcher: async () =>
                        createOcspResponseCandidate("good", canonicalOuterWithIndefiniteFirstChild),
                    crlFetcher: async () => crl,
                },
            }
        );

        expect(result.data.ocspResponses).toEqual([]);
        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.join(" ")).toMatch(/indefinite-length/i);
    });

    it("rejects a canonically framed OCSP response with an extra outer value and uses the CRL fallback", async () => {
        vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
        vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    ocspFetcher: async () =>
                        outerSequenceWithExtraNull(createOcspResponseCandidate("good")),
                    crlFetcher: async () => crl,
                },
            }
        );

        expect(result.data.ocspResponses).toEqual([]);
        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.join(" ")).toMatch(/OCSP.*structural/i);
    });

    for (const [description, response] of [
        [
            "outer response status ENUMERATED",
            () => nonMinimalOcspStatus(createOcspResponseCandidate("good")),
        ],
        [
            "nested CertID serial number INTEGER",
            () => createOcspResponseCandidate("good", nonMinimalFirstInteger),
        ],
    ] as const) {
        it(`rejects a non-minimal ${description} value and uses the CRL fallback`, async () => {
            vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
            vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
            const crl = createCrlCandidate();

            const result = await completeLTVData(
                { certificates: await certificatePair(), crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: async () => response(),
                        crlFetcher: async () => crl,
                    },
                }
            );

            expect(result.data.ocspResponses).toEqual([]);
            expect(result.data.crls).toEqual([crl]);
            expect(result.errors.join(" ")).toMatch(/non-minimal.*(INTEGER|ENUMERATED)/i);
        });
    }

    for (const [description, statusContent] of [
        ["canonical large positive", Uint8Array.of(0x00, 0x80, 0x00, 0x00)],
        ["negative", Uint8Array.of(0xff)],
        ["undefined", Uint8Array.of(0x07)],
        ["canonical multi-byte", Uint8Array.of(0x00, 0x80)],
    ] as const) {
        it(`rejects a ${description} responseStatus and uses the CRL fallback`, async () => {
            vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
            vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
            const crl = createCrlCandidate();

            const result = await completeLTVData(
                { certificates: await certificatePair(), crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: async () =>
                            ocspResponseWithStatusContent(
                                createOcspResponseCandidate("good"),
                                statusContent
                            ),
                        crlFetcher: async () => crl,
                    },
                }
            );

            expect(result.data.ocspResponses).toEqual([]);
            expect(result.data.crls).toEqual([crl]);
            expect(result.errors.join(" ")).toMatch(/responseStatus/i);
        });
    }

    for (const [description, transform] of [
        ["indefinite-length", indefiniteLengthSequence],
        ["non-minimal-length", nonMinimalLengthSequence],
    ] as const) {
        it(`rejects an OCSP response with a ${description} BasicOCSPResponse`, async () => {
            vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
            vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/valid"]);
            const crl = createCrlCandidate();

            const result = await completeLTVData(
                { certificates: await certificatePair(), crls: [], ocspResponses: [] },
                {
                    fetchers: {
                        ocspFetcher: async () => createOcspResponseCandidate("good", transform),
                        crlFetcher: async () => crl,
                    },
                }
            );

            expect(result.data.ocspResponses).toEqual([]);
            expect(result.data.crls).toEqual([crl]);
            expect(result.errors.join(" ")).toMatch(
                /BasicOCSPResponse.*(indefinite-length|non-minimal|DER)/i
            );
        });
    }

    it("skips malformed and trailing CRLs before collecting a complete candidate", async () => {
        vi.mocked(getOCSPURI).mockReturnValue(null);
        vi.mocked(getCRLDistributionPoints).mockReturnValue([
            "https://crl.example.test/malformed",
            "https://crl.example.test/trailing",
            "https://crl.example.test/valid",
        ]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    crlFetcher: async (url) => {
                        if (url.endsWith("malformed")) return Uint8Array.of(0x30, 0x01);
                        if (url.endsWith("trailing")) return Uint8Array.of(...crl, 0x00);
                        return crl;
                    },
                },
            }
        );

        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.filter((message) => /CRL.*structural/i.test(message))).toHaveLength(2);
    });

    it("skips indefinite-length and non-minimal-length CRLs before collecting a DER candidate", async () => {
        vi.mocked(getOCSPURI).mockReturnValue(null);
        vi.mocked(getCRLDistributionPoints).mockReturnValue([
            "https://crl.example.test/indefinite",
            "https://crl.example.test/non-minimal",
            "https://crl.example.test/valid",
        ]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    crlFetcher: async (url) => {
                        if (url.endsWith("indefinite")) return indefiniteLengthSequence(crl);
                        if (url.endsWith("non-minimal")) return nonMinimalLengthSequence(crl);
                        return crl;
                    },
                },
            }
        );

        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.filter((message) => /CRL.*structural/i.test(message))).toHaveLength(2);
    });

    it("skips a canonical-outer CRL with indefinite TBSCertList before collecting a DER candidate", async () => {
        vi.mocked(getOCSPURI).mockReturnValue(null);
        vi.mocked(getCRLDistributionPoints).mockReturnValue([
            "https://crl.example.test/nested-indefinite",
            "https://crl.example.test/valid",
        ]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    crlFetcher: async (url) =>
                        url.endsWith("nested-indefinite")
                            ? canonicalOuterWithIndefiniteFirstChild(crl)
                            : crl,
                },
            }
        );

        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.join(" ")).toMatch(/indefinite-length/i);
    });

    it("skips a canonically framed CRL with an extra outer value before collecting a complete candidate", async () => {
        vi.mocked(getOCSPURI).mockReturnValue(null);
        vi.mocked(getCRLDistributionPoints).mockReturnValue([
            "https://crl.example.test/extra-null",
            "https://crl.example.test/valid",
        ]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    crlFetcher: async (url) =>
                        url.endsWith("extra-null") ? outerSequenceWithExtraNull(crl) : crl,
                },
            }
        );

        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.filter((message) => /CRL.*structural/i.test(message))).toHaveLength(1);
    });

    it("skips a CRL with a non-minimal INTEGER before collecting a complete candidate", async () => {
        vi.mocked(getOCSPURI).mockReturnValue(null);
        vi.mocked(getCRLDistributionPoints).mockReturnValue([
            "https://crl.example.test/non-minimal-integer",
            "https://crl.example.test/valid",
        ]);
        const crl = createCrlCandidate();

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            {
                fetchers: {
                    crlFetcher: async (url) =>
                        url.endsWith("non-minimal-integer") ? nonMinimalFirstInteger(crl) : crl,
                },
            }
        );

        expect(result.data.crls).toEqual([crl]);
        expect(result.errors.join(" ")).toMatch(/non-minimal.*INTEGER/i);
    });

    it("collects a structurally good OCSP response as candidate material without asserting revocation trust", async () => {
        vi.mocked(getOCSPURI).mockReturnValue("https://ocsp.example.test");
        vi.mocked(getCRLDistributionPoints).mockReturnValue(["https://crl.example.test/unused"]);
        const ocsp = createOcspResponseCandidate("good");

        const result = await completeLTVData(
            { certificates: await certificatePair(), crls: [], ocspResponses: [] },
            { fetchers: { ocspFetcher: async () => ocsp } }
        );

        expect(result.data.ocspResponses).toEqual([ocsp]);
        expect(result.data.crls).toEqual([]);
    });
});
