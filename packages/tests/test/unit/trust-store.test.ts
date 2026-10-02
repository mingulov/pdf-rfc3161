import { describe, it, expect, beforeEach } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { SimpleTrustStore } from "../../../core/src/pki/trust-store.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

async function createTestCertificate(
    subjectName: string,
    isCA = false
): Promise<pkijs.Certificate> {
    const keys = await generateRSAKeyPair();

    const certificate = new pkijs.Certificate();
    certificate.version = 2;
    const rnd = new Uint8Array(4);
    cryptoEngine.crypto.getRandomValues(rnd);
    certificate.serialNumber = new asn1js.Integer({ valueHex: rnd });

    certificate.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: subjectName }),
        })
    );

    certificate.issuer = certificate.subject;
    certificate.notBefore.value = new Date(Date.now() - 86400000);
    certificate.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    certificate.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);

    if (isCA) {
        const basicConstraints = new pkijs.BasicConstraints({ cA: true });
        const extValue = basicConstraints.toSchema().toBER();
        certificate.extensions = [
            new pkijs.Extension({
                extnID: "2.5.29.19",
                critical: true,
                extnValue: extValue,
            }),
        ];
    }

    await certificate.sign(keys.privateKey as any, "SHA-256");

    return certificate;
}

describe("SimpleTrustStore", () => {
    let trustStore: SimpleTrustStore;
    let rootCert: pkijs.Certificate;

    beforeEach(async () => {
        trustStore = new SimpleTrustStore();
        rootCert = await createTestCertificate("Test Root CA", true);
    });

    describe("addCertificate", () => {
        it("should add a pkijs.Certificate directly", () => {
            trustStore.addCertificate(rootCert);
            expect(() => trustStore.verifyChain([rootCert])).not.toThrow();
        });

        it("should add a DER-encoded certificate", () => {
            const der = rootCert.toSchema().toBER(false);
            trustStore.addCertificate(new Uint8Array(der));
            expect(() => trustStore.verifyChain([rootCert])).not.toThrow();
        });

        it("should throw on invalid DER bytes", () => {
            const invalidDer = new Uint8Array([0x00, 0x01, 0x02, 0x03]);
            expect(() => {
                trustStore.addCertificate(invalidDer);
            }).toThrow();
        });

        it("should handle multiple certificates", async () => {
            const rootCert2 = await createTestCertificate("Test Root CA 2", true);
            trustStore.addCertificate(rootCert);
            trustStore.addCertificate(rootCert2);
            expect(() => trustStore.verifyChain([rootCert])).not.toThrow();
        });

        it("should handle empty array", () => {
            trustStore.addCertificate(rootCert);
            expect(() => trustStore.verifyChain([])).not.toThrow();
        });

        it("should store certificates for later verification", async () => {
            const cert1 = await createTestCertificate("CA 1", true);
            const cert2 = await createTestCertificate("CA 2", true);
            trustStore.addCertificate(cert1);
            trustStore.addCertificate(cert2);
            expect(() => trustStore.verifyChain([cert1])).not.toThrow();
            expect(() => trustStore.verifyChain([cert2])).not.toThrow();
        });
    });

    describe("verifyChain", () => {
        it("should return true for trusted CA", async () => {
            trustStore.addCertificate(rootCert);
            const result = await trustStore.verifyChain([rootCert]);
            expect(result).toBe(true);
        });

        it("should return false for untrusted CA", async () => {
            const untrustedRoot = await createTestCertificate("Untrusted CA", true);
            trustStore.addCertificate(rootCert);
            const result = await trustStore.verifyChain([untrustedRoot]);
            expect(result).toBe(false);
        });

        it("should return false for empty chain", async () => {
            trustStore.addCertificate(rootCert);
            const result = await trustStore.verifyChain([]);
            expect(result).toBe(false);
        });

        it("should return false when trust store is empty", async () => {
            const result = await trustStore.verifyChain([rootCert]);
            expect(result).toBe(false);
        });

        it("should accept DER-encoded trusted root", async () => {
            trustStore.addCertificate(rootCert);
            const rootDer = rootCert.toSchema().toBER(false);
            const result = await trustStore.verifyChain([new Uint8Array(rootDer)]);
            expect(result).toBe(true);
        });

        it("should verify multiple trusted CAs", async () => {
            const rootCert2 = await createTestCertificate("Test Root CA 2", true);
            trustStore.addCertificate(rootCert);
            trustStore.addCertificate(rootCert2);

            const result1 = await trustStore.verifyChain([rootCert]);
            const result2 = await trustStore.verifyChain([rootCert2]);

            expect(result1).toBe(true);
            expect(result2).toBe(true);
        });

        it("should reject chain with non-CA cert as root", async () => {
            const leafCert = await createTestCertificate("Leaf Cert", false);
            trustStore.addCertificate(rootCert);
            const result = await trustStore.verifyChain([leafCert]);
            expect(result).toBe(false);
        });

        it("should verify the first certificate as the target, not any chain member", async () => {
            const untrustedRoot = await createTestCertificate("Untrusted CA", true);
            trustStore.addCertificate(rootCert);
            const result = await trustStore.verifyChain([untrustedRoot, rootCert]);
            expect(result).toBe(false);
        });

        it("should trust a pinned target regardless of unrelated candidates", async () => {
            const untrustedRoot = await createTestCertificate("Untrusted CA", true);
            trustStore.addCertificate(rootCert);
            const result = await trustStore.verifyChain([rootCert, untrustedRoot]);
            expect(result).toBe(true);
        });
    });
});

// T11 (0x18/item-5): DER bytes that fail to decode -- truncated framing,
// undecodable content such as corrupted GeneralizedTime, or schema
// mismatch -- reject coded (INVALID_RESPONSE), never with a raw asn1js
// or pkijs Error. Certificates below are hand-built (no signature is
// minted: parsing runs before any signature check, so an unverifiable
// signature changes nothing about the exercised behavior).
describe("SimpleTrustStore DER taxonomy (T11/0x18/item-5)", () => {
    function handBuiltCertDer(notAfter: asn1js.UTCTime | asn1js.GeneralizedTime): Uint8Array {
        const name = new asn1js.Sequence({
            value: [
                new asn1js.Set({
                    value: [
                        new asn1js.Sequence({
                            value: [
                                new asn1js.ObjectIdentifier({ value: "2.5.4.3" }),
                                new asn1js.PrintableString({ value: "T11" }),
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
                name,
                new asn1js.Sequence({
                    value: [
                        new asn1js.UTCTime({ valueDate: new Date("2020-01-01T00:00:00Z") }),
                        notAfter,
                    ],
                }),
                name,
                new asn1js.Sequence({
                    value: [
                        new asn1js.Sequence({
                            value: [
                                new asn1js.ObjectIdentifier({ value: "1.2.840.113549.1.1.1" }),
                                new asn1js.Null(),
                            ],
                        }),
                        new asn1js.BitString({ valueHex: new Uint8Array([0x00]).buffer }),
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

    function corruptGeneralizedTime(der: Uint8Array): Uint8Array {
        const hits: number[] = [];
        for (let at = 0; at + 17 <= der.length; at++) {
            if (der[at] === 0x18 && der[at + 1] === 0x0f) hits.push(at);
        }
        expect(hits).toHaveLength(1);
        const out = new Uint8Array(der);
        out.set(new TextEncoder().encode("2030010100000!Z"), (hits[0] ?? 0) + 2);
        return out;
    }

    function outerBody(der: Uint8Array): Uint8Array {
        expect(der[0]).toBe(0x30);
        const first = der[1] ?? 0;
        return first < 0x80 ? der.slice(2) : der.slice(2 + (first & 0x7f));
    }

    function indefiniteOuter(der: Uint8Array): Uint8Array {
        return Uint8Array.of(0x30, 0x80, ...outerBody(der), 0x00, 0x00);
    }

    function nonMinimalOuter(der: Uint8Array): Uint8Array {
        const body = outerBody(der);
        return Uint8Array.of(
            0x30,
            0x83,
            0x00,
            (body.length >>> 8) & 0xff,
            body.length & 0xff,
            ...body
        );
    }

    function shortenedOuter(der: Uint8Array): Uint8Array {
        expect(der[0]).toBe(0x30);
        const out = new Uint8Array(der);
        const first = out[1] ?? 0;
        if (first < 0x80) {
            out[1] = first - 1;
            return out;
        }
        const n = first & 0x7f;
        let length = 0;
        for (let i = 0; i < n; i++) length = length * 256 + (out[2 + i] ?? 0);
        length -= 1;
        for (let i = n - 1; i >= 0; i--) {
            out[2 + i] = length & 0xff;
            length >>>= 8;
        }
        return out;
    }

    function expectInvalidResponse(fn: () => unknown, message: string): void {
        try {
            fn();
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((error as TimestampError).message).toBe(message);
            return;
        }
        throw new Error(`expected INVALID_RESPONSE: ${message}`);
    }

    it("pins a well-formed GeneralizedTime certificate (control)", () => {
        const der = handBuiltCertDer(
            new asn1js.GeneralizedTime({ valueDate: new Date("2030-01-01T00:00:00Z") })
        );
        expect(() => new SimpleTrustStore().addCertificate(der)).not.toThrow();
    });

    it("codes corrupted GeneralizedTime anchors as INVALID_RESPONSE", () => {
        const bad = corruptGeneralizedTime(
            handBuiltCertDer(new asn1js.GeneralizedTime({ valueDate: new Date("2030-01-01T00:00:00Z") }))
        );
        expectInvalidResponse(
            () => new SimpleTrustStore().addCertificate(bad),
            "Failed to parse trusted certificate"
        );
    });

    it("codes corrupted GeneralizedTime chain entries as INVALID_RESPONSE", async () => {
        const anchor = handBuiltCertDer(
            new asn1js.UTCTime({ valueDate: new Date("2030-01-01T00:00:00Z") })
        );
        const bad = corruptGeneralizedTime(
            handBuiltCertDer(new asn1js.GeneralizedTime({ valueDate: new Date("2030-01-01T00:00:00Z") }))
        );
        const store = new SimpleTrustStore();
        store.addCertificate(anchor);
        try {
            await store.verifyChainAtTime([bad], new Date());
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((error as TimestampError).message).toBe("Failed to parse chain certificate");
            return;
        }
        throw new Error("expected INVALID_RESPONSE for a corrupted chain entry");
    });

    it.each([
        ["NULL", Uint8Array.of(0x05, 0x00)],
        ["empty SEQUENCE", Uint8Array.of(0x30, 0x00)],
    ])("codes %s anchors as INVALID_RESPONSE instead of a raw schema error", (_label, bytes) => {
        expectInvalidResponse(
            () => new SimpleTrustStore().addCertificate(bytes),
            "Failed to parse trusted certificate"
        );
    });

    // BOUNDARY PINS (tolerated, NOT endorsed): indefinite, non-minimal,
    // and shortened outer framing currently pins because asn1js consumes
    // it leniently. Tightening acceptance is explicitly out of scope for
    // T11 (compat risk without ecosystem profiling); changing it requires
    // updating these pins plus the MIGRATION contract note.
    it("BOUNDARY: indefinite-length outer framing still pins", () => {
        const der = handBuiltCertDer(
            new asn1js.UTCTime({ valueDate: new Date("2030-01-01T00:00:00Z") })
        );
        expect(() => new SimpleTrustStore().addCertificate(indefiniteOuter(der))).not.toThrow();
    });

    it("BOUNDARY: non-minimal outer length still pins", () => {
        const der = handBuiltCertDer(
            new asn1js.UTCTime({ valueDate: new Date("2030-01-01T00:00:00Z") })
        );
        expect(() => new SimpleTrustStore().addCertificate(nonMinimalOuter(der))).not.toThrow();
    });

    it("BOUNDARY: a shortened outer length still verifies against its anchor", async () => {
        const root = await createTestCertificate("T11 BER Root", true);
        const der = new Uint8Array(root.toSchema().toBER(false));
        const store = new SimpleTrustStore();
        store.addCertificate(root);
        await expect(store.verifyChainAtTime([shortenedOuter(der)], new Date())).resolves.toBe(true);
    });

    it("codes an empty-SEQUENCE chain entry as INVALID_RESPONSE", async () => {
        const anchor = handBuiltCertDer(
            new asn1js.UTCTime({ valueDate: new Date("2030-01-01T00:00:00Z") })
        );
        const store = new SimpleTrustStore();
        store.addCertificate(anchor);
        try {
            await store.verifyChainAtTime([Uint8Array.of(0x30, 0x00)], new Date());
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.INVALID_RESPONSE);
            expect((error as TimestampError).message).toBe("Failed to parse chain certificate");
            return;
        }
        throw new Error("expected INVALID_RESPONSE for an empty-SEQUENCE chain entry");
    });
});
