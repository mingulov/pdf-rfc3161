import { describe, it, expect, beforeEach } from "vitest";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { SimpleTrustStore } from "../../../core/src/pki/trust-store.js";
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
    });
});
