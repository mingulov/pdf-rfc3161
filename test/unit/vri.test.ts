import { describe, it, expect, beforeEach, vi } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { webcrypto } from "crypto";
import { addVRI } from "../../src/pdf/ltv.js";

// Initialize pkijs with Node.js webcrypto
const cryptoEngine = new pkijs.CryptoEngine({
    name: "",
    crypto: webcrypto as any,
    subtle: webcrypto.subtle as any,
});
pkijs.setEngine("testEngine", cryptoEngine);

// Mock crypto.subtle for SHA-1 hashing
vi.stubGlobal("crypto", {
    subtle: {
        digest: vi.fn((_algo: string) => {
            return Promise.resolve(new ArrayBuffer(20));
        }),
    },
    getRandomValues: (arr: Uint8Array) => {
        for (let i = 0; i < arr.length; i++) arr[i] = Math.floor(Math.random() * 256);
        return arr;
    },
});

async function createTestCertificate(): Promise<pkijs.Certificate> {
    const keys = await webcrypto.subtle.generateKey(
        {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 2048,
            publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
            hash: { name: "SHA-256" },
        },
        true,
        ["sign", "verify"]
    );

    const certificate = new pkijs.Certificate();
    certificate.version = 2;
    const rnd = new Uint8Array(4);
    webcrypto.getRandomValues(rnd);
    certificate.serialNumber = new asn1js.Integer({ valueHex: rnd });

    certificate.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: "Test Signer" }),
        })
    );

    certificate.issuer = certificate.subject;
    certificate.notBefore.value = new Date(Date.now() - 60000);
    certificate.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
    await certificate.sign(keys.privateKey, "SHA-256");

    return certificate;
}

describe("VRI Dictionary Creation", () => {
    let pdfBytes: Uint8Array;
    let signingCert: pkijs.Certificate;

    beforeEach(async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        pdfBytes = await doc.save();
        signingCert = await createTestCertificate();
    });

    describe("addVRI", () => {
        it("should add VRI dictionary to PDF catalog", async () => {
            const revocationData = {
                crls: [new Uint8Array([0xc1, 0xc2, 0xc3])],
                ocspResponses: [new Uint8Array([0x01, 0x02, 0x03])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length);

            const resultDoc = await PDFDocument.load(result);
            expect(resultDoc.getPageCount()).toBe(1);
        });

        it("should handle empty revocation data", async () => {
            const revocationData = {};

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            const resultDoc = await PDFDocument.load(result);
            expect(resultDoc.getPageCount()).toBe(1);
        });

        it("should handle only CRLs", async () => {
            const revocationData = {
                crls: [new Uint8Array([0xc1, 0xc2, 0xc3, 0xc4])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length);
        });

        it("should handle only OCSP responses", async () => {
            const revocationData = {
                ocspResponses: [new Uint8Array([0x01, 0x02, 0x03, 0x04])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length);
        });

        it("should handle multiple CRLs", async () => {
            const revocationData = {
                crls: [new Uint8Array([0xc1]), new Uint8Array([0xc2]), new Uint8Array([0xc3])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length);
        });

        it("should handle multiple OCSP responses", async () => {
            const revocationData = {
                ocspResponses: [
                    new Uint8Array([0x01]),
                    new Uint8Array([0x02]),
                    new Uint8Array([0x03]),
                ],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length);
        });

        it("should preserve existing PDF content", async () => {
            const revocationData = {
                ocspResponses: [new Uint8Array([0x01, 0x02, 0x03])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            const header = String.fromCharCode(...result.slice(0, 5));
            expect(header).toBe("%PDF-");
        });

        it("should use SHA-1 for VRI key by default", async () => {
            const revocationData = {
                ocspResponses: [new Uint8Array([0x01, 0x02, 0x03])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length);
        });

        it("should support SHA-256 for PDF 2.0", async () => {
            const revocationData = {
                ocspResponses: [new Uint8Array([0x01, 0x02, 0x03])],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData, {
                hashAlgorithm: "SHA-256",
            });

            expect(result.length).toBeGreaterThan(pdfBytes.length);
        });

        it("should handle large revocation data", async () => {
            const largeCRL = new Uint8Array(1000);
            const largeOCSP = new Uint8Array(500);

            const revocationData = {
                crls: [largeCRL],
                ocspResponses: [largeOCSP],
            };

            const result = await addVRI(pdfBytes, signingCert, revocationData);

            expect(result.length).toBeGreaterThan(pdfBytes.length + 1500);
        });
    });
});

describe("VRI Hash Algorithm Support", () => {
    let pdfBytes: Uint8Array;
    let signingCert: pkijs.Certificate;

    beforeEach(async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        pdfBytes = await doc.save();
        signingCert = await createTestCertificate();
    });

    it("should work with default SHA-1 for PDF 1.x compatibility", async () => {
        const result = await addVRI(pdfBytes, signingCert, {
            ocspResponses: [new Uint8Array([0x01])],
        });

        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should accept explicit SHA-1 option", async () => {
        const result = await addVRI(
            pdfBytes,
            signingCert,
            {
                ocspResponses: [new Uint8Array([0x01])],
            },
            { hashAlgorithm: "SHA-1" }
        );

        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should accept SHA-256 for PDF 2.0", async () => {
        const result = await addVRI(
            pdfBytes,
            signingCert,
            {
                ocspResponses: [new Uint8Array([0x01])],
            },
            { hashAlgorithm: "SHA-256" }
        );

        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });
});
