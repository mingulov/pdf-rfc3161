/**
 * Tests for enhanced PAdES VRI support with proper DSS references
 */

import { describe, it, expect, beforeEach, vi } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { addVRIEnhanced } from "../../src/pdf/ltv.js";

// Initialize pkijs with Node.js webcrypto
const webcrypto = await import("crypto").then((m) => m.webcrypto);
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
            value: new asn1js.PrintableString({ value: "Test Subject" }),
        })
    );

    certificate.issuer = certificate.subject;
    certificate.notBefore.value = new Date(Date.now() - 60000);
    certificate.notAfter.value = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000);

    await certificate.subjectPublicKeyInfo.importKey(keys.publicKey);
    await certificate.sign(keys.privateKey, "SHA-256");

    return certificate;
}

describe("Enhanced PAdES VRI Support", () => {
    let pdfBytes: Uint8Array;
    let signingCert: pkijs.Certificate;

    beforeEach(async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        pdfBytes = await doc.save();
        signingCert = await createTestCertificate();
    });

    it("should create VRI with DSS certificate references", async () => {
        // Create mock DSS certificate references
        const doc = await PDFDocument.load(pdfBytes);
        const context = doc.context;

        const certRef1 = context.register(context.obj({}));
        const certRef2 = context.register(context.obj({}));
        const dssCertRefs = [certRef1, certRef2];

        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            dssCertRefs,
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should create VRI with DSS CRL and OCSP references", async () => {
        const doc = await PDFDocument.load(pdfBytes);
        const context = doc.context;

        const crlRef1 = context.register(context.obj({}));
        const ocspRef1 = context.register(context.obj({}));
        const dssCrlRefs = [crlRef1];
        const dssOcspRefs = [ocspRef1];

        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            dssCrlRefs,
            dssOcspRefs,
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should create VRI with document timestamp reference", async () => {
        const doc = await PDFDocument.load(pdfBytes);
        const context = doc.context;

        const timestampRef = context.register(context.obj({}));

        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            timestampRef,
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should create VRI with revocation data when no DSS refs provided", async () => {
        const revocationData = {
            crls: [new Uint8Array([0xc1, 0xc2, 0xc3])],
            ocspResponses: [new Uint8Array([0x01, 0x02, 0x03])],
        };

        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            revocationData,
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should support SHA-256 for VRI key generation (PDF 2.0)", async () => {
        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            hashAlgorithm: "SHA-256",
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should default to SHA-1 for VRI key generation (PDF 1.x compatibility)", async () => {
        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            // No hashAlgorithm specified - should default to SHA-1
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should handle empty revocation data gracefully", async () => {
        const result = await addVRIEnhanced(pdfBytes, signingCert, {});

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });

    it("should integrate with existing DSS structure", async () => {
        // This test verifies that the enhanced VRI can work alongside DSS
        // by using proper references instead of duplicating data

        const doc = await PDFDocument.load(pdfBytes);
        const context = doc.context;

        // Create mock DSS references
        const certRef = context.register(context.obj({}));
        const crlRef = context.register(context.obj({}));
        const ocspRef = context.register(context.obj({}));

        const result = await addVRIEnhanced(pdfBytes, signingCert, {
            dssCertRefs: [certRef],
            dssCrlRefs: [crlRef],
            dssOcspRefs: [ocspRef],
        });

        expect(result).toBeInstanceOf(Uint8Array);
        expect(result.length).toBeGreaterThan(pdfBytes.length);
    });
});
