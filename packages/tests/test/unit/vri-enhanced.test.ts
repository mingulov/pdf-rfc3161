import { describe, expect, it } from "vitest";
import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import {
    PDFArray,
    decodePDFRawStream,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFRawStream,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { addVRIEnhanced, type AddVRIEnhancedOptions } from "../../../core/src/pdf/ltv.js";
import { TimestampErrorCode } from "../../../core/src/types.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

async function createSignedPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of("3003020101000000") });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

let certificatePromise: Promise<pkijs.Certificate> | undefined;

async function createCertificate(): Promise<pkijs.Certificate> {
    certificatePromise ??= (async () => {
        const keys = await generateRSAKeyPair();
        const certificate = new pkijs.Certificate();
        certificate.version = 2;
        certificate.serialNumber = new asn1js.Integer({ value: 1 });
        certificate.subject.typesAndValues.push(
            new pkijs.AttributeTypeAndValue({
                type: "2.5.4.3",
                value: new asn1js.PrintableString({ value: "Legacy VRI Test" }),
            })
        );
        certificate.issuer = certificate.subject;
        certificate.notBefore.value = new Date("2025-01-01T00:00:00Z");
        certificate.notAfter.value = new Date("2030-01-01T00:00:00Z");
        certificate.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);
        await certificate.sign(keys.privateKey, "SHA-256", cryptoEngine);
        return certificate;
    })();
    return certificatePromise;
}

async function createForeignReference(): Promise<PDFRef> {
    const document = await PDFDocument.create();
    return document.context.register(document.context.obj({ Foreign: PDFName.of("Reference") }));
}

function requireDict(value: unknown, message: string): PDFDict {
    expect(value, message).toBeInstanceOf(PDFDict);
    if (!(value instanceof PDFDict)) {
        throw new Error(message);
    }
    return value;
}

function requireArray(value: unknown, message: string): PDFArray {
    expect(value, message).toBeInstanceOf(PDFArray);
    if (!(value instanceof PDFArray)) {
        throw new Error(message);
    }
    return value;
}

function arrayRefs(array: PDFArray, message: string): PDFRef[] {
    const refs: PDFRef[] = [];
    for (let index = 0; index < array.size(); index++) {
        const ref = array.get(index);
        expect(ref, message).toBeInstanceOf(PDFRef);
        if (!(ref instanceof PDFRef)) {
            throw new Error(message);
        }
        refs.push(ref);
    }
    return refs;
}

function assertValidationBytesShareRefs(
    document: PDFDocument,
    expected: { certificates: Uint8Array[]; crls: Uint8Array[]; ocspResponses: Uint8Array[] }
): void {
    const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
    const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");
    const [entryValue] = vri.values();
    const entry = requireDict(
        entryValue instanceof PDFRef ? document.context.lookup(entryValue) : entryValue,
        "VRI entry is required"
    );

    for (const [entryKey, dssKey, expectedBytes] of [
        ["Cert", "Certs", expected.certificates],
        ["CRL", "CRLs", expected.crls],
        ["OCSP", "OCSPs", expected.ocspResponses],
    ] as const) {
        const dssRefs = arrayRefs(
            requireArray(dss.lookup(PDFName.of(dssKey)), `${dssKey} is required`),
            `${dssKey} entries must be references`
        );
        const entryRefs = arrayRefs(
            requireArray(entry.lookup(PDFName.of(entryKey)), `${entryKey} is required`),
            `${entryKey} entries must be references`
        );
        expect(entryRefs).toHaveLength(expectedBytes.length);

        for (const bytes of expectedBytes) {
            const globalRef = dssRefs.find((ref) => {
                const stream = document.context.lookup(ref);
                if (!(stream instanceof PDFRawStream)) {
                    return false;
                }
                const decoded = decodePDFRawStream(stream).decode();
                return (
                    decoded.length === bytes.length &&
                    decoded.every((value, index) => value === bytes[index])
                );
            });
            expect(globalRef).toBeDefined();
            expect(entryRefs).toContainEqual(globalRef);
        }
    }
}

describe("deprecated addVRIEnhanced compatibility", () => {
    it("rejects the old call shape without a signature field name", async () => {
        await expect(
            addVRIEnhanced(await createSignedPdf(), await createCertificate(), {})
        ).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_ARGUMENT,
        });
    });

    it("delegates raw revocation data when a signature field name is supplied", async () => {
        const certificate = await createCertificate();
        const crls = [Uint8Array.of(0x30, 0x01, 0x02)];
        const ocspResponses = [Uint8Array.of(0x30, 0x01, 0x03)];
        const updated = await addVRIEnhanced(await createSignedPdf(), certificate, {
            signatureFieldName: "Timestamp",
            revocationData: {
                crls,
                ocspResponses,
            },
        });

        const document = await PDFDocument.load(updated, { updateMetadata: false });
        assertValidationBytesShareRefs(document, {
            certificates: [new Uint8Array(certificate.toSchema().toBER(false))],
            crls,
            ocspResponses,
        });
    });

    const unsafeOptions: [string, () => Promise<AddVRIEnhancedOptions>][] = [
        ["timestamp references", async () => ({ timestampRef: await createForeignReference() })],
        ["certificate references", async () => ({ dssCertRefs: [await createForeignReference()] })],
        ["CRL references", async () => ({ dssCrlRefs: [await createForeignReference()] })],
        ["OCSP references", async () => ({ dssOcspRefs: [await createForeignReference()] })],
        ["SHA-256 selection", async () => ({ hashAlgorithm: "SHA-256" as const })],
    ];

    it.each(unsafeOptions)(
        "rejects %s",
        async (_label: string, optionsForTest: () => Promise<AddVRIEnhancedOptions>) => {
            await expect(
                addVRIEnhanced(await createSignedPdf(), await createCertificate(), {
                    signatureFieldName: "Timestamp",
                    ...(await optionsForTest()),
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
        }
    );
});
