import { createHash } from "node:crypto";
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
    type PDFObject,
    PDFRawStream,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { TimestampErrorCode } from "../../../core/src/types.js";
import { addDSS, addVRI, addVRIForSignature } from "../../../core/src/pdf/ltv.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

const paddedContents = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00);
const trimmedContents = Uint8Array.of(0x30, 0x03, 0x02, 0x01, 0x01);

interface SignatureFieldFixture {
    name: string;
    fieldType?: "Sig" | "Tx";
    signed?: boolean;
    contents?: PDFHexString | PDFString;
}

function contentsHex(contents: Uint8Array): string {
    return Buffer.from(contents).toString("hex");
}

async function createPdfWithFields(fields: SignatureFieldFixture[]): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const fieldArray = PDFArray.withContext(context);

    for (const fixture of fields) {
        const field = context.obj({
            FT: PDFName.of(fixture.fieldType ?? "Sig"),
            T: PDFString.of(fixture.name),
        });

        if (fixture.signed ?? true) {
            const signature = context.obj({
                Contents: fixture.contents ?? PDFHexString.of(contentsHex(paddedContents)),
            });
            field.set(PDFName.of("V"), context.register(signature));
        }

        fieldArray.push(context.register(field));
    }

    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fieldArray }));
    return document.save();
}

async function createNestedSignatureFieldPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const child = context.obj({
        FT: context.register(PDFName.of("Sig")),
        T: PDFString.of("Timestamp"),
        V: context.obj({
            Contents: context.register(PDFHexString.of(contentsHex(paddedContents))),
        }),
    });
    const kids = PDFArray.withContext(context);
    kids.push(child);
    const parent = context.obj({ T: PDFString.of("Parent"), Kids: kids });
    const fields = PDFArray.withContext(context);
    const parentRef = context.register(parent);
    child.set(PDFName.of("Parent"), parentRef);
    fields.push(parentRef);
    const acroForm = context.obj({ Fields: context.register(fields) });
    document.catalog.set(PDFName.of("AcroForm"), context.register(acroForm));
    return document.save();
}

async function createInheritedSignatureFieldPdf(options: {
    inheritFieldType: boolean;
    inheritSignatureValue: boolean;
    indirectParent: boolean;
    includeChildParent?: boolean;
}): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const signatureRef = context.register(signature);
    const child = context.obj({ T: PDFString.of("Timestamp") });
    const childRef = context.register(child);
    const parentFields: Record<string, PDFObject> = {
        T: PDFString.of("Parent"),
        Kids: context.obj([childRef]),
    };

    if (options.inheritFieldType) {
        parentFields.FT = PDFName.of("Sig");
    } else {
        child.set(PDFName.of("FT"), PDFName.of("Sig"));
    }
    if (options.inheritSignatureValue) {
        parentFields.V = signatureRef;
    } else {
        child.set(PDFName.of("V"), signatureRef);
    }

    const parent = context.obj(parentFields);
    const parentRef = options.indirectParent ? context.register(parent) : undefined;
    if (options.indirectParent) {
        if (parentRef === undefined) {
            throw new Error("indirect parent reference is required");
        }
        if (options.includeChildParent ?? true) child.set(PDFName.of("Parent"), parentRef);
    } else if (options.includeChildParent ?? true) {
        child.set(PDFName.of("Parent"), parent);
    }

    const fields = PDFArray.withContext(context);
    fields.push(parentRef ?? parent);
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createMalformedParentPdf(cyclic: boolean): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const child = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const childRef = context.register(child);

    if (cyclic) {
        const parent = context.obj({ T: PDFString.of("Parent"), Kids: context.obj([childRef]) });
        const parentRef = context.register(parent);
        child.set(PDFName.of("Parent"), parentRef);
        parent.set(PDFName.of("Parent"), childRef);
    } else {
        child.set(PDFName.of("Parent"), PDFString.of("not-a-field"));
    }

    const fields = PDFArray.withContext(context);
    fields.push(childRef);
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createCyclicKidsPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) }),
    });
    const fieldRef = context.register(field);
    const kids = PDFArray.withContext(context);
    kids.push(fieldRef);
    field.set(PDFName.of("Kids"), kids);
    const fields = PDFArray.withContext(context);
    fields.push(fieldRef);
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createMalformedKidsPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) }),
        Kids: PDFString.of("not-an-array"),
    });
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createSignatureFieldWithWidget(indirectWidget: boolean): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const fieldRef = context.register(field);
    const widget = context.obj({
        Type: PDFName.of("Annot"),
        Subtype: PDFName.of("Widget"),
        Parent: fieldRef,
    });
    const kids = PDFArray.withContext(context);
    kids.push(indirectWidget ? context.register(widget) : widget);
    field.set(PDFName.of("Kids"), kids);
    const fields = PDFArray.withContext(context);
    fields.push(fieldRef);
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createDirectChildWithIndirectParentPdf(includeChildParent = true): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const child = context.obj({
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const kids = PDFArray.withContext(context);
    kids.push(child);
    const parent = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Parent"),
        Kids: kids,
    });
    const parentRef = context.register(parent);
    if (includeChildParent) child.set(PDFName.of("Parent"), parentRef);
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([parentRef]) }));
    return document.save();
}

async function createWidgetWithDirectParentPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const fieldRef = context.register(field);
    const directParent = context.obj({ T: PDFString.of("SpoofedParent") });
    const widget = context.obj({
        Type: PDFName.of("Annot"),
        Subtype: PDFName.of("Widget"),
        Parent: directParent,
    });
    field.set(PDFName.of("Kids"), context.obj([widget]));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([fieldRef]) }));
    return document.save();
}

async function createUnnamedNonWidgetChildPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const kids = PDFArray.withContext(context);
    kids.push(context.register(context.obj({ Subtype: PDFName.of("Text") })));
    field.set(PDFName.of("Kids"), kids);
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createSharedSignatureChildPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const child = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const childRef = context.register(child);
    const parent = context.obj({
        T: PDFString.of("Parent"),
        Kids: context.obj([childRef, childRef]),
    });
    const parentRef = context.register(parent);
    child.set(PDFName.of("Parent"), parentRef);
    const fields = context.obj([parentRef]);

    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save();
}

async function createSignaturePdfWithObjectHeaderSpoof(objectNumber: number): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const spoofedObjectText = `${objectNumber.toString()} 0 obj`;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));

    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    document.catalog.set(PDFName.of("SpoofLiteral"), PDFString.of(spoofedObjectText));
    return document.save({ useObjectStreams: false });
}

interface ExistingVriFixtureOptions {
    catalogVri?: boolean;
    orphanTarget?: boolean;
    orphanTargetKey?: "Cert" | "CRL" | "OCSP";
    orphanOtherEntry?: boolean;
    capturedTarget?: boolean;
    targetEntryType?: "absent" | "wrong";
    indirectTargetEntry?: boolean;
    otherEntryType?: "absent" | "wrong";
    indirectOtherEntry?: boolean;
}

async function createExistingVriFixture(options: ExistingVriFixtureOptions): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = context.obj({ Contents: PDFHexString.of(contentsHex(paddedContents)) });
    const field = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Timestamp"),
        V: context.register(signature),
    });
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    const globalCert = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x01, 0x01))
    );
    const globalCrl = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x01, 0x02))
    );
    const globalOcsp = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x01, 0x03))
    );
    const orphanReference = context.register(
        PDFRawStream.of(PDFDict.withContext(context), Uint8Array.of(0x30, 0x01, 0x7f))
    );
    const certs = PDFArray.withContext(context);
    certs.push(globalCert);
    const crls = PDFArray.withContext(context);
    crls.push(globalCrl);
    const ocsps = PDFArray.withContext(context);
    ocsps.push(globalOcsp);
    const targetKey = options.orphanTargetKey ?? "Cert";
    const targetReference =
        targetKey === "Cert" ? globalCert : targetKey === "CRL" ? globalCrl : globalOcsp;
    const capturedReference = PDFRef.of(context.largestObjectNumber + 1);
    const targetRefs = PDFArray.withContext(context);
    targetRefs.push(
        options.capturedTarget
            ? capturedReference
            : options.orphanTarget
              ? orphanReference
              : targetReference
    );
    const targetEntry = context.obj({
        [targetKey]: targetRefs,
        ...(options.targetEntryType === "wrong" ? { Type: PDFName.of("VendorVRI") } : {}),
    });
    const vri = context.obj({
        [createHash("sha1").update(paddedContents).digest("hex").toUpperCase()]:
            options.indirectTargetEntry ? context.register(targetEntry) : targetEntry,
    });

    if (options.orphanOtherEntry) {
        const otherRefs = PDFArray.withContext(context);
        otherRefs.push(orphanReference);
        vri.set(PDFName.of("Other"), context.obj({ Cert: otherRefs }));
    }
    if (options.otherEntryType !== undefined) {
        const otherEntry = context.obj({
            ...(options.otherEntryType === "wrong" ? { Type: PDFName.of("VendorVRI") } : {}),
        });
        vri.set(
            PDFName.of("Other"),
            options.indirectOtherEntry ? context.register(otherEntry) : otherEntry
        );
    }

    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    document.catalog.set(
        PDFName.of("DSS"),
        context.obj({
            Certs: certs,
            CRLs: crls,
            OCSPs: ocsps,
            VRI: vri,
            VendorData: PDFName.of("Preserved"),
        })
    );
    if (options.catalogVri) {
        document.catalog.set(PDFName.of("VRI"), context.obj({ Legacy: PDFName.of("Forbidden") }));
    }
    return document.save({ useObjectStreams: false });
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

function indirectHeaderNumbers(bytes: Uint8Array): number[] {
    return [...new TextDecoder("latin1").decode(bytes).matchAll(/(\d+)\s+\d+\s+obj\b/g)].map(
        (match) => Number.parseInt(match[1] ?? "", 10)
    );
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
                return (
                    stream instanceof PDFRawStream &&
                    decodePDFRawStream(stream)
                        .decode()
                        .every((value, index) => value === bytes[index]) &&
                    stream.getContentsSize() === bytes.length
                );
            });
            expect(globalRef).toBeDefined();
            expect(entryRefs).toContainEqual(globalRef);
        }
    }
}

async function createForeignReference(): Promise<PDFRef> {
    const document = await PDFDocument.create();
    return document.context.register(document.context.obj({ Foreign: PDFName.of("Reference") }));
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

describe("signature-specific VRI", () => {
    const validationData = {
        certificates: [Uint8Array.of(0x30, 0x01, 0x01)],
        crls: [Uint8Array.of(0x30, 0x01, 0x02)],
        ocspResponses: [Uint8Array.of(0x30, 0x01, 0x03)],
    };

    it("hashes the complete decoded padded Contents bytes and reuses global DSS references", async () => {
        const decodedPadded = createHash("sha1").update(paddedContents).digest("hex").toUpperCase();
        const asciiHex = createHash("sha1")
            .update(Buffer.from(contentsHex(paddedContents), "ascii"))
            .digest("hex")
            .toUpperCase();
        const trimmedDer = createHash("sha1").update(trimmedContents).digest("hex").toUpperCase();
        expect(new Set([decodedPadded, asciiHex, trimmedDer]).size).toBe(3);

        const pdf = await createPdfWithFields([{ name: "Timestamp" }]);
        const updated = await addVRIForSignature(
            pdf,
            { fieldName: "Timestamp" },
            { validationData }
        );
        const document = await PDFDocument.load(updated, { updateMetadata: false });

        expect(updated.slice(0, pdf.length)).toEqual(pdf);
        expect(document.catalog.has(PDFName.of("VRI"))).toBe(false);

        const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
        const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");
        expect([...vri.keys()].map((key) => key.decodeText())).toEqual([decodedPadded]);
        expect(vri.has(PDFName.of(asciiHex))).toBe(false);
        expect(vri.has(PDFName.of(trimmedDer))).toBe(false);

        const entry = requireDict(vri.lookup(PDFName.of(decodedPadded)), "VRI entry is required");
        expect(entry.get(PDFName.of("Type"))).toEqual(PDFName.of("VRI"));

        for (const [entryKey, dssKey] of [
            ["Cert", "Certs"],
            ["CRL", "CRLs"],
            ["OCSP", "OCSPs"],
        ] as const) {
            const entryRefs = requireArray(
                entry.lookup(PDFName.of(entryKey)),
                `${entryKey} is required`
            );
            const dssRefs = requireArray(dss.lookup(PDFName.of(dssKey)), `${dssKey} is required`);
            expect(entryRefs.size()).toBe(1);
            expect(entryRefs.get(0)).toBeInstanceOf(PDFRef);
            expect(entryRefs.get(0)).toEqual(dssRefs.get(0));
        }
    });

    it("preserves a same-signature VRI entry while appending new validation material", async () => {
        const pdf = await createPdfWithFields([{ name: "Timestamp" }]);
        const first = await addVRIForSignature(
            pdf,
            { fieldName: "Timestamp" },
            {
                validationData: {
                    certificates: [Uint8Array.of(0x30, 0x01, 0x01)],
                    crls: [],
                    ocspResponses: [],
                },
            }
        );
        const second = await addVRIForSignature(
            first,
            { fieldName: "Timestamp" },
            {
                validationData: {
                    certificates: [Uint8Array.of(0x30, 0x01, 0x02)],
                    crls: [],
                    ocspResponses: [],
                },
            }
        );
        const document = await PDFDocument.load(second, { updateMetadata: false });
        const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
        const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");
        const [key] = [...vri.keys()];
        expect(key).toBeDefined();
        if (key === undefined) {
            throw new Error("VRI key is required");
        }

        const entry = requireDict(vri.lookup(key), "VRI entry is required");
        const entryRefs = requireArray(entry.lookup(PDFName.of("Cert")), "Cert is required");
        const dssRefs = requireArray(dss.lookup(PDFName.of("Certs")), "Certs is required");
        expect(second.slice(0, first.length)).toEqual(first);
        expect(entryRefs.size()).toBe(2);
        expect(entryRefs.get(0)).toEqual(dssRefs.get(0));
        expect(entryRefs.get(1)).toEqual(dssRefs.get(1));
    });

    it("resolves a fully qualified field name through direct and indirect field graph values", async () => {
        const updated = await addVRIForSignature(
            await createNestedSignatureFieldPdf(),
            { fieldName: "Parent.Timestamp" },
            { validationData }
        );
        const document = await PDFDocument.load(updated, { updateMetadata: false });
        const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");

        expect(dss.lookup(PDFName.of("VRI"))).toBeInstanceOf(PDFDict);
    });

    it.each([
        { inheritFieldType: true, inheritSignatureValue: false },
        { inheritFieldType: false, inheritSignatureValue: true },
        { inheritFieldType: true, inheritSignatureValue: true },
    ])(
        "resolves inherited signature values through an indirect Parent field",
        async ({
            inheritFieldType,
            inheritSignatureValue,
        }: {
            inheritFieldType: boolean;
            inheritSignatureValue: boolean;
        }) => {
            const updated = await addVRIForSignature(
                await createInheritedSignatureFieldPdf({
                    inheritFieldType,
                    inheritSignatureValue,
                    indirectParent: true,
                }),
                { fieldName: "Parent.Timestamp" },
                { validationData }
            );
            const document = await PDFDocument.load(updated, { updateMetadata: false });
            expect(document.catalog.lookup(PDFName.of("DSS"))).toBeInstanceOf(PDFDict);
        }
    );

    it("rejects an inherited field value through a direct Parent dictionary", async () => {
        await expect(
            addVRIForSignature(
                await createInheritedSignatureFieldPdf({
                    inheritFieldType: true,
                    inheritSignatureValue: true,
                    indirectParent: false,
                }),
                { fieldName: "Parent.Timestamp" },
                { validationData }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("rejects a child reached through a direct root parent without an indirect Parent link", async () => {
        await expect(
            addVRIForSignature(
                await createInheritedSignatureFieldPdf({
                    inheritFieldType: false,
                    inheritSignatureValue: false,
                    indirectParent: false,
                    includeChildParent: false,
                }),
                { fieldName: "Parent.Timestamp" },
                { validationData }
            )
        ).rejects.toThrow("Field /Parent must be the exact indirect containing /Kids field");
    });

    it.each([false, true])(
        "rejects a malformed or cyclic Parent field chain when cyclic=%s",
        async (cyclic: boolean) => {
            await expect(
                addVRIForSignature(
                    await createMalformedParentPdf(cyclic),
                    { fieldName: "Timestamp" },
                    { validationData }
                )
            ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        }
    );

    it.each([false, true])(
        "normalizes an absent /Type on a non-target VRI entry when it is indirect=%s",
        async (indirectOtherEntry: boolean) => {
            const updated = await addVRIForSignature(
                await createExistingVriFixture({
                    otherEntryType: "absent",
                    indirectOtherEntry,
                }),
                { fieldName: "Timestamp" },
                { validationData: { certificates: [], crls: [], ocspResponses: [] } }
            );
            const document = await PDFDocument.load(updated, { updateMetadata: false });
            const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
            const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");
            const otherValue = vri.get(PDFName.of("Other"));
            const other = requireDict(
                otherValue instanceof PDFRef ? document.context.lookup(otherValue) : otherValue,
                "Other VRI entry is required"
            );

            expect(other.get(PDFName.of("Type"))).toEqual(PDFName.of("VRI"));
        }
    );

    it.each([false, true])(
        "rejects a wrong /Type on a non-target VRI entry when it is indirect=%s",
        async (indirectOtherEntry: boolean) => {
            await expect(
                addVRIForSignature(
                    await createExistingVriFixture({
                        otherEntryType: "wrong",
                        indirectOtherEntry,
                    }),
                    { fieldName: "Timestamp" },
                    { validationData }
                )
            ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        }
    );

    it.each([false, true])(
        "selects the named signature field once when its unnamed widget child is indirect=%s",
        async (indirectWidget: boolean) => {
            const updated = await addVRIForSignature(
                await createSignatureFieldWithWidget(indirectWidget),
                { fieldName: "Timestamp" },
                { validationData }
            );
            const document = await PDFDocument.load(updated, { updateMetadata: false });
            const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
            const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");

            expect(vri.keys()).toHaveLength(1);
        }
    );

    it("rejects an unnamed non-widget child instead of inheriting the parent field name", async () => {
        await expect(
            addVRIForSignature(
                await createUnnamedNonWidgetChildPdf(),
                { fieldName: "Timestamp" },
                { validationData }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("accepts a direct child with the exact indirect containing Parent field", async () => {
        const updated = await addVRIForSignature(
            await createDirectChildWithIndirectParentPdf(),
            { fieldName: "Parent.Timestamp" },
            { validationData }
        );
        const document = await PDFDocument.load(updated, { updateMetadata: false });
        expect(document.catalog.lookup(PDFName.of("DSS"))).toBeInstanceOf(PDFDict);
    });

    it("rejects a direct child missing the required indirect Parent field", async () => {
        await expect(
            addVRIForSignature(
                await createDirectChildWithIndirectParentPdf(false),
                { fieldName: "Parent.Timestamp" },
                { validationData }
            )
        ).rejects.toThrow("Field /Parent must be the exact indirect containing /Kids field");
    });

    it("rejects a direct Parent dictionary on an unnamed widget child", async () => {
        await expect(
            addVRIForSignature(
                await createWidgetWithDirectParentPdf(),
                { fieldName: "Timestamp" },
                { validationData }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("rejects a child reused through one valid Parent /Kids array", async () => {
        await expect(
            addVRIForSignature(
                await createSharedSignatureChildPdf(),
                { fieldName: "Parent.Timestamp" },
                { validationData }
            )
        ).rejects.toThrow("Field hierarchy reuses a field node");
    });

    it("rejects cyclic field Kids graphs instead of recursing indefinitely", async () => {
        await expect(
            addVRIForSignature(
                await createCyclicKidsPdf(),
                { fieldName: "Timestamp" },
                { validationData }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("rejects malformed field Kids values", async () => {
        await expect(
            addVRIForSignature(
                await createMalformedKidsPdf(),
                { fieldName: "Timestamp" },
                { validationData }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("rejects a Catalog-level VRI before mutating the requested VRI", async () => {
        const input = await createExistingVriFixture({ catalogVri: true });
        const original = input.slice();

        await expect(
            addVRIForSignature(input, { fieldName: "Timestamp" }, { validationData })
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        expect(input).toEqual(original);
        const reloaded = await PDFDocument.load(input, { updateMetadata: false });
        expect(reloaded.catalog.lookup(PDFName.of("VRI"))).toBeInstanceOf(PDFDict);
        expect(reloaded.catalog.lookup(PDFName.of("DSS"))).toBeInstanceOf(PDFDict);
    });

    it.each(["Cert", "CRL", "OCSP"] as const)(
        "rejects an orphan target VRI /%s reference even when no category is incoming",
        async (orphanTargetKey: "Cert" | "CRL" | "OCSP") => {
            const input = await createExistingVriFixture({ orphanTarget: true, orphanTargetKey });
            const original = input.slice();

            await expect(
                addVRIForSignature(
                    input,
                    { fieldName: "Timestamp" },
                    {
                        validationData: { certificates: [], crls: [], ocspResponses: [] },
                    }
                )
            ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
            expect(input).toEqual(original);
            await expect(PDFDocument.load(input, { updateMetadata: false })).resolves.toBeDefined();
        }
    );

    it("rejects an orphan reference in any existing DSS VRI entry", async () => {
        const input = await createExistingVriFixture({ orphanOtherEntry: true });
        const original = input.slice();

        await expect(
            addVRIForSignature(input, { fieldName: "Timestamp" }, { validationData })
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        expect(input).toEqual(original);
        await expect(PDFDocument.load(input, { updateMetadata: false })).resolves.toBeDefined();
    });

    it("rejects a dangling VRI reference before incoming global data can capture it", async () => {
        const input = await createExistingVriFixture({ capturedTarget: true });
        const original = input.slice();

        await expect(
            addVRIForSignature(
                input,
                { fieldName: "Timestamp" },
                {
                    validationData: {
                        certificates: [Uint8Array.of(0x30, 0x01, 0x04)],
                        crls: [],
                        ocspResponses: [],
                    },
                }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        expect(input).toEqual(original);
    });

    it("rejects a multi-category VRI update when a later registration exceeds the safe range", async () => {
        const input = await createSignaturePdfWithObjectHeaderSpoof(Number.MAX_SAFE_INTEGER - 2);
        const preserved = input.slice();

        await expect(
            addVRIForSignature(
                input,
                { fieldName: "Timestamp" },
                {
                    validationData: {
                        certificates: [Uint8Array.of(0x30, 0x01, 0x01)],
                        crls: [Uint8Array.of(0x30, 0x01, 0x02)],
                        ocspResponses: [Uint8Array.of(0x30, 0x01, 0x03)],
                    },
                }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        expect(input).toEqual(preserved);
        await expect(PDFDocument.load(input, { updateMetadata: false })).resolves.toBeDefined();
    });

    it.each([
        {
            name: "addDSS",
            update: (input: Uint8Array) =>
                addDSS(input, {
                    certificates: [Uint8Array.of(0x30, 0x01, 0x01)],
                    crls: [],
                    ocspResponses: [],
                }),
        },
        {
            name: "addVRIForSignature",
            update: (input: Uint8Array) =>
                addVRIForSignature(
                    input,
                    { fieldName: "Timestamp" },
                    {
                        validationData: {
                            certificates: [Uint8Array.of(0x30, 0x01, 0x01)],
                            crls: [],
                            ocspResponses: [],
                        },
                    }
                ),
        },
    ])(
        "uses checked classic-writer references near the safe range for $name",
        async ({ update }: { update: (input: Uint8Array) => Promise<Uint8Array> }) => {
            const input = await createSignaturePdfWithObjectHeaderSpoof(
                Number.MAX_SAFE_INTEGER - 3
            );
            const updated = await update(input);
            const appended = updated.subarray(input.length);
            const reloaded = await PDFDocument.load(updated, { updateMetadata: false });
            const appendedNumbers = indirectHeaderNumbers(appended);

            expect(updated.subarray(0, input.length)).toEqual(input);
            expect(new TextDecoder("latin1").decode(appended)).toContain("xref");
            expect(new TextDecoder("latin1").decode(appended)).not.toContain("/Type /ObjStm");
            expect(new TextDecoder("latin1").decode(appended)).not.toContain("/Type /XRef");
            expect(new Set(appendedNumbers).size).toBe(appendedNumbers.length);
            expect(
                appendedNumbers.filter((number) => number >= Number.MAX_SAFE_INTEGER - 2).sort()
            ).toEqual([Number.MAX_SAFE_INTEGER - 2, Number.MAX_SAFE_INTEGER - 1]);
            expect(reloaded.catalog.lookup(PDFName.of("DSS"))).toBeInstanceOf(PDFDict);
        }
    );

    it.each([false, true])(
        "normalizes an existing VRI entry without /Type when it is indirect=%s",
        async (indirectTargetEntry: boolean) => {
            const updated = await addVRIForSignature(
                await createExistingVriFixture({ indirectTargetEntry }),
                { fieldName: "Timestamp" },
                { validationData: { certificates: [], crls: [], ocspResponses: [] } }
            );
            const document = await PDFDocument.load(updated, { updateMetadata: false });
            const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
            const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");
            const [entryValue] = vri.values();
            const entry = requireDict(
                entryValue instanceof PDFRef ? document.context.lookup(entryValue) : entryValue,
                "VRI entry is required"
            );

            expect(entry.get(PDFName.of("Type"))).toEqual(PDFName.of("VRI"));
        }
    );

    it.each([false, true])(
        "rejects a wrong existing VRI /Type when it is indirect=%s",
        async (indirectTargetEntry: boolean) => {
            await expect(
                addVRIForSignature(
                    await createExistingVriFixture({
                        indirectTargetEntry,
                        targetEntryType: "wrong",
                    }),
                    { fieldName: "Timestamp" },
                    { validationData }
                )
            ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        }
    );

    it("preserves conforming existing VRI entries and unknown DSS keys", async () => {
        const input = await createExistingVriFixture({});
        const updated = await addVRIForSignature(
            input,
            { fieldName: "Timestamp" },
            { validationData }
        );
        const document = await PDFDocument.load(updated, { updateMetadata: false });
        const dss = requireDict(document.catalog.lookup(PDFName.of("DSS")), "DSS is required");
        const vri = requireDict(dss.lookup(PDFName.of("VRI")), "DSS /VRI is required");

        expect(updated.slice(0, input.length)).toEqual(input);
        expect(
            vri.has(
                PDFName.of(createHash("sha1").update(paddedContents).digest("hex").toUpperCase())
            )
        ).toBe(true);
        expect(dss.get(PDFName.of("VendorData"))).toEqual(PDFName.of("Preserved"));
    });

    const selectionFailures: {
        label: string;
        fields: SignatureFieldFixture[];
        fieldName: string;
    }[] = [
        {
            label: "a missing field",
            fields: [{ name: "Timestamp" }],
            fieldName: "Missing",
        },
        {
            label: "duplicate matching fields",
            fields: [{ name: "Timestamp" }, { name: "Timestamp" }],
            fieldName: "Timestamp",
        },
        {
            label: "an unsigned signature field",
            fields: [{ name: "Timestamp", signed: false }],
            fieldName: "Timestamp",
        },
        {
            label: "a non-hex Contents value",
            fields: [{ name: "Timestamp", contents: PDFString.of("not-hex") }],
            fieldName: "Timestamp",
        },
        {
            label: "a non-signature field",
            fields: [{ name: "Timestamp", fieldType: "Tx" }],
            fieldName: "Timestamp",
        },
    ];

    it.each(selectionFailures)(
        "rejects $label",
        async ({ fields, fieldName }: { fields: SignatureFieldFixture[]; fieldName: string }) => {
            const pdf = await createPdfWithFields(fields);

            await expect(
                addVRIForSignature(pdf, { fieldName }, { validationData })
            ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        }
    );
});

/* eslint-disable @typescript-eslint/no-deprecated -- compatibility coverage */
describe("deprecated addVRI compatibility", () => {
    it("rejects calls without an explicit signature field name", async () => {
        const pdf = await createPdfWithFields([{ name: "Timestamp" }]);

        await expect(addVRI(pdf, await createCertificate(), {})).rejects.toMatchObject({
            code: TimestampErrorCode.INVALID_ARGUMENT,
        });
    });

    it("delegates legacy raw validation data when a signature field name is supplied", async () => {
        const pdf = await createPdfWithFields([{ name: "Timestamp" }]);
        const updated = await addVRI(
            pdf,
            await createCertificate(),
            {
                crls: [Uint8Array.of(0x30, 0x01, 0x02)],
                ocspResponses: [Uint8Array.of(0x30, 0x01, 0x03)],
            },
            { signatureFieldName: "Timestamp" }
        );

        const document = await PDFDocument.load(updated, { updateMetadata: false });
        assertValidationBytesShareRefs(document, {
            certificates: [new Uint8Array((await createCertificate()).toSchema().toBER(false))],
            crls: [Uint8Array.of(0x30, 0x01, 0x02)],
            ocspResponses: [Uint8Array.of(0x30, 0x01, 0x03)],
        });
    });

    it("rejects SHA-256 and foreign-reference legacy options", async () => {
        const pdf = await createPdfWithFields([{ name: "Timestamp" }]);
        const certificate = await createCertificate();
        const foreignRef = await createForeignReference();

        await expect(
            addVRI(
                pdf,
                certificate,
                {},
                { signatureFieldName: "Timestamp", hashAlgorithm: "SHA-256" }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
        await expect(
            addVRI(
                pdf,
                certificate,
                {},
                { signatureFieldName: "Timestamp", dssCertRefs: [foreignRef] }
            )
        ).rejects.toMatchObject({ code: TimestampErrorCode.INVALID_ARGUMENT });
    });
});
/* eslint-enable @typescript-eslint/no-deprecated */
