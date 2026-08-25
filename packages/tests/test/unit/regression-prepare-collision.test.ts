import { describe, expect, it } from "vitest";
import {
    PDFDict,
    PDFDocument,
    PDFName,
    PDFRawStream,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { embedTimestampToken } from "../../../core/src/pdf/embed.js";
import { restoreLargestObjectNumber } from "../../../core/src/pdf/internals.js";
import { addDSS, addVRIForSignature } from "../../../core/src/pdf/ltv.js";
import { TimestampErrorCode } from "../../../core/src/types.js";

type SpoofLocation = "literal" | "stream";

function objectHeaderNumbers(bytes: Uint8Array): number[] {
    const text = new TextDecoder("latin1").decode(bytes);
    return [...text.matchAll(/(\d{1,20})\s{1,100}\d{1,20}\s{1,100}obj\b/g)].map((match) =>
        Number.parseInt(match[1] ?? "", 10)
    );
}

async function createObjectHeaderSpoofPdf(
    location: SpoofLocation,
    objectHeader: string
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);

    if (location === "literal") {
        document.catalog.set(PDFName.of("Spoof"), PDFString.of(` ${objectHeader} `));
    } else {
        const contents = new TextEncoder().encode(` ${objectHeader} `);
        const stream = PDFRawStream.of(
            document.context.obj({ Length: contents.length }),
            contents
        );
        document.catalog.set(PDFName.of("Spoof"), document.context.register(stream));
    }

    return document.save({ useObjectStreams: false });
}

function appendPhysicalObjectStream(input: Uint8Array, header: string): Uint8Array {
    const contents = "5 0 <<>>";
    const object = new TextEncoder().encode(
        `\n${header}\n<< /Type /ObjStm /N 1 /First 4 /Length ${contents.length.toString()} >>\nstream\n${contents}\nendstream\nendobj\n`
    );
    const result = new Uint8Array(input.length + object.length);
    result.set(input, 0);
    result.set(object, input.length);
    return result;
}

function appendPhysicalXrefStream(input: Uint8Array, header: string): Uint8Array {
    const object = new TextEncoder().encode(
        `\n${header}\n<< /Type /XRef /Size 0 /W [0 0 0] /Root 1 0 R /Length 0 >>\nstream\n\nendstream\nendobj\n`
    );
    const result = new Uint8Array(input.length + object.length);
    result.set(input, 0);
    result.set(object, input.length);
    return result;
}

function expectNoDuplicateNewReferences(
    bytes: Uint8Array,
    previousLength: number,
    minimumObjectNumber: number
): number[] {
    const added = objectHeaderNumbers(bytes.subarray(previousLength)).filter(
        (objectNumber) => objectNumber > minimumObjectNumber
    );
    expect(added.length).toBeGreaterThan(0);
    expect(new Set(added).size).toBe(added.length);
    return added;
}

async function expectReloadableDssAndVri(bytes: Uint8Array): Promise<void> {
    const document = await PDFDocument.load(bytes, { updateMetadata: false });
    const dss = document.catalog.lookup(PDFName.of("DSS"));
    expect(dss).toBeInstanceOf(PDFDict);
    if (!(dss instanceof PDFDict)) {
        throw new Error("DSS must be a PDF dictionary");
    }
    expect(dss.lookup(PDFName.of("VRI"))).toBeInstanceOf(PDFDict);
}

describe("Regression Tests - Prepare PDF Object Collision", () => {
    it("preserves a classic PDF prefix and creates a reloadable timestamp placeholder", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = await document.save({ useObjectStreams: false });

        const prepared = await preparePdfForTimestamp(input);

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        await expect(PDFDocument.load(prepared.bytes, { updateMetadata: false })).resolves.toBeDefined();
    });

    it("preserves an object-stream PDF prefix and embeds a reloadable timestamp", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = await document.save({ useObjectStreams: true });

        const prepared = await preparePdfForTimestamp(input);
        const embedded = embedTimestampToken(prepared, Uint8Array.of(1, 2, 3));

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        await expect(PDFDocument.load(embedded, { updateMetadata: false })).resolves.toBeDefined();
    });

    it("preserves every multi-increment prefix while reloading DSS and signature VRI", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = await document.save({ useObjectStreams: true });
        const prepared = await preparePdfForTimestamp(input);
        const withVri = await addVRIForSignature(
            prepared.bytes,
            { fieldName: "Timestamp" },
            {
                validationData: {
                    certificates: [Uint8Array.of(0x30, 0x01)],
                    crls: [],
                    ocspResponses: [],
                },
            }
        );
        const withDss = await addDSS(withVri, {
            certificates: [Uint8Array.of(0x30, 0x02)],
            crls: [],
            ocspResponses: [],
        });

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        expect(withVri.subarray(0, prepared.bytes.length)).toEqual(prepared.bytes);
        expect(withDss.subarray(0, withVri.length)).toEqual(withVri);
        await expectReloadableDssAndVri(withDss);
    });

    it.each(["literal", "stream"] as const)(
        "rejects a 20-digit unsafe object-header spoof in a %s before mutation output",
        async (location: SpoofLocation) => {
            const input = await createObjectHeaderSpoofPdf(location, "99999999999999999999 0 obj");

            await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
                code: TimestampErrorCode.PDF_ERROR,
            });
            await expect(
                addDSS(input, {
                    certificates: [Uint8Array.of(0x30, 0x01)],
                    crls: [],
                    ocspResponses: [],
                })
            ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        }
    );

    it.each(["literal", "stream"] as const)(
        "allocates safely above a safe object-header spoof in a %s without corrupting DSS",
        async (location: SpoofLocation) => {
            const input = await createObjectHeaderSpoofPdf(location, "999999 0 obj");
            const prepared = await preparePdfForTimestamp(input);
            const preparedReferences = expectNoDuplicateNewReferences(
                prepared.bytes,
                input.length,
                999999
            );
            const updated = await addDSS(prepared.bytes, {
                certificates: [Uint8Array.of(0x30, 0x03)],
                crls: [],
                ocspResponses: [],
            });
            const dssReferences = expectNoDuplicateNewReferences(
                updated,
                prepared.bytes.length,
                999999
            );

            expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
            expect(updated.subarray(0, prepared.bytes.length)).toEqual(prepared.bytes);
            expect(Math.min(...dssReferences)).toBeGreaterThan(Math.max(...preparedReferences));
            const reloaded = await PDFDocument.load(updated, { updateMetadata: false });
            expect(reloaded.catalog.lookup(PDFName.of("DSS"))).toBeInstanceOf(PDFDict);
        }
    );

    it("does not reuse an ObjStm container the official loader finds after a loose prefix", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = appendPhysicalObjectStream(
            await document.save({ useObjectStreams: false }),
            "abc10 0 obj"
        );
        const loaded = await PDFDocument.load(input, { updateMetadata: false });
        const loadedReferences = loaded.context
            .enumerateIndirectObjects()
            .map(([ref]) => ref.objectNumber);

        expect(loadedReferences).toContain(5);
        expect(loadedReferences).not.toContain(10);

        const prepared = await preparePdfForTimestamp(input);
        const appendedReferences = objectHeaderNumbers(prepared.bytes.subarray(input.length));

        expect(appendedReferences).not.toContain(10);
        expect(appendedReferences.some((objectNumber) => objectNumber > 10)).toBe(true);
    });

    it("does not reuse an ObjStm container with a zero-length generation separator", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = appendPhysicalObjectStream(
            await document.save({ useObjectStreams: false }),
            "6 0obj"
        );
        const loaded = await PDFDocument.load(input, { updateMetadata: false });
        const loadedReferences = loaded.context
            .enumerateIndirectObjects()
            .map(([ref]) => ref.objectNumber);

        expect(loadedReferences).toContain(5);
        expect(loadedReferences).not.toContain(6);

        const prepared = await preparePdfForTimestamp(input);
        const appendedReferences = objectHeaderNumbers(prepared.bytes.subarray(input.length));

        expect(appendedReferences).not.toContain(6);
        expect(appendedReferences.some((objectNumber) => objectNumber > 6)).toBe(true);
    });

    it("does not reuse an XRef container with a zero-length generation separator", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = appendPhysicalXrefStream(
            await document.save({ useObjectStreams: false }),
            "5 0obj"
        );
        const loaded = await PDFDocument.load(input, { updateMetadata: false });
        const loadedReferences = loaded.context
            .enumerateIndirectObjects()
            .map(([ref]) => ref.objectNumber);

        expect(loadedReferences).not.toContain(5);

        const updated = await addDSS(input, {
            certificates: [Uint8Array.of(0x30, 0x01)],
            crls: [],
            ocspResponses: [],
        });
        const appendedReferences = objectHeaderNumbers(updated.subarray(input.length));

        expect(appendedReferences).not.toContain(5);
        expect(appendedReferences.some((objectNumber) => objectNumber > 5)).toBe(true);
        const reloaded = await PDFDocument.load(updated, { updateMetadata: false });
        expect(reloaded.catalog.lookup(PDFName.of("DSS"))).toBeInstanceOf(PDFDict);
    });

    it("fails closed for a loader-visible ObjStm header with an overlong separator", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = appendPhysicalObjectStream(
            await document.save({ useObjectStreams: false }),
            `10${" ".repeat(101)}0 obj`
        );
        const loaded = await PDFDocument.load(input, { updateMetadata: false });
        const loadedReferences = loaded.context
            .enumerateIndirectObjects()
            .map(([ref]) => ref.objectNumber);

        expect(loadedReferences).toContain(5);
        expect(loadedReferences).not.toContain(10);

        await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
    });

    it("recognizes comments as loose official-loader header separators", () => {
        const context = {
            largestObjectNumber: 1,
            enumerateIndirectObjects: (): [PDFRef, unknown][] => [],
        };

        restoreLargestObjectNumber(new TextEncoder().encode("abc5% comment\n0 obj"), context);

        expect(context.largestObjectNumber).toBe(5);
    });

    it("fails closed when a valid stream exhausts the loose-header scan work budget", async () => {
        const input = await createObjectHeaderSpoofPdf("stream", "1 %".repeat(1000));

        await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
    });

    it("rejects unsafe dependency references before registration can lose number precision", () => {
        const context = {
            largestObjectNumber: 1,
            enumerateIndirectObjects: (): [PDFRef, unknown][] => [
                [PDFRef.of(Number.MAX_SAFE_INTEGER), undefined],
            ],
        };

        expect(() => restoreLargestObjectNumber(new Uint8Array(), context)).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });
});
