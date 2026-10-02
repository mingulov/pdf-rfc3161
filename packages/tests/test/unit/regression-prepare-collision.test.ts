import { afterEach, describe, expect, it, vi } from "vitest";
import {
    PDFDict,
    PDFDocument,
    PDFName,
    PDFRawStream,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import {
    preparePdfForTimestamp,
    updateByteRange,
} from "../../../core/src/pdf/prepare.js";
import { embedTimestampToken } from "../../../core/src/pdf/embed.js";
import { restoreLargestObjectNumber } from "../../../core/src/pdf/internals.js";
import { addDSS, addVRIForSignature } from "../../../core/src/pdf/ltv.js";
import { TimestampErrorCode } from "../../../core/src/types.js";
import { timestampPdf } from "../../../core/src/index.js";
import { verifyPdfTimestamps } from "../../../core/src/pdf/extract.js";
import { PDFArray, PDFHexString } from "pdf-lib-incremental-save";
import { makeInput, stubTsaFetch } from "../utils/timestamp-fixtures.js";
import { xrefSectionFormats } from "../utils/xref-format.js";

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

function countOccurrences(haystack: string, needle: string): number {
    return haystack.split(needle).length - 1;
}

function latin1Bytes(text: string): Uint8Array {
    // TextEncoder emits UTF-8 and would expand the binary bytes of a
    // latin1-decoded PDF; PDF surgery must round-trip them exactly.
    const bytes = new Uint8Array(text.length);
    for (let index = 0; index < text.length; index += 1) {
        bytes[index] = text.charCodeAt(index) & 0xff;
    }
    return bytes;
}

function newSignatureObjectBounds(
    outputText: string,
    objectNumber: number,
    afterOffset: number
): { header: number; end: number } {
    const headerText = `${objectNumber.toString()} 0 obj`;
    const header = outputText.indexOf(headerText, afterOffset);
    if (header < 0) throw new Error("New signature object header is missing from the update");
    const end = outputText.indexOf("endobj", header);
    if (end < 0) throw new Error("New signature object is unterminated");
    return { header, end };
}

async function newSignatureValueRefNumber(preparedBytes: Uint8Array): Promise<number> {
    const document = await PDFDocument.load(preparedBytes, { updateMetadata: false });
    const acroForm = document.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
    const fields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
    const lastField = document.context.lookup(fields.get(fields.size() - 1) as PDFRef, PDFDict);
    const valueRef = lastField.get(PDFName.of("V"));
    if (!(valueRef instanceof PDFRef)) throw new Error("New signature value is not indirect");
    return valueRef.objectNumber;
}

describe("T10 R2 - ByteRange patch identity", () => {
    const replacement: [number, number, number, number] = [0, 1, 2, 3];
    const placeholder = "/ByteRange[0 111111111111 111111111111 111111111111]";

    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it("throws PDF_ERROR instead of rewriting the first file-wide ByteRange on a hint miss", () => {
        const prefix = "0".repeat(200);
        const text = `${prefix}/ByteRange[1 2 3 4]${"0".repeat(200)}`;
        const bytes = new TextEncoder().encode(text);
        const hint = prefix.length + "/ByteRange[1 2 3 4]".length + 50;

        expect(() => updateByteRange(bytes, replacement, hint)).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
        expect(new TextDecoder("latin1").decode(bytes)).toContain("/ByteRange[1 2 3 4]");
    });

    it("ignores a ByteRange candidate before the hint and patches the placeholder after it", () => {
        const decoy = "/ByteRange[9 9 9 9]";
        const prefix = "0".repeat(20);
        const padding = "0".repeat(100 - prefix.length - decoy.length);
        const gap = "0".repeat(10);
        const text = `${prefix}${decoy}${padding}${gap}${placeholder}`;
        const hint = 100 + gap.length;
        const bytes = new TextEncoder().encode(text);

        const updated = new TextDecoder("latin1").decode(updateByteRange(bytes, replacement, hint));

        expect(updated.slice(prefix.length, prefix.length + decoy.length)).toBe(decoy);
        expect(updated).toContain("/ByteRange[0 1 2 3]");
        expect(updated.indexOf("/ByteRange[0 1 2 3]")).toBe(hint);
    });

    it("patches the placeholder at the hint when it is the only candidate", () => {
        const text = `${"0".repeat(50)}${placeholder}`;
        const bytes = new TextEncoder().encode(text);

        const updated = new TextDecoder("latin1").decode(updateByteRange(bytes, replacement, 50));

        expect(updated.slice(0, 50)).toBe("0".repeat(50));
        expect(updated.indexOf("/ByteRange[0 1 2 3]")).toBe(50);
    });

    it("patches only the new signature object with adversarial ByteRange text present", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        document.addPage([100, 100]);
        document.catalog.set(
            PDFName.of("Note"),
            PDFString.of("unrelated /ByteRange[8 8 8 8] text in a literal string")
        );
        const base = await document.save({ useObjectStreams: false });
        const withEarlier = (await preparePdfForTimestamp(base)).bytes;
        const withEarlierText = new TextDecoder("latin1").decode(withEarlier);
        const eofAt = withEarlierText.lastIndexOf("%%EOF");
        if (eofAt < 0) throw new Error("Prepared PDF is missing its end-of-file marker");
        const input = latin1Bytes(
            `${withEarlierText.slice(0, eofAt)}% unrelated /ByteRange[9 9 9 9] comment\n${withEarlierText.slice(eofAt)}`
        );
        await expect(PDFDocument.load(input, { updateMetadata: false })).resolves.toBeDefined();

        const prepared = await preparePdfForTimestamp(input);
        const inputText = new TextDecoder("latin1").decode(input);
        const outputText = new TextDecoder("latin1").decode(prepared.bytes);

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        expect(countOccurrences(outputText, "/ByteRange")).toBe(
            countOccurrences(inputText, "/ByteRange") + 1
        );
        const [offset1, length1, offset2, length2] = prepared.byteRange;
        const patchedText = `/ByteRange[${offset1.toString()} ${length1.toString()} ${offset2.toString()} ${length2.toString()}]`;
        const patchedAt = outputText.lastIndexOf("/ByteRange");
        expect(patchedAt).toBeGreaterThanOrEqual(input.length);
        expect(outputText.slice(patchedAt, patchedAt + patchedText.length)).toBe(patchedText);
        const valueNumber = await newSignatureValueRefNumber(prepared.bytes);
        const bounds = newSignatureObjectBounds(outputText, valueNumber, input.length);
        expect(patchedAt).toBeGreaterThan(bounds.header);
        expect(patchedAt).toBeLessThan(bounds.end);
        expect(outputText.slice(bounds.header, bounds.end)).toMatch(/\/Contents\s{1,4}</);
        await expect(
            PDFDocument.load(prepared.bytes, { updateMetadata: false })
        ).resolves.toBeDefined();
    });

    it("keeps the ByteRange offset ahead of Contents regardless of reservation size (R2 needs-fixture)", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = await document.save({ useObjectStreams: false });

        const small = await preparePdfForTimestamp(input, { signatureSize: 1024 });
        const large = await preparePdfForTimestamp(input, { signatureSize: 65536 });

        for (const prepared of [small, large]) {
            expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
            const outputText = new TextDecoder("latin1").decode(prepared.bytes);
            const valueNumber = await newSignatureValueRefNumber(prepared.bytes);
            const bounds = newSignatureObjectBounds(outputText, valueNumber, input.length);
            const body = outputText.slice(bounds.header, bounds.end);
            const byteRangeAt = body.indexOf("/ByteRange");
            const contentsAt = body.indexOf("/Contents");
            expect(byteRangeAt).toBeGreaterThanOrEqual(0);
            expect(contentsAt).toBeGreaterThan(byteRangeAt);
        }
        const smallText = new TextDecoder("latin1").decode(small.bytes);
        const largeText = new TextDecoder("latin1").decode(large.bytes);
        const smallValue = await newSignatureValueRefNumber(small.bytes);
        const largeValue = await newSignatureValueRefNumber(large.bytes);
        const smallBounds = newSignatureObjectBounds(smallText, smallValue, input.length);
        const largeBounds = newSignatureObjectBounds(largeText, largeValue, input.length);
        expect(smallText.indexOf("/ByteRange", smallBounds.header) - smallBounds.header).toBe(
            largeText.indexOf("/ByteRange", largeBounds.header) - largeBounds.header
        );
    });

    it.each([true, false])(
        "emits a frozen raw signature object on multi-page %s xref input (C02)",
        async (useObjectStreams: boolean) => {
            const input = await makeInput(useObjectStreams);
            const prepared = await preparePdfForTimestamp(input);
            const outputText = new TextDecoder("latin1").decode(prepared.bytes);

            expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
            const valueNumber = await newSignatureValueRefNumber(prepared.bytes);
            const bounds = newSignatureObjectBounds(outputText, valueNumber, input.length);
            const body = outputText.slice(bounds.header, bounds.end);
            expect(body).toContain("/Type /DocTimeStamp");
            expect(body).toContain("/SubFilter /ETSI.RFC3161");
            expect(body).toMatch(/\/Contents\s{1,4}</);
            expect(body).toMatch(/\/ByteRange\[0 \d{1,20} \d{1,20} \d{1,20}\]/);

            const document = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
            const acroForm = document.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
            const fields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
            const lastField = document.context.lookup(
                fields.get(fields.size() - 1) as PDFRef,
                PDFDict
            );
            const valueRef = lastField.get(PDFName.of("V"));
            if (!(valueRef instanceof PDFRef)) throw new Error("New signature value is not indirect");
            const value = document.context.lookup(valueRef, PDFDict);
            expect(value.get(PDFName.of("SubFilter"))?.toString()).toBe("/ETSI.RFC3161");
            const contents = value.get(PDFName.of("Contents"));
            expect(contents).toBeInstanceOf(PDFHexString);
            const byteRange = value.get(PDFName.of("ByteRange"));
            expect(byteRange).toBeInstanceOf(PDFArray);
            expect((byteRange as PDFArray).size()).toBe(4);

            const inputFormats = xrefSectionFormats(input);
            const outputFormats = xrefSectionFormats(prepared.bytes);
            expect(outputFormats.slice(0, inputFormats.length)).toEqual(inputFormats);
            expect(outputFormats[outputFormats.length - 1]).toBe(
                inputFormats[inputFormats.length - 1]
            );
        }
    );

    it("rejects a crafted signature field name that mimics the Contents placeholder (R2)", async () => {
        const document = await PDFDocument.create();
        document.addPage();
        document.catalog.set(
            PDFName.of("Padding"),
            document.context.register(
                document.context.stream(new TextEncoder().encode("padding".repeat(1700)))
            )
        );
        const first = await preparePdfForTimestamp(
            await document.save({ useObjectStreams: false })
        );

        await expect(
            preparePdfForTimestamp(first.bytes, {
                signatureSize: 4096,
                signatureFieldName: ">> /Contents <" + "0".repeat(8192) + ">",
            })
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("rejects a second crafted field-name shape with the decoy placed after prose (R2)", async () => {
        const document = await PDFDocument.create();
        document.addPage();
        document.catalog.set(
            PDFName.of("Padding"),
            document.context.register(
                document.context.stream(new TextEncoder().encode("padding".repeat(1700)))
            )
        );
        const first = await preparePdfForTimestamp(
            await document.save({ useObjectStreams: false })
        );

        await expect(
            preparePdfForTimestamp(first.bytes, {
                signatureSize: 4096,
                signatureFieldName: "Report >> section /Contents <" + "0".repeat(8192) + ">",
            })
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
    });

    it("rejects a timestampPdf whose field name mimics the placeholder while the first still verifies (R2)", async () => {
        stubTsaFetch();
        const document = await PDFDocument.create();
        document.addPage();
        document.catalog.set(
            PDFName.of("Padding"),
            document.context.register(
                document.context.stream(new TextEncoder().encode("padding".repeat(1700)))
            )
        );
        const first = await timestampPdf({
            pdf: await document.save({ useObjectStreams: false }),
            tsa: { url: "https://tsa.example.test" },
        });

        await expect(
            timestampPdf({
                pdf: first.pdf,
                tsa: { url: "https://tsa.example.test" },
                signatureSize: 4096,
                signatureFieldName: ">> /Contents <" + "0".repeat(8192) + ">",
            })
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });

        const verified = await verifyPdfTimestamps(first.pdf);
        expect(verified.map((value) => value.verified)).toEqual([true]);
    });
});
