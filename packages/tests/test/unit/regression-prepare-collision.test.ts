import { afterEach, describe, expect, it, vi } from "vitest";
import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { deflateSync } from "node:zlib";
import pako from "pako";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFName,
    type PDFObject,
    PDFRawStream,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { embedTimestampToken } from "../../../core/src/pdf/embed.js";
import {
    preflightPdfXref,
    restoreLargestObjectNumber,
} from "../../../core/src/pdf/internals.js";
import { addDSS } from "../../../core/src/pdf/ltv.js";
import { TimestampErrorCode } from "../../../core/src/types.js";

const spoofedObjectText = "99999999999999999999 0 obj\n999999 0 obj";

async function createSpoofedObjectTextPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const streamBytes = new TextEncoder().encode(spoofedObjectText);
    const stream = PDFRawStream.of(context.obj({ Length: streamBytes.length }), streamBytes);

    document.catalog.set(PDFName.of("SpoofLiteral"), PDFString.of(spoofedObjectText));
    document.catalog.set(PDFName.of("SpoofStream"), context.register(stream));
    return document.save({ useObjectStreams: false });
}

function objectNumbers(document: PDFDocument): number[] {
    return document.context.enumerateIndirectObjects().map(([ref]) => ref.objectNumber);
}

function asText(bytes: Uint8Array): string {
    return new TextDecoder("latin1").decode(bytes);
}

function asBytes(text: string): Uint8Array {
    return Uint8Array.from(text, (character) => character.charCodeAt(0));
}

function indirectHeaderNumbers(bytes: Uint8Array): number[] {
    return [...asText(bytes).matchAll(/(\d+)\s+\d+\s+obj\b/g)].map((match) =>
        Number.parseInt(match[1] ?? "", 10)
    );
}

function finalStartXrefOffset(text: string): number {
    const marker = text.lastIndexOf("startxref");
    if (marker < 0) {
        throw new Error("fixture must contain startxref");
    }
    return marker;
}

function replaceFinalStartXref(text: string, offset: number): string {
    const marker = finalStartXrefOffset(text);
    const before = text.slice(0, marker + "startxref".length);
    const after = text.slice(marker + "startxref".length);
    const suffix = after.indexOf("%%EOF");
    if (suffix < 0) {
        throw new Error("fixture must contain %%EOF after startxref");
    }
    return `${before}\n${offset.toString()}\n${after.slice(suffix)}`;
}

function replaceFinalXrefDictionaryValue(text: string, key: string, value: string): string {
    const trailer = text.lastIndexOf("trailer");
    const stream = text.lastIndexOf("/Type /XRef");
    const valueStart =
        stream > trailer ? text.lastIndexOf(`/${key} `, stream) : text.lastIndexOf(`/${key} `);
    if (valueStart < 0) {
        throw new Error(`fixture must contain /${key}`);
    }
    const numberStart = valueStart + key.length + 2;
    const numberEnd = text.indexOf("\n", numberStart);
    if (numberEnd < 0) {
        throw new Error(`fixture must terminate /${key}`);
    }
    return `${text.slice(0, numberStart)}${value}${text.slice(numberEnd)}`;
}

function replaceLastAsciiBytes(bytes: Uint8Array, source: string, replacement: string): Uint8Array {
    const sourceBytes = new TextEncoder().encode(source);
    const replacementBytes = new TextEncoder().encode(replacement);
    let match = -1;
    for (let start = 0; start <= bytes.length - sourceBytes.length; start++) {
        let found = true;
        for (let index = 0; index < sourceBytes.length; index++) {
            if (bytes[start + index] !== sourceBytes[index]) {
                found = false;
                break;
            }
        }
        if (found) {
            match = start;
        }
    }
    if (match < 0) {
        throw new Error(`fixture must contain ${source}`);
    }
    const result = new Uint8Array(bytes.length - sourceBytes.length + replacementBytes.length);
    result.set(bytes.subarray(0, match), 0);
    result.set(replacementBytes, match);
    result.set(bytes.subarray(match + sourceBytes.length), match + replacementBytes.length);
    return result;
}

function replaceLastAsciiNumber(bytes: Uint8Array, key: string, replacement: string): Uint8Array {
    const keyBytes = new TextEncoder().encode(key);
    let keyOffset = -1;
    for (let start = 0; start <= bytes.length - keyBytes.length; start++) {
        if (keyBytes.every((byte, index) => bytes[start + index] === byte)) {
            keyOffset = start;
        }
    }
    if (keyOffset < 0) {
        throw new Error(`fixture must contain ${key}`);
    }
    let numberEnd = keyOffset + keyBytes.length;
    let byte = bytes[numberEnd];
    while (byte !== undefined && byte >= 0x30 && byte <= 0x39) {
        numberEnd++;
        byte = bytes[numberEnd];
    }
    const source = String.fromCharCode(...bytes.subarray(keyOffset, numberEnd));
    return replaceLastAsciiBytes(bytes, source, `${key}${replacement}`);
}

function appendClassicXrefInsideRawStream(text: string): string {
    const streamPrefix = "\n5 0 obj\n<< /Length ";
    const streamSuffix = "\nendstream\nendobj\n";
    const fakeXrefPrefix = "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 6 /Root 2 0 R >>\n";
    let payload = fakeXrefPrefix;
    let offset = 0;

    for (let attempt = 0; attempt < 3; attempt++) {
        const objectHeader = `${streamPrefix}${new TextEncoder().encode(payload).length.toString()} >>\nstream\n`;
        offset = new TextEncoder().encode(text + objectHeader).length;
        payload = `${fakeXrefPrefix}startxref\n${offset.toString()}\n%%EOF\n`;
    }

    const objectHeader = `${streamPrefix}${new TextEncoder().encode(payload).length.toString()} >>\nstream\n`;
    return `${text}${objectHeader}${payload}${streamSuffix}startxref\n${offset.toString()}\n%%EOF`;
}

function asciiBytes(value: string): Uint8Array {
    return new TextEncoder().encode(value);
}

function concatenateBytes(parts: Uint8Array[]): Uint8Array {
    const result = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        result.set(part, offset);
        offset += part.length;
    }
    return result;
}

function writeBigEndian(value: number, width: number): Uint8Array {
    const bytes = new Uint8Array(width);
    let remaining = value;
    for (let index = width - 1; index >= 0; index--) {
        bytes[index] = remaining % 256;
        remaining = Math.floor(remaining / 256);
    }
    return bytes;
}

interface XrefStreamFixtureOptions {
    index: number[];
    widths?: [number, number, number];
    count?: number;
    compressed?: boolean;
    eol?: "\n" | "\r";
    decodeParms?: "null" | "predictor";
    decodedPadding?: number;
}

function createXrefStreamFixture(options: XrefStreamFixtureOptions): Uint8Array {
    const widths = options.widths ?? [1, 4, 2];
    const count =
        options.count ??
        options.index.reduce((total, value, index) => {
            return index % 2 === 1 ? total + value : total;
        }, 0);
    const header = asciiBytes("%PDF-1.5\n");
    const catalog = asciiBytes("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    const pages = asciiBytes("2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    const prefix = concatenateBytes([header, catalog, pages]);
    const xrefOffset = prefix.length;
    const catalogOffset = header.length;
    const pagesOffset = header.length + catalog.length;
    const entryWidth = widths[0] + widths[1] + widths[2];
    const decoded = new Uint8Array(count * entryWidth + (options.decodedPadding ?? 0));
    let cursor = 0;
    for (let range = 0; range < options.index.length; range += 2) {
        const first = options.index[range] ?? 0;
        const rangeCount = options.index[range + 1] ?? 0;
        for (let index = 0; index < rangeCount; index++) {
            const objectNumber = first + index;
            const type = objectNumber >= 1 && objectNumber <= 3 ? 1 : 0;
            const fieldTwo =
                objectNumber === 1 ? catalogOffset : objectNumber === 2 ? pagesOffset : xrefOffset;
            if (widths[0] > 0) {
                decoded.set(writeBigEndian(type, widths[0]), cursor);
            }
            cursor += widths[0];
            if (widths[1] > 0) {
                decoded.set(writeBigEndian(type === 1 ? fieldTwo : 0, widths[1]), cursor);
            }
            cursor += widths[1];
            if (widths[2] > 0) {
                decoded.set(writeBigEndian(objectNumber === 0 ? 65535 : 0, widths[2]), cursor);
            }
            cursor += widths[2];
        }
    }
    const streamBytes = options.compressed ? Uint8Array.from(deflateSync(decoded)) : decoded;
    const eol = options.eol ?? "\n";
    const dictionary = asciiBytes(
        `3 0 obj\n<< /Type /XRef /Size ${Math.max(...options.index.filter((_, index) => index % 2 === 0).map((first, index) => first + (options.index[index * 2 + 1] ?? 0)), 4).toString()} /Root 1 0 R /W [ ${widths.join(" ")} ] /Index [ ${options.index.join(" ")} ]${options.compressed ? " /Filter /FlateDecode" : ""}${options.decodeParms === "null" ? " /DecodeParms null" : options.decodeParms === "predictor" ? " /DecodeParms << /Predictor 12 >>" : ""} /Length ${streamBytes.length.toString()} >>\nstream${eol}`
    );
    const suffix = asciiBytes(
        `${eol}endstream\nendobj\nstartxref\n${xrefOffset.toString()}\n%%EOF\n`
    );
    return concatenateBytes([prefix, dictionary, streamBytes, suffix]);
}

function xrefFixtureContext(offset: number) {
    return {
        largestObjectNumber: 3,
        enumerateIndirectObjects: () =>
            [
                [{ objectNumber: 1 }, undefined],
                [{ objectNumber: 2 }, undefined],
                [{ objectNumber: 3 }, undefined],
            ] as [{ objectNumber: number }, unknown][],
        lookup: () => undefined,
        pdfFileDetails: { prevStartXRef: offset },
    };
}

function createObjectStreamXrefFixture(options: {
    objectStreamType?: "ObjStm" | "XRef";
    compressedObjectNumber?: number;
    compressedObjectIndex?: number;
    objectStreamMemberOffset?: number;
    compressedObjectStream?: boolean;
    objectStreamDecodedPadding?: number;
}): Uint8Array {
    const header = asciiBytes("%PDF-1.5\n");
    const catalog = asciiBytes("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    const pages = asciiBytes("2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    const objectStreamContents = concatenateBytes([
        asciiBytes(
            `${(options.compressedObjectNumber ?? 4).toString()} ${(options.objectStreamMemberOffset ?? 0).toString()} << /Value 1 >>`
        ),
        new Uint8Array(options.objectStreamDecodedPadding ?? 0),
    ]);
    const objectStreamBytes = options.compressedObjectStream
        ? Uint8Array.from(deflateSync(objectStreamContents))
        : objectStreamContents;
    const objectStreamOffset = header.length + catalog.length + pages.length;
    const objectStream = asciiBytes(
        `3 0 obj\n<< /Type /${options.objectStreamType ?? "ObjStm"} /N 1 /First 4${options.compressedObjectStream ? " /Filter /FlateDecode" : ""} /Length ${objectStreamBytes.length.toString()} >>\nstream\n`
    );
    const xrefOffset = objectStreamOffset + objectStream.length + objectStreamBytes.length + 18;
    const records = concatenateBytes([
        writeBigEndian(0, 1),
        writeBigEndian(0, 4),
        writeBigEndian(65535, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length, 4),
        writeBigEndian(0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length + catalog.length, 4),
        writeBigEndian(0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(objectStreamOffset, 4),
        writeBigEndian(0, 2),
        writeBigEndian(2, 1),
        writeBigEndian(3, 4),
        writeBigEndian(options.compressedObjectIndex ?? 0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(xrefOffset, 4),
        writeBigEndian(0, 2),
    ]);
    const xref = asciiBytes(
        `5 0 obj\n<< /Type /XRef /Size 6 /Root 1 0 R /W [ 1 4 2 ] /Index [ 0 6 ] /Length ${records.length.toString()} >>\nstream\n`
    );
    const suffix = asciiBytes(
        "\nendstream\nendobj\nstartxref\n" + xrefOffset.toString() + "\n%%EOF\n"
    );
    return concatenateBytes([
        header,
        catalog,
        pages,
        objectStream,
        objectStreamBytes,
        asciiBytes("\nendstream\nendobj\n"),
        xref,
        records,
        suffix,
    ]);
}

function createManyObjectStreamXrefFixture(compressedEntryCount: number): Uint8Array {
    const header = asciiBytes("%PDF-1.5\n");
    const catalog = asciiBytes("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    const pages = asciiBytes("2 0 obj\n<< /Type /Pages /Count 0 /Kids [] >>\nendobj\n");
    const objectBodies = Array.from(
        { length: compressedEntryCount },
        (_, index) => `<< /Value ${(index + 4).toString()} >>`
    );
    let bodyOffset = 0;
    const headerPairs = objectBodies.map((body, index) => {
        const pair = `${(index + 4).toString()} ${bodyOffset.toString()}`;
        bodyOffset += asciiBytes(body).length;
        return pair;
    });
    const objectStreamContents = asciiBytes(`${headerPairs.join(" ")} ${objectBodies.join("")}`);
    const first = asciiBytes(`${headerPairs.join(" ")} `).length;
    const compressedContents = Uint8Array.from(deflateSync(objectStreamContents));
    const objectStreamOffset = header.length + catalog.length + pages.length;
    const objectStream = asciiBytes(
        `3 0 obj\n<< /Type /ObjStm /N ${compressedEntryCount.toString()} /First ${first.toString()} /Filter /FlateDecode /Length ${compressedContents.length.toString()} >>\nstream\n`
    );
    const xrefOffset = objectStreamOffset + objectStream.length + compressedContents.length + 18;
    const records: Uint8Array[] = [
        writeBigEndian(0, 1),
        writeBigEndian(0, 4),
        writeBigEndian(65535, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length, 4),
        writeBigEndian(0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length + catalog.length, 4),
        writeBigEndian(0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(objectStreamOffset, 4),
        writeBigEndian(0, 2),
    ];
    for (let index = 0; index < compressedEntryCount; index++) {
        records.push(
            writeBigEndian(2, 1),
            writeBigEndian(3, 4),
            writeBigEndian(index, 2)
        );
    }
    const xrefObjectNumber = compressedEntryCount + 4;
    records.push(
        writeBigEndian(1, 1),
        writeBigEndian(xrefOffset, 4),
        writeBigEndian(0, 2)
    );
    const xrefRecords = concatenateBytes(records);
    const xref = asciiBytes(
        `${xrefObjectNumber.toString()} 0 obj\n<< /Type /XRef /Size ${(xrefObjectNumber + 1).toString()} /Root 1 0 R /W [ 1 4 2 ] /Index [ 0 ${(xrefObjectNumber + 1).toString()} ] /Length ${xrefRecords.length.toString()} >>\nstream\n`
    );
    const suffix = asciiBytes(
        `\nendstream\nendobj\nstartxref\n${xrefOffset.toString()}\n%%EOF\n`
    );
    return concatenateBytes([
        header,
        catalog,
        pages,
        objectStream,
        compressedContents,
        asciiBytes("\nendstream\nendobj\n"),
        xref,
        xrefRecords,
        suffix,
    ]);
}

function createNormativeHybridFixture(options: {
    supplementalOmitsSelf?: boolean;
    classicSelfEntry?: "matching" | "missing" | "wrong-generation" | "wrong-offset";
} = {}): Uint8Array {
    const header = asciiBytes("%PDF-1.5\n");
    const catalog = asciiBytes("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n");
    const pages = asciiBytes("2 0 obj\n<< /Type /Pages /Count 1 /Kids [3 0 R] >>\nendobj\n");
    const page = asciiBytes(
        "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] >>\nendobj\n"
    );
    const hybridOffset = header.length + catalog.length + pages.length + page.length;
    const records = concatenateBytes([
        writeBigEndian(0, 1),
        writeBigEndian(0, 4),
        writeBigEndian(65535, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length, 4),
        writeBigEndian(0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length + catalog.length, 4),
        writeBigEndian(0, 2),
        writeBigEndian(1, 1),
        writeBigEndian(header.length + catalog.length + pages.length, 4),
        writeBigEndian(0, 2),
        ...(options.supplementalOmitsSelf
            ? []
            : [writeBigEndian(1, 1), writeBigEndian(hybridOffset, 4), writeBigEndian(0, 2)]),
    ]);
    const index = options.supplementalOmitsSelf ? "0 4" : "0 5";
    const hybrid = asciiBytes(
        `4 0 obj\n<< /Type /XRef /Size 5 /Root 1 0 R /W [ 1 4 2 ] /Index [ ${index} ] /Length ${records.length.toString()} >>\nstream\n`
    );
    const hybridSuffix = asciiBytes("\nendstream\nendobj\n");
    const classicOffset = hybridOffset + hybrid.length + records.length + hybridSuffix.length;
    const classicSelfEntry =
        options.classicSelfEntry === "missing"
            ? "0000000000 00000 f "
            : options.classicSelfEntry === "wrong-generation"
              ? `${hybridOffset.toString().padStart(10, "0")} 00001 n `
              : options.classicSelfEntry === "wrong-offset"
                ? "0000000000 00000 n "
                : `${hybridOffset.toString().padStart(10, "0")} 00000 n `;
    const classic = asciiBytes(
        `xref\n0 5\n0000000000 65535 f \n${header.length.toString().padStart(10, "0")} 00000 n \n${(header.length + catalog.length).toString().padStart(10, "0")} 00000 n \n${(header.length + catalog.length + pages.length).toString().padStart(10, "0")} 00000 n \n${classicSelfEntry}\ntrailer\n<< /Size 5 /Root 1 0 R /XRefStm ${hybridOffset.toString()} >>\nstartxref\n${classicOffset.toString()}\n%%EOF\n`
    );
    return concatenateBytes([header, catalog, pages, page, hybrid, records, hybridSuffix, classic]);
}

function appendStaleObjectStreamContainerRevision(input: Uint8Array): Uint8Array {
    const previous = asText(input).lastIndexOf("5 0 obj");
    const replacement = "3 0 obj\n<< /Type /XRef >>\nendobj\n";
    const xrefOffset = input.length + asciiBytes(replacement).length;
    const revision = asciiBytes(
        `${replacement}xref\n3 1\n${input.length.toString().padStart(10, "0")} 00000 n \ntrailer\n<< /Size 6 /Root 1 0 R /Prev ${previous.toString()} >>\nstartxref\n${xrefOffset.toString()}\n%%EOF\n`
    );
    return concatenateBytes([input, revision]);
}

async function expectPreparePdfError(bytes: Uint8Array): Promise<void> {
    await expect(preparePdfForTimestamp(bytes)).rejects.toMatchObject({
        code: TimestampErrorCode.PDF_ERROR,
    });
}

async function ghostscriptLinearizedFixture(): Promise<Uint8Array> {
    const encoded = await readFile(
        new URL("../fixtures/ghostscript-linearized.pdf.base64", import.meta.url),
        "utf8"
    );
    return Uint8Array.from(Buffer.from(encoded.trim(), "base64"));
}

afterEach(() => {
    vi.restoreAllMocks();
});

describe("Regression Tests - Prepare PDF Object Collision", () => {
    /**
     * Regression test for object number collision in preparePdfForTimestamp.
     *
     * Problem: When preparing a PDF that contains object streams (ObjStm),
     * pdf-lib-incremental-save incorrectly calculated largestObjectNumber,
     * often thinking it was lower than reality. This caused the new signature
     * dictionary to be assigned an object number that was already in use
     * (e.g., Object 5), effectively overwriting critical document structure.
     *
     * Fix: preparePdfForTimestamp now scans the entire PDF for object definitions
     * and manually updates largestObjectNumber before creating the signature.
     */
    it("should not overwrite existing objects when creating signature placeholder", async () => {
        // 1. Create a base PDF
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        // Add enough content to trigger object streams if possible,
        // or just ensure we have a known object number count.
        // By default pdf-lib might use ObjStm for minimal files.
        const pdfBytes = await doc.save({ useObjectStreams: true });

        // 2. Prepare for timestamp
        const prepared = await preparePdfForTimestamp(pdfBytes);

        // 3. Analyze objects in the prepared PDF
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Find all object definitions
        const objMatches = [...pdfStr.matchAll(/(\d+)\s+\d+\s+obj/g)];
        const objNums = objMatches.map((m) => parseInt(m[1] ?? "0", 10));

        // Count occurrences of each object number
        const counts = new Map<number, number>();
        for (const num of objNums) {
            counts.set(num, (counts.get(num) ?? 0) + 1);
        }

        // 4. Verify specific behavior:
        // - Object 5 (often the ObjStm in simple pdf-lib docs) should NOT be duplicated/overwritten
        // - The signature dictionary should have a NEW object number

        // Find duplicate object numbers
        const duplicates = [];
        for (const [num, count] of counts) {
            if (count > 1) {
                duplicates.push(num);
            }
        }

        // In a valid incremental update, essentially NO object number should be redefined
        // in a way that conflicts with its original type.
        // Note: '5 0 obj' appearing twice is technically valid in PDF increment
        // (replaces old version), BUT if the old version was an ObjStm and the new
        // one is a Dict, it destroys the objects inside the old ObjStm.

        // We can't strictly say "no duplicates" because standard incremental updates
        // DO duplicate object numbers (to update them).
        // BUT for a NEW signature on a fresh PDF, we shouldn't be updating
        // existing objects (like the catalog or pages) unless we explicitly meant to.
        // We DEFINITELY shouldn't update Object 5 if it's an ObjStm.

        // Let's check if the signature dictionary has a unique object number
        const sigDictMatch = /(\d+)\s+0\s+obj[\s\S]*?\/Type\s*\/DocTimeStamp/.exec(pdfStr);
        expect(sigDictMatch).toBeDefined();
        if (sigDictMatch) {
            const sigObjNum = parseInt(sigDictMatch[1] ?? "0", 10);

            // Check if this object number existed in the original PDF
            // We can approximate "original PDF" by looking at the first half of the file
            // or just checking if there are multiple definitions of this object number
            const occurrences = counts.get(sigObjNum);

            // If the signature object number appears more than once, it means we
            // overwrote an existing object. This is BAD for a new signature
            // (it should be a fresh object).
            expect(occurrences).toBe(1);
        }
    });

    it("should produce a valid PDF structure according to simple analysis", async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save();

        const prepared = await preparePdfForTimestamp(pdfBytes);
        const pdfStr = new TextDecoder("latin1").decode(prepared.bytes);

        // Check that we have a clean incremental update structure
        // Should have %%EOF at least twice (original + update)
        const eofCount = (pdfStr.match(/%%EOF/g) ?? []).length;
        expect(eofCount).toBeGreaterThanOrEqual(2);

        // Should have a new trailer/xref
        // (This is implicitly tested by generic PDF validity, but good to check)
    });

    it("should prepare and embed a timestamp on an object-stream PDF", async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        const pdfBytes = await doc.save({ useObjectStreams: true });
        const prepared = await preparePdfForTimestamp(pdfBytes);
        const appended = new TextDecoder("latin1").decode(prepared.bytes.subarray(pdfBytes.length));

        expect(appended).toContain("/DocTimeStamp");
        expect(appended).toContain("0".repeat(prepared.contentsPlaceholderLength));
        expect(prepared.byteRange).toHaveLength(4);

        const embedded = embedTimestampToken(prepared, new Uint8Array([1, 2, 3]));
        await expect(PDFDocument.load(embedded, { updateMetadata: false })).resolves.toBeDefined();
    });

    it("ignores object-like literal and stream text when allocating new references", async () => {
        // A raw-byte header scan would assign either spoofed number to the next signature ref.
        const input = await createSpoofedObjectTextPdf();
        const inputDocument = await PDFDocument.load(input, { updateMetadata: false });
        const inputNumbers = new Set(objectNumbers(inputDocument));

        const prepared = await preparePdfForTimestamp(input);
        const document = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
        const acroForm = document.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
        const fields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
        const fieldRef = fields.get(fields.size() - 1);

        expect(prepared.bytes.slice(0, input.length)).toEqual(input);
        expect(fieldRef).toBeInstanceOf(PDFRef);
        if (!(fieldRef instanceof PDFRef)) {
            throw new Error("prepared signature field must be indirect");
        }
        expect(inputNumbers.has(fieldRef.objectNumber)).toBe(false);
        expect(Math.max(...objectNumbers(document))).toBeLessThan(1000);
    });

    it("rejects a stale parser-derived startxref offset", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = asBytes(
            replaceFinalStartXref(asText(await document.save({ useObjectStreams: false })), 1)
        );

        await expectPreparePdfError(input);
    });

    it("rejects a PDF whose final xref metadata was removed", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const text = asText(await document.save({ useObjectStreams: false }));
        const input = asBytes(text.slice(0, finalStartXrefOffset(text)));

        await expectPreparePdfError(input);
    });

    it("rejects an appended comment containing a fake startxref marker", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = asBytes(
            `${asText(await document.save({ useObjectStreams: false }))}\n% startxref\n1\n%%EOF`
        );

        await expectPreparePdfError(input);
    });

    it("rejects a parser-directed classic xref embedded inside a raw stream", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = asBytes(
            appendClassicXrefInsideRawStream(
                asText(await document.save({ useObjectStreams: false }))
            )
        );
        const load = vi.spyOn(PDFDocument, "load").mockRejectedValue(new Error("load must not run"));

        await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
        expect(load).not.toHaveBeenCalled();
    });

    it("rejects a lowered final xref-stream Size", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const original = await document.save({ useObjectStreams: true });
        const input = replaceLastAsciiBytes(original, "/Size 7", "/Size 1");

        await expectPreparePdfError(input);
    });

    it("rejects a small latest classic Size despite a valid larger Prev revision", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const first = await preparePdfForTimestamp(
            await document.save({ useObjectStreams: false })
        );
        const input = asBytes(replaceFinalXrefDictionaryValue(asText(first.bytes), "Size", "1"));

        await expectPreparePdfError(input);
    });

    it("accepts escaped legal xref-stream dictionary names", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const original = await document.save({ useObjectStreams: true });
        const input = replaceLastAsciiBytes(
            replaceLastAsciiBytes(original, "/Type /XRef", "/Type /XR#65f"),
            "/Size ",
            "/Si#7Ae "
        );

        const parsedOriginal = await PDFDocument.load(original, { updateMetadata: false });
        expect(() => restoreLargestObjectNumber(input, parsedOriginal.context)).not.toThrow();
    });

    it("accepts a legal CR-only xref-stream end-of-line", () => {
        const input = createXrefStreamFixture({ index: [0, 4], eol: "\r" });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(() =>
            restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))
        ).not.toThrow();
    });

    it("updates a normative hybrid xref with a supplemental stream that omits /Prev", async () => {
        const input = createNormativeHybridFixture();
        const prepared = await preparePdfForTimestamp(input);

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        await expect(
            PDFDocument.load(prepared.bytes, { updateMetadata: false })
        ).resolves.toBeDefined();
    });

    it("updates a hybrid xref when its classic table provides the supplemental self entry", async () => {
        const input = createNormativeHybridFixture({ supplementalOmitsSelf: true });
        const prepared = await preparePdfForTimestamp(input);

        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        await expect(
            PDFDocument.load(prepared.bytes, { updateMetadata: false })
        ).resolves.toBeDefined();
    });

    it.each(["missing", "wrong-generation", "wrong-offset"] as const)(
        "rejects a hybrid supplemental self entry without a matching classic %s entry",
        async (classicSelfEntry: "missing" | "wrong-generation" | "wrong-offset") => {
            await expectPreparePdfError(
                createNormativeHybridFixture({
                    supplementalOmitsSelf: true,
                    classicSelfEntry,
                })
            );
        }
    );

    it("updates the checked Ghostscript 10.06.0 linearized fixture", async () => {
        const input = await ghostscriptLinearizedFixture();
        const prepared = await preparePdfForTimestamp(input);

        expect(createHash("sha256").update(input).digest("hex")).toBe(
            "710eb9e6a8afa12934faf907a63dffc085d173a2a69ac3073ac643368d2cd173"
        );
        expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        await expect(
            PDFDocument.load(prepared.bytes, { updateMetadata: false })
        ).resolves.toBeDefined();
    });

    it("repeats preparation on the checked Ghostscript-linearized revision", async () => {
        const original = await ghostscriptLinearizedFixture();
        const first = await preparePdfForTimestamp(original);
        const second = await preparePdfForTimestamp(first.bytes);

        expect(second.bytes.subarray(0, first.bytes.length)).toEqual(first.bytes);
        const appendedNumbers = indirectHeaderNumbers(second.bytes.subarray(first.bytes.length));
        expect(new Set(appendedNumbers).size).toBe(
            appendedNumbers.length
        );
        await expect(PDFDocument.load(second.bytes, { updateMetadata: false })).resolves.toBeDefined();
    });

    it("adds DSS after preparing the checked Ghostscript-linearized revision", async () => {
        const original = await ghostscriptLinearizedFixture();
        const first = await preparePdfForTimestamp(original);
        const updated = await addDSS(first.bytes, {
            certificates: [Uint8Array.of(0x30, 0x01, 0x01)],
            crls: [],
            ocspResponses: [],
        });

        expect(updated.subarray(0, first.bytes.length)).toEqual(first.bytes);
        const appendedNumbers = indirectHeaderNumbers(updated.subarray(first.bytes.length));
        expect(new Set(appendedNumbers).size).toBe(
            appendedNumbers.length
        );
        await expect(PDFDocument.load(updated, { updateMetadata: false })).resolves.toBeDefined();
    });

    it("rejects duplicate or overlapping xref-stream /Index ranges", () => {
        const input = createXrefStreamFixture({ index: [0, 4, 0, 4] });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });

    it("rejects non-overlapping xref-stream /Index ranges that are not ascending", () => {
        const input = createXrefStreamFixture({ index: [2, 2, 0, 2] });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });

    it("accepts null xref DecodeParms without silently treating predictors as null", () => {
        const input = createXrefStreamFixture({ index: [0, 4], decodeParms: "null" });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(() =>
            restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))
        ).not.toThrow();
    });

    it("fails closed for xref DecodeParms the pinned decoder cannot apply", () => {
        const input = createXrefStreamFixture({ index: [0, 4], decodeParms: "predictor" });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
            "DecodeParms is unsupported"
        );
    });

    it("rejects a compressed xref stream before a high-ratio decoded payload is materialized", () => {
        const input = createXrefStreamFixture({
            index: [0, 1_000_000],
            widths: [8, 8, 0],
            count: 1_000_000,
            compressed: true,
        });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(input.length).toBeLessThan(100_000);
        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });

    it("stops a Flate xref stream that expands past its declared entry length", () => {
        const input = createXrefStreamFixture({
            index: [0, 4],
            compressed: true,
            decodedPadding: 16 * 1024 * 1024,
        });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");

        expect(input.length).toBeLessThan(100_000);
        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });

    it("rejects public xref-stream bombs before PDFDocument.load", async () => {
        const input = createXrefStreamFixture({
            index: [0, 4],
            compressed: true,
            decodedPadding: 128 * 1024 * 1024,
        });
        const load = vi.spyOn(PDFDocument, "load").mockRejectedValue(new Error("load must not run"));

        await expect(preparePdfForTimestamp(input)).rejects.toMatchObject({
            code: TimestampErrorCode.PDF_ERROR,
        });
        expect(load).not.toHaveBeenCalled();
    });

    it("rejects public object-stream bombs before PDFDocument.load", async () => {
        const input = createObjectStreamXrefFixture({
            compressedObjectStream: true,
            objectStreamDecodedPadding: 128 * 1024 * 1024,
        });
        const load = vi.spyOn(PDFDocument, "load").mockRejectedValue(new Error("load must not run"));

        await expect(
            addDSS(input, { certificates: [], crls: [], ocspResponses: [] })
        ).rejects.toMatchObject({ code: TimestampErrorCode.PDF_ERROR });
        expect(load).not.toHaveBeenCalled();
    });

    it.each([
        { label: "a non-ObjStm active container", options: { objectStreamType: "XRef" as const } },
        { label: "an out-of-range object-stream index", options: { compressedObjectIndex: 1 } },
        {
            label: "a mismatched object-stream header object",
            options: { compressedObjectNumber: 9 },
        },
    ])(
        "rejects compressed xref entries with $label",
        ({ options }: { options: Parameters<typeof createObjectStreamXrefFixture>[0] }) => {
            const input = createObjectStreamXrefFixture(options);
            const xrefOffset = asText(input).lastIndexOf("5 0 obj");

            expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
                expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
            );
        }
    );

    it("rejects an object stream whose member offset is outside the decoded stream", () => {
        const input = createObjectStreamXrefFixture({ objectStreamMemberOffset: 999 });
        const xrefOffset = asText(input).lastIndexOf("5 0 obj");

        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });

    it("decodes one active compressed object stream once even when it serves many entries", () => {
        const input = createManyObjectStreamXrefFixture(64);
        const xrefOffset = asText(input).lastIndexOf("68 0 obj");
        const push = vi.spyOn(pako.Inflate.prototype, "push");

        expect(() => restoreLargestObjectNumber(input, xrefFixtureContext(xrefOffset))).not.toThrow();
        expect(push).toHaveBeenCalledTimes(1);
    });

    it("rejects a compressed entry whose active container was shadowed in a newer revision", async () => {
        const input = appendStaleObjectStreamContainerRevision(createObjectStreamXrefFixture({}));

        await expectPreparePdfError(input);
    });

    it("rejects preparation when repeated registrations would exceed the safe object range", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const input = replaceLastAsciiNumber(
            await document.save({ useObjectStreams: false }),
            "/Size ",
            Number.MAX_SAFE_INTEGER.toString()
        );

        await expectPreparePdfError(input);
    });

    it("rejects unsafe parsed context object numbers before allocating a reference", () => {
        const contexts: {
            largestObjectNumber: number;
            enumerateIndirectObjects(): [{ objectNumber: number }, unknown][];
            lookup(ref: PDFRef): PDFObject | undefined;
            pdfFileDetails: { prevStartXRef: number };
        }[] = [
            {
                largestObjectNumber: -1,
                enumerateIndirectObjects: () => [],
                lookup: () => undefined,
                pdfFileDetails: { prevStartXRef: 1 },
            },
            {
                largestObjectNumber: 1,
                enumerateIndirectObjects: () => [
                    [{ objectNumber: Number.MAX_SAFE_INTEGER }, undefined],
                ],
                lookup: () => undefined,
                pdfFileDetails: { prevStartXRef: 1 },
            },
        ];

        for (const context of contexts) {
            expect(() => restoreLargestObjectNumber(new Uint8Array(), context)).toThrow(
                expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
            );
        }
    });

    it("rejects post-load parsed references that were not present in the pre-load proof", () => {
        const input = createXrefStreamFixture({ index: [0, 4] });
        const xrefOffset = asText(input).lastIndexOf("3 0 obj");
        const proof = preflightPdfXref(input);
        const context = xrefFixtureContext(xrefOffset);
        context.enumerateIndirectObjects = () =>
            [
                [{ objectNumber: 1 }, undefined],
                [{ objectNumber: 2 }, undefined],
                [{ objectNumber: 3 }, undefined],
                [{ objectNumber: 4 }, undefined],
            ] as [{ objectNumber: number }, unknown][];

        expect(() => restoreLargestObjectNumber(input, context, proof)).toThrow(
            expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR })
        );
    });
});
