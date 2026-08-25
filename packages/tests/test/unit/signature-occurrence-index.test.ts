import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import {
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFString,
} from "pdf-lib-incremental-save";
import * as pkijs from "pkijs";
import { extractTimestamps, verifyPdfTimestamps } from "../../../core/src/pdf/extract.js";
import { PdfSignatureOccurrenceIndex } from "../../../core/src/pdf/signature-occurrence-index.js";
import * as pkiUtils from "../../../core/src/pki/pki-utils.js";
import { createTimestampRequest } from "../../../core/src/tsa/index.js";
import * as tokenValidation from "../../../core/src/tsa/token-validation.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";
import { qpdfLinearizedBasePdf } from "../fixtures/qpdf-linearized-base.js";

type ByteRange = [number, number, number, number];

const SCANNER_FRAME_COLLECTION_CAP = 100_000;
const SCANNER_REVISION_CAP = 4_096;

interface ContentsSpan {
    start: number;
    end: number;
}

function contentsSpans(text: string): ContentsSpan[] {
    const result: ContentsSpan[] = [];
    let position = 0;
    while (position < text.length) {
        const key = text.indexOf("/Contents", position);
        if (key < 0) break;
        const start = text.indexOf("<", key);
        const end = start < 0 ? -1 : text.indexOf(">", start);
        if (start < 0 || end < 0) throw new Error("Fixture has an unterminated Contents value");
        result.push({ start, end });
        position = end + 1;
    }
    return result;
}

function byteRangeSpans(text: string): { start: number; end: number }[] {
    const result: { start: number; end: number }[] = [];
    let position = 0;
    while (position < text.length) {
        const start = text.indexOf("/ByteRange", position);
        if (start < 0) break;
        const end = text.indexOf("]", start);
        if (end < 0) throw new Error("Fixture has an unterminated ByteRange");
        result.push({ start, end: end + 1 });
        position = end + 1;
    }
    return result;
}

function replaceByteRanges(pdf: Uint8Array, byteRanges: ByteRange[]): Uint8Array {
    const result = new Uint8Array(pdf);
    const text = new TextDecoder("latin1").decode(result);
    const spans = byteRangeSpans(text);
    if (spans.length !== byteRanges.length) throw new Error("Fixture ByteRange count does not match");
    for (let index = 0; index < spans.length; index += 1) {
        const span = spans[index];
        const byteRange = byteRanges[index];
        if (span === undefined || byteRange === undefined) throw new Error("Fixture ByteRange is missing");
        const replacement = `/ByteRange [${byteRange.map(String).join(" ")}]`;
        if (replacement.length > span.end - span.start) {
            throw new Error("Fixture ByteRange placeholder is too small");
        }
        result.set(
            new TextEncoder().encode(replacement.padEnd(span.end - span.start, " ")),
            span.start
        );
    }
    return result;
}

function coveredBytes(pdf: Uint8Array, byteRange: ByteRange): Uint8Array {
    const [offset1, length1, offset2, length2] = byteRange;
    const result = new Uint8Array(length1 + length2);
    result.set(pdf.subarray(offset1, offset1 + length1));
    result.set(pdf.subarray(offset2, offset2 + length2), length1);
    return result;
}

function tokenHex(token: Uint8Array): string {
    return Array.from(token, (byte) => byte.toString(16).padStart(2, "0")).join("").toUpperCase();
}

function malformedCandidateBytes(kind: "hex" | "literal" | "indirect-length-stream"): Uint8Array {
    const candidate =
        kind === "hex"
            ? "1 0 obj <\n"
            : kind === "literal"
              ? "1 0 obj (\n"
              : "1 0 obj\n<< /Length 9 0 R >>\nstream\n";
    return new TextEncoder().encode(`%PDF-1.7\n${candidate.repeat(1024)}`);
}

function oversizedArrayObject(itemCount = SCANNER_FRAME_COLLECTION_CAP + 1): Uint8Array {
    return new TextEncoder().encode(`1 0 obj\n[${"0 ".repeat(itemCount)}]\nendobj\n`);
}

function oversizedDictionaryObject(entryCount = SCANNER_FRAME_COLLECTION_CAP + 1): Uint8Array {
    return new TextEncoder().encode(`1 0 obj\n<< ${"/A 0 ".repeat(entryCount)}>>\nendobj\n`);
}

function oversizedNestedDictionaryObject(): Uint8Array {
    const dictionary = `<< /Nested << ${"/A 0 ".repeat(250)}>> >>`;
    return new TextEncoder().encode(`1 0 obj\n[${dictionary.repeat(401)}]\nendobj\n`);
}

function revisionMarkerFlood(markerCount = SCANNER_REVISION_CAP + 1): Uint8Array {
    return new TextEncoder().encode("startxref\n0\n%%EOF\n".repeat(markerCount));
}

interface SignatureOccurrenceScanStats {
    lexicalBytes: number;
    physicalObjectAttempts: number;
    revisionBoundaryComparisons: number;
}

function scanStats(index: PdfSignatureOccurrenceIndex): SignatureOccurrenceScanStats | undefined {
    return (index as unknown as { scanStats?: SignatureOccurrenceScanStats }).scanStats;
}

type SecondRevisionShape =
    | "valid"
    | "empty-xref"
    | "missing-prev"
    | "wrong-prev"
    | "malformed-entry";

function twoRevisionPdf(
    shape: SecondRevisionShape,
    updatePrefix = "",
    afterXref = "",
    previousPrefix = ""
): Uint8Array {
    let source = "%PDF-1.4\n";
    const firstXrefOffset = source.length;
    source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n${firstXrefOffset.toString()}\n%%EOF\n`;

    source += updatePrefix;
    const secondXrefOffset = source.length;
    const secondEntries =
        shape === "empty-xref"
            ? ""
            : shape === "malformed-entry"
              ? "0 1\n0000000000\n65535\nf \n"
              : "0 1\n0000000000 65535 f \n";
    const previous =
        shape === "missing-prev"
            ? ""
            : ` /Prev ${previousPrefix}${(shape === "wrong-prev" ? 0 : firstXrefOffset).toString()}`;
    source += `xref\n${secondEntries}trailer\n<< /Size 1${previous} >>\n${afterXref}startxref\n${secondXrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(source);
}

function twoRevisionPdfWithClassicEntry(entry: string, subsectionEnding = "\n"): Uint8Array {
    let source = "%PDF-1.4\n";
    const firstXrefOffset = source.length;
    source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n${firstXrefOffset.toString()}\n%%EOF\n`;

    const secondXrefOffset = source.length;
    source += `xref\n0 1${subsectionEnding}${entry}trailer\n<< /Size 1 /Prev ${firstXrefOffset.toString()} >>\nstartxref\n${secondXrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(source);
}

function twoRevisionPdfWithClassicHeader(header: string, afterEntry = ""): Uint8Array {
    let source = "%PDF-1.4\n";
    const firstXrefOffset = source.length;
    source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n${firstXrefOffset.toString()}\n%%EOF\n`;

    const secondXrefOffset = source.length;
    source += `xref${header}0000000000 65535 f \n${afterEntry}trailer\n<< /Size 1 /Prev ${firstXrefOffset.toString()} >>\nstartxref\n${secondXrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(source);
}

function streamRevisionObject(dictionary: string, payload = "abc"): string {
    return `8 0 obj\n${dictionary}\nstream\n${payload}\nendstream\nendobj\n`;
}

function demoPdfWithIncrementalObject(object: string): Uint8Array {
    const source = new TextDecoder("latin1").decode(
        readFileSync(new URL("../../../demo/test.pdf", import.meta.url))
    );
    const markerStart = source.lastIndexOf("startxref\n");
    const previousStart = markerStart + "startxref\n".length;
    const previousEnd = source.indexOf("\n", previousStart);
    if (markerStart < 0 || previousEnd < previousStart) {
        throw new Error("Demo fixture has no terminal startxref marker");
    }
    const previousXref = Number(source.slice(previousStart, previousEnd));
    if (!Number.isSafeInteger(previousXref) || previousXref < 0) {
        throw new Error("Demo fixture has an invalid terminal startxref offset");
    }

    let result = `${source}\n`;
    const objectOffset = result.length;
    if (objectOffset > 9_999_999_999) {
        throw new Error("Demo fixture object offset does not fit a classic xref entry");
    }
    result += object;
    const xrefOffset = result.length;
    result += `xref\n0 1\n0000000000 65535 f \n8 1\n${objectOffset.toString().padStart(10, "0")} 00000 n \ntrailer\n<< /Size 9 /Prev ${previousXref.toString()} >>\nstartxref\n${xrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(result);
}

function oneRevisionPdf(previous?: number): Uint8Array {
    let source = "%PDF-1.4\n";
    const xrefOffset = source.length;
    const previousEntry = previous === undefined ? "" : ` /Prev ${previous.toString()}`;
    source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1${previousEntry} >>\nstartxref\n${xrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(source);
}

function oneRevisionPdfWithOffsetTrivia(trivia: string): Uint8Array {
    let source = "%PDF-1.4\n";
    const xrefOffset = source.length;
    source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n${xrefOffset.toString()}\n${trivia}%%EOF`;
    return new TextEncoder().encode(source);
}

function replaceSameWidthAscii(bytes: Uint8Array, expected: string, replacement: string): void {
    if (expected.length !== replacement.length) {
        throw new Error("Fixture replacement must preserve physical offsets");
    }
    const index = new TextDecoder("latin1").decode(bytes).indexOf(expected);
    if (index < 0) throw new Error(`Fixture does not contain '${expected}'`);
    bytes.set(new TextEncoder().encode(replacement), index);
}

function linearizedObjectAfterXrefPdf(segment: "early" | "main"): Uint8Array {
    const base = qpdfLinearizedBasePdf("early");
    const source = new TextDecoder("latin1").decode(base);
    const earlyMarker = source.indexOf("startxref\n0\n%%EOF");
    const terminalMarker = source.lastIndexOf("startxref\n216\n%%EOF");
    if (earlyMarker < 0 || terminalMarker < 0) throw new Error("Fixture has no linearized boundaries");

    const object = new TextEncoder().encode("7 0 obj\n<< /Test true >>\nendobj\n");
    const insertAt = segment === "early" ? earlyMarker : terminalMarker;
    const result = new Uint8Array(base.length + object.length);
    result.set(base.subarray(0, insertAt));
    result.set(object, insertAt);
    result.set(base.subarray(insertAt), insertAt + object.length);

    replaceSameWidthAscii(result, `/L ${base.length.toString()}`, `/L ${result.length.toString()}`);
    if (segment === "early") {
        const mainXref = source.lastIndexOf("xref\n0 2");
        if (mainXref < 0) throw new Error("Fixture has no main xref");
        replaceSameWidthAscii(
            result,
            `/Prev ${mainXref.toString()}`,
            `/Prev ${(mainXref + object.length).toString()}`
        );
    }
    return result;
}

function linearizedPdfWithNumericMarker(value: string): Uint8Array {
    const base = qpdfLinearizedBasePdf("early");
    const source = new TextDecoder("latin1").decode(base);
    const markerStart = source.indexOf("/Linearized ");
    const valueStart = markerStart + "/Linearized ".length;
    const valueEnd = source.indexOf(" ", valueStart);
    const paddingStart = source.indexOf("endobj\n", valueEnd) + "endobj\n".length;
    const addedLength = value.length - (valueEnd - valueStart);
    if (
        markerStart < 0 ||
        valueEnd < valueStart ||
        addedLength < 0 ||
        source.slice(valueStart, valueEnd) !== "1" ||
        source.slice(paddingStart, paddingStart + addedLength) !== " ".repeat(addedLength)
    ) {
        throw new Error("Linearized fixture cannot preserve xref offsets for this numeric marker");
    }

    const result = new Uint8Array(base.length);
    result.set(base.subarray(0, valueStart));
    result.set(new TextEncoder().encode(value), valueStart);
    let resultPosition = valueStart + value.length;
    result.set(base.subarray(valueEnd, paddingStart), resultPosition);
    resultPosition += paddingStart - valueEnd;
    result.set(base.subarray(paddingStart + addedLength), resultPosition);
    return result;
}

function lexicalRevisionChain(revisionCount: number): Uint8Array {
    let source = "%PDF-1.4\n";
    let previousXrefOffset: number | undefined;
    for (let revision = 0; revision < revisionCount; revision += 1) {
        const xrefOffset = source.length;
        const previous =
            previousXrefOffset === undefined ? "" : ` /Prev ${previousXrefOffset.toString()}`;
        source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1${previous} >>\nstartxref\n${xrefOffset.toString()}\n%%EOF`;
        if (revision + 1 < revisionCount) source += "\n";
        previousXrefOffset = xrefOffset;
    }
    return new TextEncoder().encode(source);
}

function xrefStreamPdf(type: string): Uint8Array {
    let source = "%PDF-1.5\n";
    const xrefOffset = source.length;
    source += `1 0 obj\n<< /Type /${type} /Length 0 >>\nstream\n\nendstream\nendobj\nstartxref\n${xrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(source);
}

function classicThenXrefStreamPdf(previous: "valid" | "missing" | "wrong"): Uint8Array {
    let source = "%PDF-1.5\n";
    const firstXrefOffset = source.length;
    source += `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 1 >>\nstartxref\n${firstXrefOffset.toString()}\n%%EOF\n`;
    const xrefOffset = source.length;
    const previousEntry =
        previous === "missing"
            ? ""
            : ` /Prev ${(previous === "valid" ? firstXrefOffset : 0).toString()}`;
    source += `2 0 obj\n<< /Type /XRef${previousEntry} /Length 0 >>\nstream\n\nendstream\nendobj\nstartxref\n${xrefOffset.toString()}\n%%EOF`;
    return new TextEncoder().encode(source);
}

async function directSignatureDictionaryPdf(
    firstHasExactMarkers: boolean,
    secondHasExactMarkers?: boolean
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const contentsLength = 4096 * 2;
    const signature = (hasExactMarkers: boolean) =>
        context.obj({
            ...(hasExactMarkers && { Type: PDFName.of("DocTimeStamp") }),
            SubFilter: PDFName.of("ETSI.RFC3161"),
            Contents: PDFHexString.of("0".repeat(contentsLength)),
            ByteRange: context.obj([0, 111111111111, 111111111111, 111111111111]),
        });
    const first = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("First"),
        V: signature(firstHasExactMarkers),
    });
    const fields = context.register(
        context.obj([
            first,
            ...(secondHasExactMarkers === undefined
                ? []
                : [
                      context.obj({
                          FT: PDFName.of("Sig"),
                          T: PDFString.of("Second"),
                          V: signature(secondHasExactMarkers),
                      }),
                  ]),
        ])
    );
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));

    const unsigned = await document.save({ useObjectStreams: false });
    const text = new TextDecoder("latin1").decode(unsigned);
    const spans = contentsSpans(text);
    if (spans.length !== (secondHasExactMarkers === undefined ? 1 : 2)) {
        throw new Error("Fixture has the wrong direct Contents count");
    }
    const firstSpan = spans[0];
    if (firstSpan === undefined) throw new Error("Fixture has no first Contents value");
    const range: ByteRange = [
        0,
        firstSpan.start,
        firstSpan.end + 1,
        unsigned.length - (firstSpan.end + 1),
    ];
    const prepared = replaceByteRanges(unsigned, spans.map(() => range));
    const { request } = await createTimestampRequest(coveredBytes(prepared, range), {
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    const hex = tokenHex(fixture.rawToken);
    if (hex.length > contentsLength) throw new Error("Fixture token does not fit");
    const result = new Uint8Array(prepared);
    for (const span of spans) result.set(new TextEncoder().encode(hex), span.start + 1);
    return result;
}

async function manyFieldsSharingOneSignaturePdf(
    fieldCount = 128,
    includeSharedMetadata = false
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const padding = context.register(PDFString.of("x".repeat(1024 * 1024)));
    document.catalog.set(PDFName.of("Padding"), padding);
    const contentsLength = 4096 * 2;
    const signature = context.obj({
        Type: PDFName.of("DocTimeStamp"),
        SubFilter: PDFName.of("ETSI.RFC3161"),
        Contents: PDFHexString.of("0".repeat(contentsLength)),
        ByteRange: context.obj([0, 111111111111, 111111111111, 111111111111]),
        ...(includeSharedMetadata
            ? {
                  Reason: PDFHexString.of("526561736f6e"),
                  Location: PDFHexString.of("48656c73696e6b69"),
                  ContactInfo: PDFHexString.of("747361406578616d706c652e74657374"),
                  M: PDFString.of("D:20260825000000Z"),
              }
            : {}),
    });
    const signatureRef = context.register(signature);
    // Keep the field graph large enough to exercise shared /V deduplication
    // without turning this unit test into a wall-clock benchmark.
    const fieldArray = context.obj([]);
    for (let index = 0; index < fieldCount; index += 1) {
        fieldArray.push(
            context.register(
                context.obj({
                    FT: PDFName.of("Sig"),
                    T: PDFString.of(`Shared${index.toString()}`),
                    V: signatureRef,
                })
            )
        );
    }
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fieldArray }));

    const unsigned = await document.save({ useObjectStreams: false });
    const text = new TextDecoder("latin1").decode(unsigned);
    const [span] = contentsSpans(text);
    if (span === undefined) throw new Error("Fixture has no shared Contents value");
    const range: ByteRange = [0, span.start, span.end + 1, unsigned.length - (span.end + 1)];
    const prepared = replaceByteRanges(unsigned, [range]);
    const { request } = await createTimestampRequest(coveredBytes(prepared, range), {
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    const hex = tokenHex(fixture.rawToken);
    if (hex.length > contentsLength) throw new Error("Fixture token does not fit");
    const result = new Uint8Array(prepared);
    result.set(new TextEncoder().encode(hex), span.start + 1);
    return result;
}

describe("lexical signature /Contents occurrence binding", () => {
    it("rejects an array before retaining more than one frame's parsed-value budget", () => {
        expect(() => new PdfSignatureOccurrenceIndex(oversizedArrayObject(), [])).toThrow(
            "PDF signature occurrence scan exceeds the retained structure limit"
        );
    });

    it("rejects a dictionary before retaining more than one frame's entry budget", () => {
        expect(() => new PdfSignatureOccurrenceIndex(oversizedDictionaryObject(), [])).toThrow(
            "PDF signature occurrence scan exceeds the retained structure limit"
        );
    });

    it("shares the retained-structure budget across nested dictionaries in one frame", () => {
        expect(() => new PdfSignatureOccurrenceIndex(oversizedNestedDictionaryObject(), [])).toThrow(
            "PDF signature occurrence scan exceeds the retained structure limit"
        );
    });

    it("rejects a revision-marker flood while collecting boundaries", () => {
        expect(() => new PdfSignatureOccurrenceIndex(revisionMarkerFlood(), [])).toThrow(
            "PDF signature occurrence scan exceeds the revision marker limit"
        );
    });

    it.each(["hex", "literal", "indirect-length-stream"] as const)(
        "scans repeated unterminated %s candidates in one bounded lexical pass",
        (kind: "hex" | "literal" | "indirect-length-stream") => {
            const bytes = malformedCandidateBytes(kind);
            const index = new PdfSignatureOccurrenceIndex(bytes, []);

            // A malformed candidate may make the tail ambiguous, but it must
            // consume that tail once rather than retry a full parse at every
            // fake object header within it.
            expect(scanStats(index)).toMatchObject({
                lexicalBytes: expect.any(Number),
                physicalObjectAttempts: 1,
            });
            expect(scanStats(index)?.lexicalBytes).toBeLessThanOrEqual(bytes.length * 2);
        }
    );

    it("accepts a framed two-revision classic xref chain", () => {
        const bytes = twoRevisionPdf("valid");
        const index = new PdfSignatureOccurrenceIndex(bytes, []);

        expect(index.isRevisionBoundary(bytes.length, bytes.length)).toBe(true);
    });

    it.each([
        ["one exact direct length", "<< /Length 3 >>", true],
        ["one indirect length reference", "<< /Length 9 0 R >>", true],
        ["a missing Length", "<< >>", false],
        ["duplicate Length entries", "<< /Length 3 /Length 4 >>", false],
        ["a name Length", "<< /Length /Bad >>", false],
        ["a negative Length", "<< /Length -1 >>", false],
        ["an out-of-bounds direct Length", "<< /Length 999999999 >>", false],
        ["an unsafe direct Length", "<< /Length 9007199254740992 >>", false],
    ])(
        "classifies stream framing with %s",
        (_: string, dictionary: string, expected: boolean) => {
            const bytes = twoRevisionPdf("valid", streamRevisionObject(dictionary));

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(expected);
        }
    );

    it("rejects an implausible direct stream length in a demo-PDF incremental revision", () => {
        const bytes = demoPdfWithIncrementalObject(
            streamRevisionObject("<< /Length 999999999 >>")
        );

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it.each([
        ["a non-hex name escape", "/Bad#GG", false],
        ["an incomplete name escape", "/Bad#0", false],
        ["a decoded NUL name escape", "/Bad#00", false],
        ["a valid escaped name byte", "/Bad#20", true],
    ])(
        "classifies a revision object with %s",
        (_: string, name: string, expected: boolean) => {
            const bytes = demoPdfWithIncrementalObject(`8 0 obj\n<< ${name} true >>\nendobj\n`);

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(expected);
        }
    );

    it.each(["empty-xref", "missing-prev", "wrong-prev", "malformed-entry"] as const)(
        "rejects a terminal revision with %s framing",
        (shape: Exclude<SecondRevisionShape, "valid">) => {
            const bytes = twoRevisionPdf(shape);
            const index = new PdfSignatureOccurrenceIndex(bytes, []);

            expect(index.isRevisionBoundary(bytes.length, bytes.length)).toBe(false);
        }
    );

    it.each([
        "0000000000 65535 f \n",
        "0000000000 65535 f \r",
        "0000000000 65535 f\r\n",
        "0000000000 65535 f \r\n",
        "0000000000\t65535\tf\t\n",
    ])("accepts a classic xref entry with qpdf-compatible horizontal padding", (entry: string) => {
        const bytes = twoRevisionPdfWithClassicEntry(entry);

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            true
        );
    });

    it("requires a line terminator after a classic xref subsection header", () => {
        const bytes = twoRevisionPdfWithClassicEntry("0000000000 65535 f \n", " ");

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it.each([
        ["a comment after xref", "\n% comment\n0 1\n", "", false],
        ["a comment between subsection columns", "\n0 % comment\n1\n", "", false],
        ["a NUL after xref", "\0 0 1\n", "", false],
        ["a NUL between subsection columns", "\n0\0 1\n", "", false],
        ["horizontal whitespace between subsection columns", "\n0\t1\n", "", true],
        ["form-feed xref control whitespace", "\f0\f1\n", "", true],
        ["a comment after the final xref entry", "\n0 1\n", "% comment\n", true],
    ])(
        "classifies classic xref framing with %s",
        (_: string, header: string, afterEntry: string, expected: boolean) => {
            const bytes = twoRevisionPdfWithClassicHeader(header, afterEntry);

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(expected);
        }
    );

    it("rejects a signed indirect-object header in an otherwise framed update", () => {
        const bytes = twoRevisionPdf("valid", "-1 -0 obj\n<< >>\nendobj\n");

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it("rejects an object-zero header in an otherwise framed update", () => {
        const bytes = twoRevisionPdf("valid", "0 0 obj\n<< >>\nendobj\n");

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it("rejects a physical object after a selected xref frame", () => {
        const bytes = twoRevisionPdf("valid", "", "8 0 obj\n<< >>\nendobj\n");

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it.each([
        ["an unknown bare scalar", "8 0 obj\nTHIS_IS_GARBAGE\nendobj\n"],
        ["a non-hex byte in a hex string", "8 0 obj\n<not-hex>\nendobj\n"],
        ["a signed indirect reference", "8 0 obj\n-1 -0 R\nendobj\n"],
    ])("rejects a revision object with %s", (_: string, updatePrefix: string) => {
        const bytes = twoRevisionPdf("valid", updatePrefix);

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it("accepts a valid real scalar in a complete revision object", () => {
        const bytes = twoRevisionPdf("valid", "8 0 obj\n-1.5\nendobj\n");

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            true
        );
    });

    it("rejects an ordinary base trailer with a forward Prev pointer", () => {
        const bytes = oneRevisionPdf(0);

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it.each(["% comment\n", "%\n"])(
        "accepts a comment between startxref offset and EOF (%s)",
        (trivia: string) => {
            const bytes = oneRevisionPdfWithOffsetTrivia(trivia);

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(true);
        }
    );

    it("rejects a signed structural Prev pointer", () => {
        const bytes = twoRevisionPdf("valid", "", "", "+");

        expect(new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)).toBe(
            false
        );
    });

    it.each(["early", "main"] as const)(
        "rejects a complete object after the linearized %s xref",
        (segment: "early" | "main") => {
            const bytes = linearizedObjectAfterXrefPdf(segment);

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(false);
        }
    );

    it.each(["1.0", "+1.0", "01", "1.", "0001.000"])(
        "accepts a qpdf-compatible exact-one Linearized value (%s)",
        (value: string) => {
            const bytes = linearizedPdfWithNumericMarker(value);

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(true);
        }
    );

    it.each([".5", "1e0", ".1e1"])(
        "rejects a non-one or invalid Linearized numeric value (%s)",
        (value: string) => {
            const bytes = linearizedPdfWithNumericMarker(value);

            expect(
                new PdfSignatureOccurrenceIndex(bytes, []).isRevisionBoundary(bytes.length, bytes.length)
            ).toBe(false);
        }
    );

    it("looks up a revision boundary without linearly scanning every earlier revision", () => {
        const bytes = lexicalRevisionChain(2048);
        const index = new PdfSignatureOccurrenceIndex(bytes, []);

        expect(index.isRevisionBoundary(bytes.length, bytes.length)).toBe(true);
        expect(scanStats(index)?.revisionBoundaryComparisons).toBeLessThan(16);
    });

    it("requires an XRef stream target to declare an exact root /Type /XRef", () => {
        const valid = xrefStreamPdf("XRef");
        const invalid = xrefStreamPdf("NotXRef");

        expect(new PdfSignatureOccurrenceIndex(valid, []).isRevisionBoundary(valid.length, valid.length)).toBe(
            true
        );
        expect(
            new PdfSignatureOccurrenceIndex(invalid, []).isRevisionBoundary(invalid.length, invalid.length)
        ).toBe(false);
    });

    it.each(["missing", "wrong"] as const)(
        "requires a later XRef stream /Prev to link to its preceding xref (%s)",
        (previous: "missing" | "wrong") => {
            const valid = classicThenXrefStreamPdf("valid");
            const invalid = classicThenXrefStreamPdf(previous);

            expect(
                new PdfSignatureOccurrenceIndex(valid, []).isRevisionBoundary(valid.length, valid.length)
            ).toBe(true);
            expect(
                new PdfSignatureOccurrenceIndex(invalid, []).isRevisionBoundary(
                    invalid.length,
                    invalid.length
                )
            ).toBe(false);
        }
    );

    it("fails closed when two direct signature dictionaries in one owner are indistinguishable", async () => {
        await expect(extractTimestamps(await directSignatureDictionaryPdf(true, true))).resolves.toEqual(
            []
        );
    });

    it("keeps a direct SubFilter-only legacy signature value publicly extractable", async () => {
        const timestamps = await extractTimestamps(await directSignatureDictionaryPdf(false));
        expect(timestamps.map((timestamp) => timestamp.fieldName)).toEqual(["First"]);
    });

    it("fails closed when direct candidates share the same legacy SubFilter binding", async () => {
        await expect(extractTimestamps(await directSignatureDictionaryPdf(true, false))).resolves.toEqual(
            []
        );
    });

    it("decodes, parses, and binds a shared signature value once", async () => {
        const pdf = await manyFieldsSharingOneSignaturePdf();
        const decode = vi.spyOn(PDFHexString.prototype, "asBytes");
        const parse = vi.spyOn(pkiUtils, "parseTimestampToken");
        const bind = vi.spyOn(PdfSignatureOccurrenceIndex.prototype, "hasSelectedContents");

        try {
            await expect(extractTimestamps(pdf)).resolves.toHaveLength(128);
            expect(decode).toHaveBeenCalledTimes(1);
            expect(parse).toHaveBeenCalledTimes(1);
            expect(bind).toHaveBeenCalledTimes(1);
        } finally {
            decode.mockRestore();
            parse.mockRestore();
            bind.mockRestore();
        }
    });

    it("shares cached signature buffers and decodes shared metadata once", async () => {
        const pdf = await manyFieldsSharingOneSignaturePdf(4, true);
        const metadataDecode = vi.spyOn(PDFHexString.prototype, "asString");

        try {
            const timestamps = await extractTimestamps(pdf);
            const first = timestamps[0];
            const second = timestamps[1];
            if (first === undefined || second === undefined) throw new Error("Fixture has too few timestamps");

            expect(first.token).toBe(second.token);
            expect(first.contentsValueBytes).toBe(second.contentsValueBytes);
            expect(first.info.nonce).toBe(second.info.nonce);
            expect(first.info.genTime).not.toBe(second.info.genTime);
            expect(first.m).not.toBe(second.m);
            expect(metadataDecode).toHaveBeenCalledTimes(3);
        } finally {
            metadataDecode.mockRestore();
        }
    });

    it("verifies a shared signature value once while retaining every field result", async () => {
        const pdf = await manyFieldsSharingOneSignaturePdf(4);
        const verifyCms = vi.spyOn(tokenValidation, "verifyTimestampCmsSignature");

        try {
            const verified = await verifyPdfTimestamps(pdf, { strictESSValidation: true });

            expect(verified).toHaveLength(4);
            expect(verified.every((timestamp) => timestamp.verified)).toBe(true);
            expect(verifyCms).toHaveBeenCalledTimes(1);
        } finally {
            verifyCms.mockRestore();
        }
    });

    it("shares a large cached certificate array across duplicate verification results", async () => {
        const pdf = await manyFieldsSharingOneSignaturePdf(4);
        const initial = await verifyPdfTimestamps(pdf, { strictESSValidation: true });
        const certificate = initial[0]?.certificates?.[0];
        if (certificate === undefined) throw new Error("Fixture has no signer certificate");
        const certificates = [
            certificate,
            ...Array.from({ length: 16_383 }, () => new pkijs.Certificate()),
        ];
        const getCertificates = vi
            .spyOn(tokenValidation, "getEmbeddedCertificates")
            .mockReturnValue(certificates);

        try {
            const verified = await verifyPdfTimestamps(pdf, { strictESSValidation: true });
            const first = verified[0];
            const second = verified[1];
            if (first === undefined || second === undefined) {
                throw new Error("Fixture has too few verified timestamps");
            }

            expect(first.certificates).toBe(certificates);
            expect(second.certificates).toBe(first.certificates);
        } finally {
            getCertificates.mockRestore();
        }
    });

});
