import { describe, expect, it } from "vitest";
import {
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFString,
} from "pdf-lib-incremental-save";
import {
    discoverArchiveTimestamps,
    extractTimestamps,
    verifyTimestamp,
} from "../../../core/src/pdf/extract.js";
import { createTimestampRequest } from "../../../core/src/tsa/index.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";

interface NestedPreparedPdf {
    bytes: Uint8Array;
    byteRange: [number, number, number, number];
    contentsOffset: number;
    contentsLength: number;
    spoofContentsOffset?: number;
}

function replaceByteRange(
    pdf: Uint8Array,
    byteRange: [number, number, number, number]
): Uint8Array {
    const result = new Uint8Array(pdf);
    const text = new TextDecoder("latin1").decode(result);
    const start = text.lastIndexOf("/ByteRange");
    const end = text.indexOf("]", start);
    if (start < 0 || end < 0) throw new Error("Nested fixture has no ByteRange placeholder");
    const replacement = `/ByteRange [${byteRange.map(String).join(" ")}]`;
    const originalLength = end + 1 - start;
    if (replacement.length > originalLength) {
        throw new Error("Nested fixture ByteRange placeholder is too small");
    }
    result.set(new TextEncoder().encode(replacement.padEnd(originalLength, " ")), start);
    return result;
}

function coveredBytes(
    pdf: Uint8Array,
    [offset1, length1, offset2, length2]: [number, number, number, number]
): Uint8Array {
    const result = new Uint8Array(length1 + length2);
    result.set(pdf.subarray(offset1, offset1 + length1));
    result.set(pdf.subarray(offset2, offset2 + length2), length1);
    return result;
}

async function createNestedPreparedPdf(
    includeWidget = false,
    directSignatureValue = false,
    reason = "endobj",
    contentsSpoofInReason = false
): Promise<NestedPreparedPdf> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const contentsLength = 4096 * 2;
    const signature = context.obj({
        Type: PDFName.of("DocTimeStamp"),
        SubFilter: PDFName.of("ETSI.RFC3161"),
        // This legal literal precedes /Contents. Raw owner matching must not
        // mistake its text for the enclosing indirect-object terminator.
        Reason: PDFString.of(
            contentsSpoofInReason ? `${reason} /Contents <${"0".repeat(contentsLength)}>` : reason
        ),
        Contents: PDFHexString.of("0".repeat(contentsLength)),
        ByteRange: context.obj([0, 111111111111, 111111111111, 111111111111]),
    });
    const signatureRef = directSignatureValue ? undefined : context.register(signature);
    const child = PDFDict.withContext(context);
    const childRef = context.register(child);
    const parent = context.obj({
        FT: PDFName.of("Sig"),
        T: PDFString.of("Parent"),
        Kids: context.obj([childRef]),
    });
    const parentRef = context.register(parent);
    child.set(PDFName.of("T"), PDFString.of("Timestamp"));
    child.set(PDFName.of("Parent"), parentRef);
    child.set(PDFName.of("V"), signatureRef ?? signature);
    if (includeWidget) {
        const widget = context.obj({
            Type: PDFName.of("Annot"),
            Subtype: PDFName.of("Widget"),
            Parent: childRef,
        });
        child.set(PDFName.of("Kids"), context.obj([context.register(widget)]));
    }
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: context.obj([parentRef]) }));

    const unsigned = await document.save({ useObjectStreams: false });
    const text = new TextDecoder("latin1").decode(unsigned);
    const contentsKey = text.lastIndexOf("/Contents");
    const contentsStart = text.indexOf("<", contentsKey);
    const contentsEnd = text.indexOf(">", contentsStart);
    if (contentsKey < 0 || contentsStart < 0 || contentsEnd < 0) {
        throw new Error("Nested fixture has no Contents placeholder");
    }
    const spoofContentsKey = contentsSpoofInReason ? text.indexOf("/Contents <") : -1;
    const spoofContentsStart = spoofContentsKey < 0 ? -1 : text.indexOf("<", spoofContentsKey);
    const spoofContentsEnd = spoofContentsStart < 0 ? -1 : text.indexOf(">", spoofContentsStart);
    if (contentsSpoofInReason && (spoofContentsStart < 0 || spoofContentsEnd < 0)) {
        throw new Error("Nested fixture has no literal Contents spoof");
    }
    const excludedStart = contentsSpoofInReason ? spoofContentsStart : contentsStart;
    const excludedEnd = contentsSpoofInReason ? spoofContentsEnd : contentsEnd;
    const byteRange: [number, number, number, number] = [
        0,
        excludedStart,
        excludedEnd + 1,
        unsigned.length - (excludedEnd + 1),
    ];
    return {
        bytes: replaceByteRange(unsigned, byteRange),
        byteRange,
        contentsOffset: contentsStart + 1,
        contentsLength,
        ...(contentsSpoofInReason && { spoofContentsOffset: spoofContentsStart + 1 }),
    };
}

async function createSignedNestedTimestampPdf(
    includeWidget = false,
    directSignatureValue = false,
    reason = "endobj",
    contentsSpoofInReason = false
): Promise<Uint8Array> {
    const prepared = await createNestedPreparedPdf(
        includeWidget,
        directSignatureValue,
        reason,
        contentsSpoofInReason
    );
    const { request } = await createTimestampRequest(coveredBytes(prepared.bytes, prepared.byteRange), {
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    const tokenHex = Array.from(fixture.rawToken, (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (tokenHex.length > prepared.contentsLength) throw new Error("Fixture token does not fit");
    const result = new Uint8Array(prepared.bytes);
    result.set(new TextEncoder().encode(tokenHex.toUpperCase()), prepared.contentsOffset);
    if (prepared.spoofContentsOffset !== undefined) {
        result.set(new TextEncoder().encode(tokenHex.toUpperCase()), prepared.spoofContentsOffset);
    }
    return result;
}

function appendBytes(left: Uint8Array, right: Uint8Array): Uint8Array {
    const result = new Uint8Array(left.length + right.length);
    result.set(left, 0);
    result.set(right, left.length);
    return result;
}

function signatureObjectReference(pdf: Uint8Array): { objectNumber: number; generationNumber: number } {
    const text = new TextDecoder("latin1").decode(pdf);
    const typeStart = text.lastIndexOf("/Type /DocTimeStamp");
    const objectKeyword = typeStart < 0 ? -1 : text.lastIndexOf(" obj", typeStart);
    const lineStart = objectKeyword < 0 ? -1 : text.lastIndexOf("\n", objectKeyword) + 1;
    const parts =
        lineStart < 0 || objectKeyword < 0
            ? []
            : text.slice(lineStart, objectKeyword).trim().split(" ");
    const objectNumber = Number(parts[0]);
    const generationNumber = Number(parts[1]);
    if (!Number.isSafeInteger(objectNumber) || !Number.isSafeInteger(generationNumber)) {
        throw new Error("Nested fixture has no signature object reference");
    }
    return { objectNumber, generationNumber };
}

function rewriteFinalStartXref(pdf: Uint8Array): Uint8Array {
    const result = new Uint8Array(pdf);
    const text = new TextDecoder("latin1").decode(result);
    const marker = text.lastIndexOf("startxref");
    const valueStart = marker < 0 ? -1 : text.indexOf("\n", marker) + 1;
    const valueEnd = valueStart < 0 ? -1 : text.indexOf("\n", valueStart);
    const xrefStart = marker < 0 ? -1 : text.lastIndexOf("\nxref\n", marker) + 1;
    if (valueStart < 0 || valueEnd < 0 || xrefStart < 0) {
        throw new Error("Nested fixture has no final startxref");
    }
    const replacement = String(xrefStart);
    if (replacement.length > valueEnd - valueStart) {
        throw new Error("Nested fixture startxref field is too small");
    }
    result.set(
        new TextEncoder().encode(replacement.padEnd(valueEnd - valueStart, " ")),
        valueStart
    );
    return result;
}

function withCommentObjectHeaderBeforeContents(pdf: Uint8Array): Uint8Array {
    const text = new TextDecoder("latin1").decode(pdf);
    const contentsKey = text.lastIndexOf("/Contents");
    const contentsStart = contentsKey < 0 ? -1 : text.indexOf("<", contentsKey);
    const contentsEnd = contentsStart < 0 ? -1 : text.indexOf(">", contentsStart);
    if (contentsKey < 0 || contentsStart < 0 || contentsEnd < 0) {
        throw new Error("Nested fixture has no Contents value");
    }
    const comment = new TextEncoder().encode("% 999 0 obj\n");
    const withComment = new Uint8Array(pdf.length + comment.length);
    withComment.set(pdf.subarray(0, contentsKey), 0);
    withComment.set(comment, contentsKey);
    withComment.set(pdf.subarray(contentsKey), contentsKey + comment.length);
    const shiftedStart = contentsStart + comment.length;
    const shiftedEnd = contentsEnd + comment.length;
    const withRange = replaceByteRange(withComment, [
        0,
        shiftedStart,
        shiftedEnd + 1,
        withComment.length - (shiftedEnd + 1),
    ]);
    return rewriteFinalStartXref(withRange);
}

function appendIncrementalSection(pdf: Uint8Array, body: string): Uint8Array {
    const text = new TextDecoder("latin1").decode(pdf);
    const marker = text.lastIndexOf("startxref");
    const valueStart = marker < 0 ? -1 : text.indexOf("\n", marker) + 1;
    const valueEnd = valueStart < 0 ? -1 : text.indexOf("\n", valueStart);
    const previousXref = Number(text.slice(valueStart, valueEnd).trim());
    if (!Number.isSafeInteger(previousXref) || previousXref < 0) {
        throw new Error("Nested fixture has no final startxref offset");
    }
    const bodyBytes = new TextEncoder().encode(`\n${body}\n`);
    const xrefOffset = pdf.length + bodyBytes.length;
    const trailer = new TextEncoder().encode(
        `xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 100 /Prev ${String(previousXref)} >>\nstartxref\n${String(
            xrefOffset
        )}\n%%EOF\n`
    );
    return appendBytes(appendBytes(pdf, bodyBytes), trailer);
}

function byteRangeText(pdf: Uint8Array): string {
    const text = new TextDecoder("latin1").decode(pdf);
    const start = text.lastIndexOf("/ByteRange");
    const end = start < 0 ? -1 : text.indexOf("]", start);
    if (start < 0 || end < 0) throw new Error("Nested fixture has no ByteRange text");
    return text.slice(start, end + 1);
}

function contentsHexText(pdf: Uint8Array): string {
    const text = new TextDecoder("latin1").decode(pdf);
    const key = text.lastIndexOf("/Contents");
    const start = key < 0 ? -1 : text.indexOf("<", key);
    const end = start < 0 ? -1 : text.indexOf(">", start);
    if (start < 0 || end < 0) throw new Error("Nested fixture has no Contents hex text");
    return text.slice(start + 1, end);
}

describe("nested RFC 3161 document timestamp fields", () => {
    it("collects and verifies a nested timestamp using inherited /FT and a qualified name", async () => {
        const pdf = await createSignedNestedTimestampPdf();

        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]).toMatchObject({ fieldName: "Parent.Timestamp" });
        await expect(
            verifyTimestamp(extracted[0]!, { pdf, strictESSValidation: true })
        ).resolves.toMatchObject({ verified: true });

        await expect(discoverArchiveTimestamps(pdf)).resolves.toMatchObject({
            timestamps: [expect.objectContaining({ fieldName: "Parent.Timestamp" })],
            malformedFieldNames: [],
        });
    });

    it("does not report an unnamed widget as a second inherited timestamp field", async () => {
        const pdf = await createSignedNestedTimestampPdf(true);

        await expect(extractTimestamps(pdf)).resolves.toMatchObject([
            { fieldName: "Parent.Timestamp" },
        ]);
    });

    it("binds a direct nested signature value to its containing field object", async () => {
        const pdf = await createSignedNestedTimestampPdf(false, true);

        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        expect(extracted[0]?.contentsObject).toBeDefined();
        await expect(
            verifyTimestamp(extracted[0]!, { pdf, strictESSValidation: true })
        ).resolves.toMatchObject({ verified: true });
    });

    it("does not mistake a literal object header for the signature object", async () => {
        const pdf = await createSignedNestedTimestampPdf(false, false, "999 0 obj");

        const extracted = await extractTimestamps(pdf);
        expect(extracted).toHaveLength(1);
        await expect(
            verifyTimestamp(extracted[0]!, { pdf, strictESSValidation: true })
        ).resolves.toMatchObject({ verified: true });
    });

    it("skips nested escaped literal syntax while locating the signature object", async () => {
        const pdf = await createSignedNestedTimestampPdf(
            false,
            false,
            "outer (nested \\(escaped\\) 999 0 obj)"
        );

        await expect(extractTimestamps(pdf)).resolves.toHaveLength(1);
    });

    it("rejects a ByteRange that targets a /Contents-looking literal string", async () => {
        const pdf = await createSignedNestedTimestampPdf(false, false, "metadata", true);

        await expect(extractTimestamps(pdf)).resolves.toEqual([]);
    });

    it("skips a fake object header in a comment before the selected Contents", async () => {
        const pdf = withCommentObjectHeaderBeforeContents(await createSignedNestedTimestampPdf());

        await expect(extractTimestamps(pdf)).resolves.toHaveLength(1);
    });

    it("skips a fake signature header embedded in a later stream payload", async () => {
        const pdf = await createSignedNestedTimestampPdf();
        const reference = signatureObjectReference(pdf);
        const payload = `${reference.objectNumber.toString()} ${reference.generationNumber.toString()} obj\n<< /Contents <00> >>\nendobj`;
        const appended = appendIncrementalSection(
            pdf,
            `99 0 obj\n<< /Length ${String(payload.length)} >>\nstream\n${payload}\nendstream\nendobj`
        );

        await expect(extractTimestamps(appended)).resolves.toHaveLength(1);
    });

    it("rejects an earlier gap when the selected indirect signature is redefined later", async () => {
        const pdf = await createSignedNestedTimestampPdf();
        const reference = signatureObjectReference(pdf);
        const redefined = appendIncrementalSection(
            pdf,
            `${reference.objectNumber.toString()} ${reference.generationNumber.toString()} obj\n<< /Type /DocTimeStamp /SubFilter /ETSI.RFC3161 /Contents <${contentsHexText(
                pdf
            )}> ${byteRangeText(pdf)} >>\nendobj`
        );

        await expect(extractTimestamps(redefined)).resolves.toEqual([]);
    });
});
