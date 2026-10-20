import { describe, it, expect } from "vitest";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFNumber,
    PDFString,
} from "pdf-lib-incremental-save";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

async function blankPdf(): Promise<Uint8Array> {
    const doc = await PDFDocument.create();
    doc.addPage();
    return await doc.save();
}

describe("PDF string sanitization (L5)", () => {
    it("accepts a reasonable reason string", async () => {
        const pdf = await blankPdf();
        await expect(
            preparePdfForTimestamp(pdf, { reason: "Document approval" })
        ).resolves.toBeDefined();
    });

    it("rejects reason longer than the cap", async () => {
        const pdf = await blankPdf();
        const tooLong = "x".repeat(2049);
        await expect(preparePdfForTimestamp(pdf, { reason: tooLong })).rejects.toThrow(
            TimestampError
        );
        try {
            await preparePdfForTimestamp(pdf, { reason: tooLong });
        } catch (e) {
            expect((e as TimestampError).code).toBe(TimestampErrorCode.PDF_ERROR);
            expect((e as TimestampError).message).toMatch(/maximum length/);
        }
    });

    it("rejects location containing embedded NUL", async () => {
        const pdf = await blankPdf();
        await expect(preparePdfForTimestamp(pdf, { location: "Berlin\x00Office" })).rejects.toThrow(
            /NUL character/
        );
    });

    it("rejects contactInfo containing embedded NUL", async () => {
        const pdf = await blankPdf();
        await expect(
            preparePdfForTimestamp(pdf, { contactInfo: "support@example.com\x00leaked" })
        ).rejects.toThrow(/NUL character/);
    });

    it("accepts empty string (treats as 'no value')", async () => {
        const pdf = await blankPdf();
        // Empty string falls through the `value === undefined` check below but
        // sanitizePdfString accepts it -- caller intent is "set to empty".
        await expect(preparePdfForTimestamp(pdf, { reason: "" })).resolves.toBeDefined();
    });
});

describe.each([false, true])("PDF text round trips (object streams: %s)", (useObjectStreams) => {
    const textFields = [
        ["reason", "Reason"],
        ["location", "Location"],
        ["contactInfo", "ContactInfo"],
        ["signatureFieldName", "T"],
    ] as const;
    const texts = [
        ["unmatched parentheses", "Approved ) (draft"],
        ["trailing backslash", "C:\\new\\test\\"],
        ["control characters", "first\r\nsecond\tthird"],
        ["Unicode", "\u041f\u0440\u0438\u0432\u0435\u0442 \u4e16\u754c \ud83d\ude80"],
        ["PDF-looking text", "text) /Type /Sig /ByteRange [0 1 2 3] /T (changed"],
    ] as const;

    for (const [option, key] of textFields) {
        it.each(texts)(`preserves ${option} containing %s`, async (_label, text) => {
            const document = await PDFDocument.create();
            document.addPage();
            const input = await document.save({ useObjectStreams });
            const prepared = await preparePdfForTimestamp(input, { [option]: text });
            const output = await PDFDocument.load(prepared.bytes, { updateMetadata: false });
            const acroForm = output.catalog.lookup(PDFName.of("AcroForm"), PDFDict);
            const fields = acroForm.lookup(PDFName.of("Fields"), PDFArray);
            const field = fields.lookup(0, PDFDict);
            const signature = field.lookup(PDFName.of("V"), PDFDict);
            const owner = option === "signatureFieldName" ? field : signature;
            const value = owner.get(PDFName.of(key));
            expect(value instanceof PDFString || value instanceof PDFHexString).toBe(true);
            if (!(value instanceof PDFString) && !(value instanceof PDFHexString)) {
                throw new Error("Prepared text is not a PDF string");
            }
            expect(value.decodeText()).toBe(text);
            expect(signature.get(PDFName.of("Type"))?.toString()).toBe("/DocTimeStamp");
            expect(field.get(PDFName.of("FT"))?.toString()).toBe("/Sig");
            const range = signature.lookup(PDFName.of("ByteRange"), PDFArray);
            expect(range.asArray().map((item) => (item as PDFNumber).asNumber())).toEqual(
                prepared.byteRange
            );
            expect(prepared.bytes.subarray(0, input.length)).toEqual(input);
        });
    }
});

describe("Signature field name limits", () => {
    it("rejects a name exceeding the text length cap", async () => {
        await expect(
            preparePdfForTimestamp(await blankPdf(), { signatureFieldName: "x".repeat(2049) })
        ).rejects.toThrow(/maximum length/);
    });

    it("rejects a name containing an embedded NUL", async () => {
        await expect(
            preparePdfForTimestamp(await blankPdf(), { signatureFieldName: "name\x00suffix" })
        ).rejects.toThrow(/NUL character/);
    });
});
