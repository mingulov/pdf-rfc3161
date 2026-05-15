import { describe, it, expect } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
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
        await expect(preparePdfForTimestamp(pdf, { reason: "Document approval" })).resolves
            .toBeDefined();
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
        await expect(
            preparePdfForTimestamp(pdf, { location: "Berlin\x00Office" })
        ).rejects.toThrow(/NUL character/);
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
