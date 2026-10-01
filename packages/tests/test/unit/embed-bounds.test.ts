import { describe, expect, it } from "vitest";
import { embedTimestampToken, PlaceholderTooSmallError } from "../../../core/src/pdf/embed.js";
import { preparePdfForTimestamp, type PreparedPDF } from "../../../core/src/pdf/prepare.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";

function minimalPdf(): Uint8Array {
    return new TextEncoder().encode(`%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << >> >>
endobj
xref
0 4
0000000000 65535 f${" "}
0000000009 00000 n${" "}
0000000058 00000 n${" "}
0000000115 00000 n${" "}
trailer
<< /Size 4 /Root 1 0 R >>
startxref
203
%%EOF`);
}

async function realPrepared(): Promise<PreparedPDF> {
    return preparePdfForTimestamp(minimalPdf(), { signatureSize: 1024 });
}

function expectPdfError(fn: () => unknown, messagePart?: string): void {
    try {
        fn();
    } catch (error) {
        expect(error).toBeInstanceOf(TimestampError);
        expect((error as TimestampError).code).toBe(TimestampErrorCode.PDF_ERROR);
        if (messagePart !== undefined) {
            expect((error as TimestampError).message).toContain(messagePart);
        }
        return;
    }
    expect.unreachable("expected TimestampError(PDF_ERROR)");
}

describe("embedTimestampToken bounds (R3)", () => {
    it.each([
        ["negative", -1],
        ["fractional", 10.5],
        ["NaN", Number.NaN],
        ["Infinity", Number.POSITIVE_INFINITY],
        ["unsafe integer", Number.MAX_SAFE_INTEGER + 1],
        ["past the end", -2],
    ])("rejects %s contentsOffset with PDF_ERROR", async (_label: string, offset: number) => {
        const prepared = await realPrepared();
        const contentsOffset = offset === -2 ? prepared.bytes.length + 1 : offset;
        expectPdfError(() =>
            embedTimestampToken({ ...prepared, contentsOffset }, new Uint8Array([1]))
        );
    });

    it.each([
        ["negative", -2],
        ["fractional", 10.5],
        ["NaN", Number.NaN],
        ["Infinity", Number.POSITIVE_INFINITY],
        ["odd", 11],
        ["past the end", -2],
    ])(
        "rejects %s contentsPlaceholderLength with PDF_ERROR",
        async (_label: string, length: number) => {
            const prepared = await realPrepared();
            const contentsPlaceholderLength =
                length === -2 ? prepared.bytes.length - prepared.contentsOffset + 1 : length;
            expectPdfError(() =>
                embedTimestampToken({ ...prepared, contentsPlaceholderLength }, new Uint8Array([1]))
            );
        }
    );

    it("rejects a reservation window running past the end of the PDF", async () => {
        const prepared = await realPrepared();
        expectPdfError(() =>
            embedTimestampToken(
                { ...prepared, contentsOffset: prepared.bytes.length - 4 },
                new Uint8Array([1])
            )
        );
    });

    it("rejects a missing opening Contents delimiter", async () => {
        const prepared = await realPrepared();
        const bytes = new Uint8Array(prepared.bytes);
        bytes[prepared.contentsOffset - 1] = 0x20;
        expectPdfError(
            () => embedTimestampToken({ ...prepared, bytes }, new Uint8Array([1])),
            "delimiter"
        );
    });

    it("rejects a missing closing Contents delimiter", async () => {
        const prepared = await realPrepared();
        const bytes = new Uint8Array(prepared.bytes);
        bytes[prepared.contentsOffset + prepared.contentsPlaceholderLength] = 0x20;
        expectPdfError(
            () => embedTimestampToken({ ...prepared, bytes }, new Uint8Array([1])),
            "delimiter"
        );
    });

    it("rejects a byteRange whose hole disagrees with the reservation window", async () => {
        const prepared = await realPrepared();
        const byteRange: [number, number, number, number] = [
            prepared.byteRange[0],
            prepared.byteRange[1] + 1,
            prepared.byteRange[2],
            prepared.byteRange[3],
        ];
        expectPdfError(
            () => embedTimestampToken({ ...prepared, byteRange }, new Uint8Array([1])),
            "ByteRange"
        );
    });

    it("rejects a non-safe-integer byteRange with PDF_ERROR", async () => {
        const prepared = await realPrepared();
        const byteRange = [0, 1.5, 2, 3] as unknown as [number, number, number, number];
        expectPdfError(() => embedTimestampToken({ ...prepared, byteRange }, new Uint8Array([1])));
    });

    it("keeps PDF_ERROR compatibility when the token exceeds the reservation", async () => {
        const prepared = await realPrepared();
        try {
            embedTimestampToken(prepared, new Uint8Array(2048));
        } catch (error) {
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as TimestampError).code).toBe(TimestampErrorCode.PDF_ERROR);
            expect((error as TimestampError).message).toContain("Increase signatureSize");
            return;
        }
        expect.unreachable("expected the oversized token to be rejected");
    });

    it("throws PlaceholderTooSmallError with the required size for oversized tokens", async () => {
        const prepared = await realPrepared();
        const token = new Uint8Array(2048);
        try {
            embedTimestampToken(prepared, token);
        } catch (error) {
            expect(error).toBeInstanceOf(PlaceholderTooSmallError);
            expect(error).toBeInstanceOf(TimestampError);
            expect((error as PlaceholderTooSmallError).code).toBe(TimestampErrorCode.PDF_ERROR);
            expect((error as PlaceholderTooSmallError).requiredSignatureSize).toBe(
                Math.ceil(token.length * 1.1)
            );
            expect((error as Error).message).toContain("Increase signatureSize");
            return;
        }
        expect.unreachable("expected PlaceholderTooSmallError");
    });

    it("still embeds a fitting token into a genuine prepared PDF", async () => {
        const prepared = await realPrepared();
        const token = Uint8Array.of(0xde, 0xad, 0xbe, 0xef);
        const embedded = embedTimestampToken(prepared, token);
        expect(embedded.length).toBe(prepared.bytes.length);
        const text = new TextDecoder("latin1").decode(
            embedded.subarray(prepared.contentsOffset, prepared.contentsOffset + 8)
        );
        expect(text).toBe("DEADBEEF");
    });
});
