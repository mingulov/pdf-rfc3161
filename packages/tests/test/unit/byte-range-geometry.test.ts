import { describe, expect, it, vi } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { embedTimestampToken } from "../../../core/src/pdf/embed.js";
import {
    extractTimestamps,
    verifyPdfTimestamps,
    verifyTimestamp,
    verifyTimestampsWithSharedIndex,
    type ExtractedTimestamp,
} from "../../../core/src/pdf/extract.js";
import { preparePdfForTimestamp, type PreparedPDF } from "../../../core/src/pdf/prepare.js";
import { MAX_BATCH_TIMESTAMP_VERIFICATION_BYTES } from "../../../core/src/constants.js";
import { createTimestampRequest } from "../../../core/src/tsa/index.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";
import {
    qpdfLinearizedBasePdf,
    type LinearizedTerminalTarget,
} from "../fixtures/qpdf-linearized-base.js";
import * as tokenValidation from "../../../core/src/tsa/token-validation.js";

type ByteRange = [number, number, number, number];

const SIGNED_MALFORMED_RANGES: [string, ByteRange][] = [
    ["a nonzero first offset", [1, 2, 3, 4]],
    ["overlapping ranges", [0, 4, 0, 0]],
];

const INVALID_NUMBER_RANGES: [string, ByteRange][] = [
    ["a fractional value", [0, 1.5, 2, 3]],
    ["an unsafe integer", [0, Number.MAX_SAFE_INTEGER + 1, 2, 3]],
];

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

function bytesCoveredByRange(
    pdf: Uint8Array,
    [offset1, length1, offset2, length2]: ByteRange
): Uint8Array {
    const result = new Uint8Array(length1 + length2);
    result.set(pdf.subarray(offset1, offset1 + length1), 0);
    result.set(pdf.subarray(offset2, offset2 + length2), length1);
    return result;
}

function withByteRange(
    prepared: PreparedPDF,
    byteRange: ByteRange,
    serializedValues: readonly string[] = byteRange.map(String)
): PreparedPDF {
    const bytes = new Uint8Array(prepared.bytes);
    const text = new TextDecoder("latin1").decode(bytes);
    const start = text.lastIndexOf("/ByteRange[");
    if (start < 0) throw new Error("Prepared PDF has no ByteRange");
    const end = text.indexOf("]", start);
    if (end < 0) throw new Error("Prepared PDF has an unterminated ByteRange");

    let reservedEnd = end + 1;
    while (text[reservedEnd] === " ") reservedEnd += 1;
    const originalLength = reservedEnd - start;
    const replacement = `/ByteRange[${serializedValues.join(" ")}]`;
    if (replacement.length > originalLength) {
        throw new Error("Test ByteRange does not fit the prepared placeholder");
    }
    bytes.set(new TextEncoder().encode(replacement.padEnd(originalLength, " ")), start);
    return { ...prepared, bytes, byteRange };
}

async function signedPdfForRange(
    byteRange?: ByteRange
): Promise<{ pdf: Uint8Array; token: Uint8Array; timestamp: ExtractedTimestamp }> {
    const original = await preparePdfForTimestamp(minimalPdf(), { signatureSize: 4096 });
    const prepared = byteRange === undefined ? original : withByteRange(original, byteRange);
    const { request } = await createTimestampRequest(bytesCoveredByRange(prepared.bytes, prepared.byteRange), {
        hashAlgorithm: "SHA-256",
        requestCertificate: true,
    });
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    const pdf = embedTimestampToken(prepared, fixture.rawToken);
    const [timestamp] = await extractTimestamps(
        byteRange === undefined ? pdf : embedTimestampToken(original, fixture.rawToken)
    );
    if (!timestamp) throw new Error("Reference timestamp was not extracted");
    return { pdf, token: fixture.rawToken, timestamp };
}

async function relabeledEarlierTimestampPdf(): Promise<Uint8Array> {
    const first = await signedPdfForRange();
    const appendedPrepared = await preparePdfForTimestamp(first.pdf, { signatureSize: 4096 });
    const appended = embedTimestampToken(appendedPrepared, first.token);
    return withByteRange(
        {
            bytes: appended,
            byteRange: appendedPrepared.byteRange,
            contentsOffset: appendedPrepared.contentsOffset,
            contentsPlaceholderLength: appendedPrepared.contentsPlaceholderLength,
        },
        first.timestamp.byteRange
    ).bytes;
}

async function timestampedObjectStreamInputPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const input = await document.save({ useObjectStreams: true });
    const prepared = await preparePdfForTimestamp(input, { signatureSize: 4096 });
    const { request } = await createTimestampRequest(
        bytesCoveredByRange(prepared.bytes, prepared.byteRange),
        { hashAlgorithm: "SHA-256", requestCertificate: true }
    );
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    return embedTimestampToken(prepared, fixture.rawToken);
}

async function timestampedLinearizedBasePdf(
    terminalTarget: LinearizedTerminalTarget
): Promise<Uint8Array> {
    const prepared = await preparePdfForTimestamp(qpdfLinearizedBasePdf(terminalTarget), {
        signatureSize: 4096,
    });
    return embedFixtureTimestamp(prepared);
}

async function embedFixtureTimestamp(prepared: PreparedPDF): Promise<Uint8Array> {
    const { request } = await createTimestampRequest(
        bytesCoveredByRange(prepared.bytes, prepared.byteRange),
        { hashAlgorithm: "SHA-256", requestCertificate: true }
    );
    const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
    return embedTimestampToken(prepared, fixture.rawToken);
}

async function chainedTimestampPdf(count: number): Promise<Uint8Array> {
    let pdf = minimalPdf();
    for (let index = 0; index < count; index += 1) {
        const prepared = await preparePdfForTimestamp(pdf, { signatureSize: 4096 });
        const { request } = await createTimestampRequest(
            bytesCoveredByRange(prepared.bytes, prepared.byteRange),
            { hashAlgorithm: "SHA-256", requestCertificate: true }
        );
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
        pdf = embedTimestampToken(prepared, fixture.rawToken);
    }
    return pdf;
}

function tamperCoveredWhitespace(pdf: Uint8Array, timestamp: ExtractedTimestamp): Uint8Array {
    const tampered = new Uint8Array(pdf);
    for (const [offset, length] of [
        [timestamp.byteRange[0], timestamp.byteRange[1]],
        [timestamp.byteRange[2], timestamp.byteRange[3]],
    ] as const) {
        for (let index = offset; index < offset + length; index += 1) {
            if (tampered[index] === 0x0a) {
                tampered[index] = 0x0d;
                return tampered;
            }
        }
    }
    throw new Error("Reference PDF has no covered newline to tamper");
}

function appendPdfBytes(pdf: Uint8Array, suffix: string): Uint8Array {
    const suffixBytes = new TextEncoder().encode(suffix);
    const result = new Uint8Array(pdf.length + suffixBytes.length);
    result.set(pdf);
    result.set(suffixBytes, pdf.length);
    return result;
}

function terminalStartXrefOffset(pdf: Uint8Array): number {
    const text = new TextDecoder("latin1").decode(pdf);
    const marker = text.lastIndexOf("startxref");
    if (marker < 0) throw new Error("Reference PDF has no startxref marker");
    const offset = Number.parseInt(text.slice(marker + "startxref".length), 10);
    if (!Number.isSafeInteger(offset) || offset < 0) {
        throw new Error("Reference PDF has an invalid startxref offset");
    }
    return offset;
}

describe("RFC 3161 PDF ByteRange geometry", () => {
    it.each(SIGNED_MALFORMED_RANGES)(
        "rejects %s even when its timestamp token was signed for that range",
        async (_: string, range: ByteRange) => {
            const reference = await signedPdfForRange();
            const malformed = await signedPdfForRange(range);
            const forgedTimestamp: ExtractedTimestamp = {
                ...reference.timestamp,
                token: malformed.token,
                byteRange: range,
            };

            await expect(extractTimestamps(malformed.pdf)).resolves.toEqual([]);
            await expect(verifyTimestamp(forgedTimestamp, { pdf: malformed.pdf })).resolves.toMatchObject({
                verified: false,
            });
        }
    );

    it("rejects an otherwise valid token whose gap omits the Contents delimiters", async () => {
        const reference = await signedPdfForRange();
        const [offset1, length1, offset2, length2] = reference.timestamp.byteRange;
        const malformedRange: [number, number, number, number] = [
            offset1,
            length1 + 1,
            offset2 - 1,
            length2 + 1,
        ];
        const malformed = await signedPdfForRange(malformedRange);

        await expect(extractTimestamps(malformed.pdf)).resolves.toEqual([]);
    });

    it.each(INVALID_NUMBER_RANGES)("rejects a ByteRange with %s", async (_: string, range: ByteRange) => {
        const reference = await signedPdfForRange();
        const malformed = withByteRange(
            {
                bytes: reference.pdf,
                byteRange: reference.timestamp.byteRange,
                contentsOffset: 0,
                contentsPlaceholderLength: 0,
            },
            range
        );

        await expect(extractTimestamps(malformed.bytes)).resolves.toEqual([]);
    });

    it("accepts a valid ByteRange rendered with optional plus signs", async () => {
        const prepared = await preparePdfForTimestamp(minimalPdf(), { signatureSize: 4096 });
        const signedRange = withByteRange(
            prepared,
            prepared.byteRange,
            prepared.byteRange.map((value) => `+${value.toString()}`)
        );
        const { request } = await createTimestampRequest(
            bytesCoveredByRange(signedRange.bytes, signedRange.byteRange),
            { hashAlgorithm: "SHA-256", requestCertificate: true }
        );
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });

        await expect(extractTimestamps(embedTimestampToken(signedRange, fixture.rawToken))).resolves.toHaveLength(
            1
        );
    });

    it("accepts loader-equivalent negative zero in a valid ByteRange", async () => {
        const prepared = await preparePdfForTimestamp(minimalPdf(), { signatureSize: 4096 });
        const signedRange = withByteRange(
            prepared,
            prepared.byteRange,
            ["-0", ...prepared.byteRange.slice(1).map((value) => `+${value.toString()}`)]
        );
        const { request } = await createTimestampRequest(
            bytesCoveredByRange(signedRange.bytes, signedRange.byteRange),
            { hashAlgorithm: "SHA-256", requestCertificate: true }
        );
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });

        await expect(extractTimestamps(embedTimestampToken(signedRange, fixture.rawToken))).resolves.toHaveLength(
            1
        );
    });

    it("keeps a valid timestamp from an earlier incremental revision", async () => {
        const first = await signedPdfForRange();
        const secondPrepared = await preparePdfForTimestamp(first.pdf, { signatureSize: 4096 });
        const { request } = await createTimestampRequest(
            bytesCoveredByRange(secondPrepared.bytes, secondPrepared.byteRange),
            { hashAlgorithm: "SHA-256", requestCertificate: true }
        );
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "raw" });
        const chained = embedTimestampToken(secondPrepared, fixture.rawToken);

        const extracted = await extractTimestamps(chained);
        expect(extracted).toHaveLength(2);
        await expect(verifyPdfTimestamps(chained, { strictESSValidation: true })).resolves.toEqual(
            expect.arrayContaining([expect.objectContaining({ verified: true })])
        );
    });

    it("bounds CMS verification concurrency for distinct timestamp values", async () => {
        const pdf = await chainedTimestampPdf(4);
        const original = tokenValidation.verifyTimestampCmsSignature;
        let active = 0;
        let peak = 0;
        const verifyCms = vi
            .spyOn(tokenValidation, "verifyTimestampCmsSignature")
            .mockImplementation(
                async (...args: Parameters<typeof tokenValidation.verifyTimestampCmsSignature>) => {
                active += 1;
                peak = Math.max(peak, active);
                await new Promise<void>((resolve) => setTimeout(resolve, 5));
                try {
                    return await original(...args);
                } finally {
                    active -= 1;
                }
                }
            );

        try {
            const verified = await verifyPdfTimestamps(pdf, { strictESSValidation: true });

            expect(verified).toHaveLength(4);
            expect(verified.every((timestamp) => timestamp.verified)).toBe(true);
            expect(peak).toBe(1);
        } finally {
            verifyCms.mockRestore();
        }
    });

    it("bounds aggregate covered-byte work for distinct timestamp values", async () => {
        const pdf = await chainedTimestampPdf(2);
        const timestamps = await extractTimestamps(pdf);
        const first = timestamps[0];
        const second = timestamps[1];
        if (first === undefined || second === undefined) throw new Error("Fixture has too few timestamps");
        const tooExpensive: ExtractedTimestamp = {
            ...second,
            byteRange: [
                0,
                MAX_BATCH_TIMESTAMP_VERIFICATION_BYTES,
                MAX_BATCH_TIMESTAMP_VERIFICATION_BYTES + 1,
                0,
            ],
        };
        const verifyCms = vi.spyOn(tokenValidation, "verifyTimestampCmsSignature");

        try {
            const verified = await verifyTimestampsWithSharedIndex(
                [first, tooExpensive],
                { pdf, strictESSValidation: true }
            );

            expect(verified).toHaveLength(2);
            expect(verified[0]).toMatchObject({ fieldName: first.fieldName, verified: true });
            expect(verified[1]).toMatchObject({
                fieldName: second.fieldName,
                verified: false,
                verificationError: "Timestamp verification work budget exhausted",
            });
            // The second distinct value is refused before its geometry check,
            // PDF slice/hash, or CMS parse. The first one is the sole CMS run.
            expect(verifyCms).toHaveBeenCalledTimes(1);
        } finally {
            verifyCms.mockRestore();
        }
    });

    it("keeps an xref-stream source PDF timestamped in a classic incremental revision", async () => {
        await expect(extractTimestamps(await timestampedObjectStreamInputPdf())).resolves.toHaveLength(1);
    });

    it.each(["early", "main"] as const)(
        "extracts and verifies two timestamps appended to a qpdf-linearized base with a %s terminal xref",
        async (terminalTarget: LinearizedTerminalTarget) => {
            const first = await timestampedLinearizedBasePdf(terminalTarget);
            const second = await embedFixtureTimestamp(
                await preparePdfForTimestamp(first, { signatureSize: 4096 })
            );

            await expect(extractTimestamps(second)).resolves.toHaveLength(2);
            await expect(verifyPdfTimestamps(second, { strictESSValidation: true })).resolves.toEqual([
                expect.objectContaining({ verified: true }),
                expect.objectContaining({ verified: true }),
            ]);
        }
    );

    it("rejects an appended field that relabels an earlier field's excluded Contents token", async () => {
        const relabeled = await relabeledEarlierTimestampPdf();

        await expect(extractTimestamps(relabeled)).resolves.toHaveLength(1);
    });

    it("requires the final revision to end at a lexical EOF, allowing only trailing whitespace", async () => {
        const reference = await signedPdfForRange();
        const whitespaceOnly = appendPdfBytes(reference.pdf, " \n\t");
        const trailingGarbage = appendPdfBytes(reference.pdf, "\nnot-a-pdf-revision");

        await expect(extractTimestamps(whitespaceOnly)).resolves.toHaveLength(1);
        await expect(extractTimestamps(trailingGarbage)).resolves.toEqual([]);
        await expect(verifyTimestamp(reference.timestamp, { pdf: trailingGarbage })).resolves.toMatchObject({
            verified: false,
        });
    });

    it("rejects a forged terminal startxref that points back to an earlier xref", async () => {
        const reference = await signedPdfForRange();
        const forged = appendPdfBytes(
            reference.pdf,
            `\nstartxref\n${terminalStartXrefOffset(reference.pdf).toString()}\n%%EOF`
        );

        await expect(extractTimestamps(forged)).resolves.toEqual([]);
        await expect(verifyTimestamp(reference.timestamp, { pdf: forged })).resolves.toMatchObject({
            verified: false,
        });
    });

    it("never lets options.pdf replace the PDF argument", async () => {
        const valid = await signedPdfForRange();
        const tampered = tamperCoveredWhitespace(valid.pdf, valid.timestamp);

        await expect(
            verifyPdfTimestamps(tampered, { pdf: valid.pdf } as never)
        ).resolves.toEqual([expect.objectContaining({ verified: false })]);
    });
});
