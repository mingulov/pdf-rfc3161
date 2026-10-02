import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
    PDFArray,
    PDFDict,
    PDFDocument,
    PDFHexString,
    PDFName,
    PDFRef,
    PDFString,
} from "pdf-lib-incremental-save";
import { timestampPdf } from "pdf-rfc3161";
import { extractTimestamps, verifyPdfTimestamps } from "../../../core/src/pdf/extract.js";
import { preparePdfForTimestamp } from "../../../core/src/pdf/prepare.js";
import { TimestampError, TimestampErrorCode } from "../../../core/src/types.js";
import { createRFC3161TokenFixture } from "../fixtures/rfc3161-token.js";
import { stubTsaFetch, makeInput } from "../utils/timestamp-fixtures.js";

const warnSpy = vi.fn();
vi.mock("../../../core/src/utils/logger.js", async (importOriginal: <T = unknown>() => Promise<T>) => {
    const mod = await importOriginal<typeof import("../../../core/src/utils/logger.js")>();
    return {
        ...mod,
        getLogger: () => ({
            debug: vi.fn(),
            info: vi.fn(),
            warn: warnSpy,
            error: vi.fn(),
        }),
    };
});

// Audit L1: the prior "forwards options" test only asserted
// `typeof === "function"` and `.length === 1` -- a tautology that would
// have passed for any function shape, including `async () => []`. This
// rewrite exercises the actual call path so a future refactor that drops
// `...options` or `pdf: pdfBytes` is caught.
//
// Limitation: verifyPdfTimestamps lives in the same module as the
// functions it delegates to (extractTimestamps, verifyTimestamp). In ESM,
// intra-module function references are captured in the closure, so
// vi.mock cannot intercept the delegated calls. Deeper "spy on
// verifyTimestamp call args" tests would require either a DI refactor or
// a real signed-PDF fixture (neither exists today). Until then we
// exercise what we can via the real path.

describe("verifyPdfTimestamps", () => {
    let pdfBytes: Uint8Array;

    beforeEach(async () => {
        const doc = await PDFDocument.create();
        doc.addPage([100, 100]);
        pdfBytes = await doc.save();
    });

    it("returns empty array for a PDF with no timestamps", async () => {
        const result = await verifyPdfTimestamps(pdfBytes);
        expect(result).toEqual([]);
    });

    it("accepts and threads extract-side options (ignoreEncryption: true)", async () => {
        // Smoke test for option-spread. If `...options` were dropped from
        // the inner extractTimestamps call, this would still pass (the PDF
        // isn't encrypted), but it catches the case where the entire
        // options object is dropped or thrown out.
        const result = await verifyPdfTimestamps(pdfBytes, { ignoreEncryption: true });
        expect(result).toEqual([]);
    });

    it("accepts and threads verify-side options (requireTimestampingEKU: false)", async () => {
        // Same shape -- exercises the verify-side branch of the spread. A
        // PDF without timestamps short-circuits before verifyTimestamp is
        // called, so this is bounded; it still catches a "drop options
        // before the verify spread" regression.
        const result = await verifyPdfTimestamps(pdfBytes, { requireTimestampingEKU: false });
        expect(result).toEqual([]);
    });

    it("rejects on garbage PDF bytes with TimestampError", async () => {
        // The audit risk includes "...options drops error propagation". A
        // real PDF_ERROR throw confirms the function does NOT silently
        // return [] on malformed input.
        await expect(
            verifyPdfTimestamps(new Uint8Array([0xde, 0xad, 0xbe, 0xef]))
        ).rejects.toThrow(TimestampError);
    });

    it("preserves Promise.all rejection semantics on inner failure", async () => {
        // If any timestamp's verifyTimestamp rejects, the wrapped Promise.all
        // must reject too (i.e., the wrapper does not swallow). We can't
        // trigger this without a fixture that yields >=1 timestamp; the
        // returned shape on the empty path is the dual assertion.
        const result = await verifyPdfTimestamps(pdfBytes);
        expect(Array.isArray(result)).toBe(true);
    });
});

let cachedTokenHexPromise: Promise<string> | undefined;

function cachedTokenHex(): Promise<string> {
    cachedTokenHexPromise ??= createRFC3161TokenFixture().then((fixture) =>
        Array.from(fixture.rawToken, (byte) => byte.toString(16).padStart(2, "0")).join("")
    );
    return cachedTokenHexPromise;
}

function coverContentsWithByteRange(pdf: Uint8Array): Uint8Array {
    const result = new Uint8Array(pdf);
    const text = new TextDecoder("latin1").decode(result);
    const contentsKey = text.lastIndexOf("/Contents");
    if (contentsKey < 0) throw new Error("Test PDF has no Contents key");
    const contentsStart = text.indexOf("<", contentsKey);
    const contentsEnd = text.indexOf(">", contentsStart);
    if (contentsStart < 0 || contentsEnd < 0) throw new Error("Test PDF has no Contents hex string");

    const byteRangeStart = text.lastIndexOf("/ByteRange");
    const byteRangeEnd = text.indexOf("]", byteRangeStart);
    if (byteRangeStart < 0 || byteRangeEnd < 0) throw new Error("Test PDF has no ByteRange");
    const replacement = `/ByteRange [0 ${String(contentsStart)} ${String(contentsEnd + 1)} ${String(
        result.length - (contentsEnd + 1)
    )}]`;
    const originalLength = byteRangeEnd + 1 - byteRangeStart;
    if (replacement.length > originalLength) throw new Error("Test ByteRange placeholder is too small");
    result.set(new TextEncoder().encode(replacement.padEnd(originalLength, " ")), byteRangeStart);
    return result;
}

async function metadataTimestampPdf(
    entries: Record<string, PDFString | PDFHexString | PDFName>
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = PDFDict.withContext(context);
    signature.set(PDFName.of("Type"), PDFName.of("DocTimeStamp"));
    signature.set(PDFName.of("SubFilter"), PDFName.of("ETSI.RFC3161"));
    signature.set(PDFName.of("Contents"), PDFHexString.of(await cachedTokenHex()));
    signature.set(
        PDFName.of("ByteRange"),
        context.obj([0, 111111111111, 111111111111, 111111111111])
    );
    for (const [name, value] of Object.entries(entries)) {
        signature.set(PDFName.of(name), value);
    }
    const signatureRef = context.register(signature);
    const field = PDFDict.withContext(context);
    field.set(PDFName.of("FT"), PDFName.of("Sig"));
    field.set(PDFName.of("T"), PDFString.of("MetadataTimestamp"));
    field.set(PDFName.of("V"), signatureRef);
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return coverContentsWithByteRange(await document.save({ useObjectStreams: false }));
}

function asciiHex(text: string): string {
    return Array.from(new TextEncoder().encode(text), (byte) =>
        byte.toString(16).padStart(2, "0")
    ).join("");
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

describe("extractTimestamps signature metadata decoding (T10 S5)", () => {
    it("unescapes parentheses in literal metadata strings", async () => {
        const [timestamp] = await extractTimestamps(
            await metadataTimestampPdf({ Reason: PDFString.of("Approve (final) release") })
        );

        expect(timestamp?.reason).toBe("Approve (final) release");
    });

    it("decodes UTF-16BE literal metadata strings", async () => {
        // Length-preserving octal injection: the placeholder serializes as
        // 16 raw bytes, replaced by the UTF-16BE BOM plus "Hi" without
        // shifting any cross-reference offset.
        const placeholder = await metadataTimestampPdf({ Reason: PDFString.of("X".repeat(14)) });
        const text = new TextDecoder("latin1").decode(placeholder);
        const literal = text.indexOf("(XXXXXXXXXXXXXX)");
        if (literal < 0) throw new Error("Test PDF is missing its Reason placeholder");
        const injected = `${text.slice(0, literal)}(\\376\\377\\0H\\0i)${text.slice(literal + 16)}`;
        const [timestamp] = await extractTimestamps(
            coverContentsWithByteRange(latin1Bytes(injected))
        );

        expect(timestamp?.reason).toBe("Hi");
    });

    it("decodes PDFDocEncoding bytes in literal metadata strings", async () => {
        // Octal 205 is the en dash in PDFDocEncoding; raw latin1 would show a
        // control character instead.
        const placeholder = await metadataTimestampPdf({ Reason: PDFString.of("123456") });
        const text = new TextDecoder("latin1").decode(placeholder);
        const literal = text.indexOf("(123456)");
        if (literal < 0) throw new Error("Test PDF is missing its Reason placeholder");
        const injected = `${text.slice(0, literal)}(a\\205b)${text.slice(literal + 8)}`;
        const [timestamp] = await extractTimestamps(
            coverContentsWithByteRange(latin1Bytes(injected))
        );

        expect(timestamp?.reason).toBe("a\u2013b");
    });

    it("decodes hex metadata strings as text instead of hex digits", async () => {
        const [timestamp] = await extractTimestamps(
            await metadataTimestampPdf({ Location: PDFHexString.of(asciiHex("Hello")) })
        );

        expect(timestamp?.location).toBe("Hello");
    });

    it("decodes UTF-16BE hex metadata strings", async () => {
        const [timestamp] = await extractTimestamps(
            await metadataTimestampPdf({ ContactInfo: PDFHexString.of("FEFF00480069") })
        );

        expect(timestamp?.contactInfo).toBe("Hi");
    });

    it("parses a hex modification time", async () => {
        const [timestamp] = await extractTimestamps(
            await metadataTimestampPdf({
                M: PDFHexString.of(asciiHex("D:20240102030405+00'00'")),
            })
        );

        expect(timestamp?.m?.toISOString()).toBe("2024-01-02T03:04:05.000Z");
    });

    it("keeps plain literal metadata and literal modification times working", async () => {
        const [timestamp] = await extractTimestamps(
            await metadataTimestampPdf({
                Reason: PDFString.of("Reviewed"),
                M: PDFString.of("D:20240102030405+00'00'"),
            })
        );

        expect(timestamp?.reason).toBe("Reviewed");
        expect(timestamp?.m?.toISOString()).toBe("2024-01-02T03:04:05.000Z");
    });

    it("keeps non-string metadata values as their raw representation", async () => {
        const [timestamp] = await extractTimestamps(
            await metadataTimestampPdf({ Reason: PDFName.of("Reviewed") })
        );

        expect(timestamp?.reason).toBe("/Reviewed");
    });
});

async function invalidTokenTimestampPdf(): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const signature = PDFDict.withContext(context);
    signature.set(PDFName.of("Type"), PDFName.of("DocTimeStamp"));
    signature.set(PDFName.of("SubFilter"), PDFName.of("ETSI.RFC3161"));
    signature.set(PDFName.of("Contents"), PDFHexString.of("3001"));
    signature.set(PDFName.of("ByteRange"), context.obj([0, 0, 0, 0]));
    const signatureRef = context.register(signature);
    const field = PDFDict.withContext(context);
    field.set(PDFName.of("FT"), PDFName.of("Sig"));
    field.set(PDFName.of("T"), PDFString.of("MalformedTimestamp"));
    field.set(PDFName.of("V"), signatureRef);
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save({ useObjectStreams: false });
}

type MissingSignatureValueVariant = "dangling-reference" | "missing" | "non-dictionary";

async function markerFieldWithoutValuePdf(
    variant: MissingSignatureValueVariant,
    fieldName: string
): Promise<Uint8Array> {
    const document = await PDFDocument.create();
    document.addPage([100, 100]);
    const context = document.context;
    const field = PDFDict.withContext(context);
    field.set(PDFName.of("FT"), PDFName.of("Sig"));
    field.set(PDFName.of("T"), PDFString.of(fieldName));
    field.set(PDFName.of("Type"), PDFName.of("DocTimeStamp"));
    field.set(PDFName.of("SubFilter"), PDFName.of("ETSI.RFC3161"));
    if (variant === "dangling-reference") {
        // Object 700 is never registered: a dangling indirect /V.
        field.set(PDFName.of("V"), PDFRef.of(700, 0));
    } else if (variant === "non-dictionary") {
        field.set(PDFName.of("V"), PDFString.of("not-a-signature-dictionary"));
    }
    const fields = PDFArray.withContext(context);
    fields.push(context.register(field));
    document.catalog.set(PDFName.of("AcroForm"), context.obj({ Fields: fields }));
    return document.save({ useObjectStreams: false });
}

describe("public discovery malformed-field visibility (T10 S20)", () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });

    it("warns naming skipped malformed fields from extractTimestamps without changing its return type", async () => {
        const result = await extractTimestamps(await invalidTokenTimestampPdf());

        expect(result).toEqual([]);
        expect(Array.isArray(result)).toBe(true);
        expect(warnSpy).toHaveBeenCalledTimes(1);
        expect(warnSpy).toHaveBeenCalledWith(
            expect.stringContaining("MalformedTimestamp")
        );
    });

    it("warns naming skipped malformed fields from verifyPdfTimestamps", async () => {
        const result = await verifyPdfTimestamps(await invalidTokenTimestampPdf());

        expect(result).toEqual([]);
        expect(warnSpy).toHaveBeenCalledTimes(1);
        expect(warnSpy).toHaveBeenCalledWith(
            expect.stringContaining("MalformedTimestamp")
        );
    });

    it.each([
        { variant: "dangling-reference", fieldName: "NamedBroken" },
        { variant: "missing", fieldName: "MissingValue" },
        { variant: "non-dictionary", fieldName: "NonDictionaryValue" },
    ] as const)(
        "warns naming a $variant /V field ($fieldName) from both public paths",
        async ({ variant, fieldName }: { variant: MissingSignatureValueVariant; fieldName: string }) => {
            const pdf = await markerFieldWithoutValuePdf(variant, fieldName);

            const extracted = await extractTimestamps(pdf);
            expect(extracted).toEqual([]);
            expect(Array.isArray(extracted)).toBe(true);
            expect(warnSpy).toHaveBeenCalledTimes(1);
            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(fieldName));

            vi.clearAllMocks();
            const verified = await verifyPdfTimestamps(pdf);
            expect(verified).toEqual([]);
            expect(warnSpy).toHaveBeenCalledTimes(1);
            expect(warnSpy).toHaveBeenCalledWith(expect.stringContaining(fieldName));
        }
    );

    it("stays silent for clean PDFs and unsigned placeholders", async () => {
        const document = await PDFDocument.create();
        document.addPage([100, 100]);
        const clean = await document.save({ useObjectStreams: false });
        const placeholder = (await preparePdfForTimestamp(clean)).bytes;

        await expect(extractTimestamps(clean)).resolves.toEqual([]);
        await expect(extractTimestamps(placeholder)).resolves.toEqual([]);
        await expect(verifyPdfTimestamps(clean)).resolves.toEqual([]);
        expect(warnSpy).not.toHaveBeenCalled();
    });
});

describe("earlier signature downstream verification (T10 C04)", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
    });

    it.each([true, false])(
        "verifies every signature after a second timestamp on multi-page %s xref input",
        async (useObjectStreams: boolean) => {
            stubTsaFetch();
            const input = await makeInput(useObjectStreams);
            const first = await timestampPdf({
                pdf: input,
                tsa: { url: "https://tsa.example.test", retry: 0 },
            });
            const second = await timestampPdf({
                pdf: first.pdf,
                tsa: { url: "https://tsa.example.test", retry: 0 },
            });

            expect(second.pdf.subarray(0, first.pdf.length)).toEqual(first.pdf);
            const verified = await verifyPdfTimestamps(second.pdf);
            expect(verified).toHaveLength(2);
            expect(verified.map((value) => value.fieldName)).toEqual([
                "Timestamp",
                "Timestamp_2",
            ]);
            expect(verified.map((value) => value.verified)).toEqual([true, true]);
            const earlier = verified[0];
            const later = verified[1];
            if (earlier === undefined || later === undefined) {
                throw new Error("Earlier timestamp is missing");
            }
            // timestampPdf enables LTV by default, so each output ends with
            // a DSS revision its own signature does not cover; both still
            // verify against their own revision boundaries.
            expect(earlier.coversWholeDocument).toBe(false);
            expect(earlier.byteRange[2] + earlier.byteRange[3]).toBeLessThanOrEqual(
                first.pdf.length
            );
            expect(later.coversWholeDocument).toBe(false);
            expect(later.byteRange[2] + later.byteRange[3]).toBeGreaterThan(first.pdf.length);
            expect(later.byteRange[2] + later.byteRange[3]).toBeGreaterThan(
                earlier.byteRange[2] + earlier.byteRange[3]
            );

            const tampered = new Uint8Array(second.pdf);
            tampered[10] = (tampered[10] ?? 0) ^ 0xff;
            const tamperedVerified = await verifyPdfTimestamps(tampered);
            expect(tamperedVerified.map((value) => value.verified)).toEqual([false, false]);
            expect(tamperedVerified[0]?.verificationError).toContain("Document hash mismatch");
            expect(tamperedVerified[0]?.verificationErrorCode).toBe(
                TimestampErrorCode.VERIFICATION_FAILED
            );
        }
    );
});
