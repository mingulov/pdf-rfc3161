import { PDFRef } from "pdf-lib-incremental-save";
import {
    extractTimestamps,
    timestampPdf,
    timestampPdfMultiple,
    TimestampErrorCode,
    TimestampSession,
} from "pdf-rfc3161";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
    assertIncrementalWriterHeadroom,
    MAX_SUPPORTED_OBJECT_NUMBER,
} from "../../../core/src/pdf/internals.js";
import { qpdfLinearizedBasePdf } from "../fixtures/qpdf-linearized-base.js";
import { createRFC3161TokenFixtureFromRequest } from "../fixtures/rfc3161-token.js";
import { appendClassicTableRevision } from "../utils/incremental-revision.js";
import { makeInput, stubTsaFetch } from "../utils/timestamp-fixtures.js";
import { xrefSectionFormats } from "../utils/xref-format.js";

// PR#63 regression: incremental updates must use the same cross-reference
// format as the input PDF. CoreGraphics (macOS Preview/Quick Look) refuses a
// classic xref table whose /Prev points into a cross-reference stream, so an
// xref-stream input must receive xref-stream updates, and a classic-table
// input must keep classic-table updates.

afterEach(() => {
    vi.unstubAllGlobals();
});

const decoder = new TextDecoder("latin1");

describe("incremental xref format matches the input PDF", () => {
    it("appends xref streams to an xref-stream input (no LTV)", async () => {
        stubTsaFetch();
        const input = await makeInput(true);
        expect(xrefSectionFormats(input)).toEqual(["stream"]);

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: false,
        });

        expect(xrefSectionFormats(result.pdf)).toEqual(["stream", "stream"]);
    });

    it("appends xref streams to an xref-stream input (LTV)", async () => {
        stubTsaFetch();
        const input = await makeInput(true);

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        expect(result.ltvData?.certificates).toHaveLength(1);
        expect(xrefSectionFormats(result.pdf)).toEqual(["stream", "stream", "stream"]);
    });

    it("keeps classic xref tables for a classic-table input (LTV)", async () => {
        stubTsaFetch();
        const input = await makeInput(false);
        expect(xrefSectionFormats(input)).toEqual(["table"]);

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        expect(xrefSectionFormats(result.pdf)).toEqual(["table", "table", "table"]);
    });

    it("appends xref streams through the step-by-step TimestampSession (LTV)", async () => {
        // The session is the public step-by-step API; timestampPdf drives one
        // internally today, so this pins the contract rather than a second
        // implementation -- a future session-specific save path cannot drift
        // away from format matching unnoticed.
        const input = await makeInput(true);
        const session = new TimestampSession(input, { enableLTV: true });
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "response" });
        const output = await session.embedTimestampToken(fixture.response);

        // prepare -> placeholder revision, embed -> in place, DSS -> LTV revision.
        expect(xrefSectionFormats(output)).toEqual(["stream", "stream", "stream"]);
        await expect(extractTimestamps(output)).resolves.toHaveLength(1);
    });

    it("appends xref streams through the step-by-step TimestampSession (no LTV)", async () => {
        const input = await makeInput(true);
        const session = new TimestampSession(input, { enableLTV: false });
        const request = await session.createTimestampRequest();
        const fixture = await createRFC3161TokenFixtureFromRequest(request, { form: "response" });
        const output = await session.embedTimestampToken(fixture.response);

        expect(xrefSectionFormats(output)).toEqual(["stream", "stream"]);
        await expect(extractTimestamps(output)).resolves.toHaveLength(1);
    });

    it("appends xref streams for every TSA of timestampPdfMultiple", async () => {
        stubTsaFetch();
        const result = await timestampPdfMultiple({
            pdf: await makeInput(true),
            tsaList: [
                { url: "https://timestamp-a.example.test", retry: 0 },
                { url: "https://timestamp-b.example.test", retry: 0 },
            ],
            enableLTV: false,
        });

        expect(result.timestamps).toHaveLength(2);
        // One appended revision per TSA, on top of the input's own section.
        expect(xrefSectionFormats(result.pdf)).toEqual(["stream", "stream", "stream"]);
        await expect(extractTimestamps(result.pdf)).resolves.toHaveLength(2);
    });

    it("keeps classic xref tables for a qpdf-linearized input (LTV)", async () => {
        stubTsaFetch();
        const input = qpdfLinearizedBasePdf();
        // A linearized base ends its first-page section with `startxref 0`,
        // the "no earlier revision" sentinel, so that section has no xref at
        // the recorded offset; its main section is an ordinary classic table.
        // Physical linearization must not make the format sniffing guess
        // "stream" for a file that contains no cross-reference stream at all.
        expect(xrefSectionFormats(input)).toEqual(["unknown@0", "table"]);

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        expect(xrefSectionFormats(result.pdf)).toEqual(["unknown@0", "table", "table", "table"]);
        await expect(extractTimestamps(result.pdf)).resolves.toHaveLength(1);
    });

    it("appends a classic table when the input's last revision is a classic table", async () => {
        stubTsaFetch();
        // An input that already carries both formats across its revisions:
        // an xref-stream base with a classic-table revision appended.
        const input = appendClassicTableRevision(await makeInput(true));
        expect(xrefSectionFormats(input)).toEqual(["stream", "table"]);

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: false,
        });

        // The update chains to the LAST revision, so it must use that
        // revision's cross-reference format. pdf-lib's own
        // pdfFileDetails.useObjectStreams flag is set by ANY xref stream
        // anywhere in the file, which would append a stream whose /Prev
        // points at a classic table -- a shape CoreGraphics and Ghostscript
        // both refuse to open. See docs/pdf-lib-incremental-save-limitations.md.
        expect(xrefSectionFormats(result.pdf)).toEqual(["stream", "table", "table"]);
        await expect(extractTimestamps(result.pdf)).resolves.toHaveLength(1);
    });

    it("keeps the /DocTimeStamp signature dictionary out of object streams", async () => {
        stubTsaFetch();
        const input = await makeInput(true);

        const result = await timestampPdf({
            pdf: input,
            tsa: { url: "https://timestamp.example.test", retry: 0 },
            enableLTV: true,
        });

        // The signature dictionary must stay a plain uncompressed object so the
        // /ByteRange//Contents bytes live at fixed file offsets.
        const text = decoder.decode(result.pdf);
        expect(text).toContain("/DocTimeStamp");
        expect(text).toContain("/ByteRange");

        // And the timestamp must still parse and cover the right bytes.
        const timestamps = await extractTimestamps(result.pdf);
        expect(timestamps).toHaveLength(1);
    });
});

describe("assertIncrementalWriterHeadroom", () => {
    function indirectObjectEntries(count: number): [PDFRef, unknown][] {
        return Array.from({ length: count }, (_unused, index): [PDFRef, unknown] => [
            PDFRef.of(index + 1),
            undefined,
        ]);
    }

    /**
     * Mirrors the shape the guard reads on a real PDFContext: the private
     * `indirectObjects` Map (its O(1) `.size`) plus the public enumeration.
     */
    function headroomContext(
        useObjectStreams: boolean,
        largestObjectNumber: number,
        objectCount = 2
    ) {
        const entries = indirectObjectEntries(objectCount);
        return {
            largestObjectNumber,
            pdfFileDetails: { useObjectStreams },
            indirectObjects: new Map<PDFRef, unknown>(entries),
            enumerateIndirectObjects: (): [PDFRef, unknown][] => entries,
        };
    }

    it("rejects an xref-stream save without room for the invented references", () => {
        expect(() =>
            assertIncrementalWriterHeadroom(headroomContext(true, Number.MAX_SAFE_INTEGER - 3))
        ).toThrow(expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR }));
    });

    it("accepts an xref-stream save with room for the invented references", () => {
        expect(() => assertIncrementalWriterHeadroom(headroomContext(true, 4))).not.toThrow();
    });

    it("reserves nothing for the classic writer, which invents no references", () => {
        expect(() =>
            assertIncrementalWriterHeadroom(headroomContext(false, Number.MAX_SAFE_INTEGER - 3))
        ).not.toThrow();
    });

    it("reserves one object-stream container per 50 objects, not one per object", () => {
        // PDFStreamWriter packs 50 compressed objects into each ObjStm, so 100
        // objects cost 2 container references plus 1 xref stream plus the /Size
        // written one past them: 4, not 102. Reserving one per object rejects
        // saves that both writers would complete safely.
        expect(() =>
            assertIncrementalWriterHeadroom(
                headroomContext(true, MAX_SUPPORTED_OBJECT_NUMBER - 50, 100)
            )
        ).not.toThrow();
    });

    it("still rejects a large-context save that genuinely overflows", () => {
        expect(() =>
            assertIncrementalWriterHeadroom(
                headroomContext(true, MAX_SUPPORTED_OBJECT_NUMBER - 3, 100)
            )
        ).toThrow(expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR }));
    });

    it("falls back to the public enumeration when no indirectObjects map is present", () => {
        // pdf-lib declares indirectObjects private, so the guard reads it
        // defensively; a future build that changes the shape must still get
        // the same bound from enumerateIndirectObjects().
        const entries = indirectObjectEntries(100);
        const context = {
            largestObjectNumber: MAX_SUPPORTED_OBJECT_NUMBER - 50,
            pdfFileDetails: { useObjectStreams: true },
            enumerateIndirectObjects: (): [PDFRef, unknown][] => entries,
        };
        expect(() => assertIncrementalWriterHeadroom(context)).not.toThrow();

        expect(() =>
            assertIncrementalWriterHeadroom({
                ...context,
                largestObjectNumber: MAX_SUPPORTED_OBJECT_NUMBER - 3,
            })
        ).toThrow(expect.objectContaining({ code: TimestampErrorCode.PDF_ERROR }));
    });
});
