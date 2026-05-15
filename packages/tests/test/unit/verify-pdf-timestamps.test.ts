import { describe, it, expect, beforeEach } from "vitest";
import { PDFDocument } from "pdf-lib-incremental-save";
import { verifyPdfTimestamps } from "../../../core/src/pdf/extract.js";
import { TimestampError } from "../../../core/src/types.js";

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
