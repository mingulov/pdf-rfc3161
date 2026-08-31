import { describe, expect, it } from "vitest";
import { applyLastRevisionXrefFormat } from "../../../core/src/pdf/internals.js";

// PR#63 follow-up: `applyLastRevisionXrefFormat` classifies the cross-reference
// section the file's TERMINAL `startxref` points at, and falls back to the
// classic table whenever the tail cannot be read with confidence. The
// end-to-end suites in `incremental-xref-format.test.ts` pin the two happy
// paths through real PDFs; this suite pins the fallback edges directly, so a
// future refactor that starts guessing instead of standing down fails here
// rather than on someone's macOS Preview.

const decoder = new TextDecoder("latin1");

function latin1(text: string): Uint8Array {
    const bytes = new Uint8Array(text.length);
    for (let index = 0; index < text.length; index += 1) {
        bytes[index] = text.charCodeAt(index) & 0xff;
    }
    return bytes;
}

/** Runs the sniffer over `bytes` from a known starting flag and reports the result. */
function sniff(bytes: Uint8Array, useObjectStreams: boolean): boolean {
    const context = { pdfFileDetails: { useObjectStreams } };
    applyLastRevisionXrefFormat(bytes, context);
    return context.pdfFileDetails.useObjectStreams;
}

/**
 * An unreadable tail must land on the classic table, whatever pdf-lib had
 * decided. Leaving the flag alone is not neutral: pdf-lib sets it for ANY
 * cross-reference stream anywhere in the file's history, so a hybrid-history
 * file (xref-stream base, classic-table last revision -- the shape v0.2.0
 * itself emitted) would receive a cross-reference STREAM over a classic TABLE.
 * That is the inverse of the shape this release removes and worse than v0.2.0,
 * which appended a table there. Clearing the flag reproduces v0.2.0 exactly for
 * this class, which is what makes "never worse than v0.2.0" a total guarantee.
 *
 * Both starting values are asserted: a one-sided check would pass against an
 * implementation that happened to leave the flag untouched.
 */
function expectStandsDownToTable(bytes: Uint8Array): void {
    expect(sniff(bytes, true)).toBe(false);
    expect(sniff(bytes, false)).toBe(false);
}

const HEAD = "%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 3 0 R >>\nendobj\n";
const TABLE_SECTION =
    "xref\n0 2\n0000000000 65535 f \n0000000009 00000 n \ntrailer\n<< /Size 2 >>\n";
const STREAM_SECTION =
    "2 0 obj\n<< /Type /XRef /Size 3 /W [1 2 1] >>\nstream\n\x01\x00\x09\x00\nendstream\nendobj\n";

/**
 * Builds `head + section + startxref/%%EOF`, where the recorded offset points
 * at the first byte of `section` unless `offsetText` overrides it. Everything
 * is ASCII, so string indices are byte offsets.
 */
function buildTail(head: string, section: string, offsetText?: string): Uint8Array {
    return latin1(`${head}${section}startxref\n${offsetText ?? String(head.length)}\n%%EOF\n`);
}

describe("applyLastRevisionXrefFormat classifies the last revision", () => {
    it("clears the flag for a classic table, even when it started set", () => {
        // The hybrid-history case the fix exists for: pdf-lib turns the flag on
        // for ANY xref stream anywhere in the file, but the update chains to the
        // last revision, which here is a classic table.
        const bytes = buildTail(HEAD, TABLE_SECTION);
        expect(decoder.decode(bytes.subarray(HEAD.length, HEAD.length + 4))).toBe("xref");

        expect(sniff(bytes, true)).toBe(false);
        expect(sniff(bytes, false)).toBe(false);
    });

    it("sets the flag for a cross-reference stream, including the false -> true flip", () => {
        // A cross-reference stream is an ordinary indirect object, so the probe
        // sees an `N G obj` header rather than the `xref` keyword.
        const bytes = buildTail(HEAD, STREAM_SECTION);
        expect(decoder.decode(bytes.subarray(HEAD.length, HEAD.length + 7))).toBe("2 0 obj");

        expect(sniff(bytes, false)).toBe(true);
        expect(sniff(bytes, true)).toBe(true);
    });

    it("takes the terminal startxref, not an earlier decoy inside a content stream", () => {
        // A content stream can carry the literal text `startxref <n>`. Here the
        // decoy points at a real `N G obj` header, so an implementation that
        // took the first match would answer "stream" for a file whose last
        // revision is a classic table.
        const decoy = (value: string): string =>
            `4 0 obj\n<< /Length 22 >>\nstream\nstartxref ${value}\nendstream\nendobj\n`;
        const probe = `%PDF-1.7\n${decoy("0000000")}9 0 obj\n<< /Type /XRef >>\nstream\nx\nendstream\nendobj\n`;
        const decoyTarget = probe.indexOf("9 0 obj");
        // Zero padding keeps the decoy the same length as the probe pass, so
        // the recomputed head places `9 0 obj` at exactly `decoyTarget`.
        const head = probe.replace("0000000", String(decoyTarget).padStart(7, "0"));
        const bytes = buildTail(head, TABLE_SECTION);

        expect(decoder.decode(bytes.subarray(decoyTarget, decoyTarget + 7))).toBe("9 0 obj");
        expect(decoder.decode(bytes.subarray(head.length, head.length + 4))).toBe("xref");

        expect(sniff(bytes, true)).toBe(false);
        expect(sniff(bytes, false)).toBe(false);
    });
});

describe("applyLastRevisionXrefFormat stands down when the tail is unreadable", () => {
    it("clears the flag for the linearized `startxref 0` sentinel", () => {
        // A physically linearized file records 0 as its "no earlier revision"
        // marker; offset 0 is the %PDF header, never a cross-reference section.
        expectStandsDownToTable(buildTail(HEAD, TABLE_SECTION, "0"));
    });

    it("clears the flag for an offset at or past the end of the file", () => {
        const beyond = buildTail(HEAD, TABLE_SECTION, "99999999");
        expect(beyond.length).toBeLessThan(99999999);
        expectStandsDownToTable(beyond);

        // And the boundary itself: an offset of exactly the file length has no
        // byte to read. Zero padding keeps both passes the same size.
        const probe = buildTail(HEAD, TABLE_SECTION, "0000000");
        const atEnd = buildTail(HEAD, TABLE_SECTION, String(probe.length).padStart(7, "0"));
        expect(atEnd.length).toBe(probe.length);
        expectStandsDownToTable(atEnd);
    });

    it("clears the flag when the offset lands on whitespace before the xref keyword", () => {
        // No whitespace skipping: a recorded offset that is off by a few bytes
        // is a broken file, not a licence to assume the neighbouring format.
        const head = `${HEAD}      \n`;
        const bytes = buildTail(head, TABLE_SECTION, String(HEAD.length));
        expect(decoder.decode(bytes.subarray(HEAD.length, HEAD.length + 3))).toBe("   ");
        expectStandsDownToTable(bytes);
    });

    it("clears the flag when the offset lands on binary garbage", () => {
        const garbage = "\x00\xff\x80\x01\xfe\x7f\x00\xff\x80\x01";
        const head = `${HEAD}${garbage}`;
        expectStandsDownToTable(buildTail(head, TABLE_SECTION, String(HEAD.length)));
    });

    it("clears the flag when the terminal startxref sits beyond the tail scan window", () => {
        // MAX_PDF_TAIL_SCAN is 2048 bytes; padding past it hides the trailer,
        // and no trailer means the classic-table fallback rather than a guess.
        // This is the case the strict-reader oracle exercises end to end: the
        // same padded hybrid-history file used to receive a cross-reference
        // stream over its classic-table last revision.
        const padded = latin1(`${"%".repeat(2500)}\n`);
        const tail = buildTail(HEAD, TABLE_SECTION);
        const bytes = new Uint8Array(tail.length + padded.length);
        bytes.set(tail, 0);
        bytes.set(padded, tail.length);

        expect(decoder.decode(bytes.subarray(bytes.length - 2048))).not.toContain("startxref");
        expectStandsDownToTable(bytes);
    });

    it("clears the flag, without throwing, when fewer than five bytes follow the offset", () => {
        // The probe needs a delimiter after `xref` to tell the keyword from a
        // longer token; a file that ends mid-keyword must not throw either.
        const lead = "%PDF-1.7\nstartxref\n";
        const offset = lead.length + "0000".length + 1;
        const bytes = latin1(`${lead}${String(offset).padStart(4, "0")}\nxref`);

        expect(decoder.decode(bytes.subarray(offset))).toBe("xref");
        expect(bytes.length - offset).toBe(4);
        expectStandsDownToTable(bytes);
    });

    it("clears the flag, without throwing, for a digit run past the 20-digit bound", () => {
        // A 24-digit offset overflows the safe-integer range; the bounded
        // quantifier truncates it, and the range check rejects what is left.
        const bytes = buildTail(HEAD, TABLE_SECTION, "123456789012345678901234");
        expectStandsDownToTable(bytes);
    });

    it("clears the flag, without throwing, for empty and non-PDF input", () => {
        expectStandsDownToTable(new Uint8Array(0));
        expectStandsDownToTable(latin1("not a pdf"));
        expectStandsDownToTable(latin1("startxref"));
    });
});
