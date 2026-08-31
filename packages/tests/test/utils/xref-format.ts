// One implementation of "which cross-reference format does this revision
// use?", shared by every suite that asks. It used to exist three times: the
// unit-level format net, the incremental-revision builder, and a hand-copied
// literal inside the packed-consumer's generated check script -- three copies
// of a classifier whose whole job is to pin the PR#63 regression.

export type XrefFormat = "table" | "stream" | "unknown";

export interface XrefSection {
    /** Byte offset the section's `startxref` points at. */
    offset: number;
    format: XrefFormat;
}

/**
 * Returns one entry per %%EOF-terminated revision: "table" when the section's
 * startxref offset points at a classic `xref` keyword, "stream" when it points
 * at an `N G obj` header (cross-reference stream), "unknown" otherwise -- for
 * example a physically linearized file's first-page section, which records the
 * `startxref 0` "no earlier revision" sentinel.
 *
 * Kept free of module-level references on purpose: `test-packed-consumer.ts`
 * emits this function into a generated ES module with `String(...)`, so it must
 * stand on its own. `lastXrefFormat` is emitted next to it and may call it by
 * name.
 */
export function xrefSections(bytes: Uint8Array): XrefSection[] {
    const text = new TextDecoder("latin1").decode(bytes);
    const sections: XrefSection[] = [];
    // Bounded quantifiers: this only ever scans trusted test output, but the
    // project-wide unsafe-regex rule applies to every regex in the repository.
    for (const match of text.matchAll(/startxref\s{1,4}(\d{1,12})\s{1,4}%%EOF/g)) {
        const offset = Number(match[1]);
        const target = text.slice(offset, offset + 32);
        const format: XrefFormat = target.startsWith("xref")
            ? "table"
            : /^\d{1,12} \d{1,6} obj/.test(target)
              ? "stream"
              : "unknown";
        sections.push({ offset, format });
    }
    return sections;
}

/**
 * The format of the section the file's LAST startxref points at -- the revision
 * an incremental update chains to, and therefore the format it has to match.
 * Throws rather than reporting "unknown", because every caller uses it as an
 * assertion about a file it expects to be well formed.
 *
 * Emitted into the packed-consumer's generated script alongside
 * `xrefSections`; keep both self-contained.
 */
export function lastXrefFormat(bytes: Uint8Array): "table" | "stream" {
    const last = xrefSections(bytes).at(-1);
    if (last === undefined) {
        throw new Error("PDF has no startxref/%%EOF pair");
    }
    if (last.format === "unknown") {
        throw new Error("PDF ends with an unrecognizable cross-reference section");
    }
    return last.format;
}

/**
 * One label per revision, in file order. An unrecognizable section is reported
 * as `unknown@<offset>` so a failing assertion names the offset it could not
 * classify.
 */
export function xrefSectionFormats(bytes: Uint8Array): string[] {
    return xrefSections(bytes).map((section) =>
        section.format === "unknown" ? `unknown@${String(section.offset)}` : section.format
    );
}

/** Byte offset recorded by the file's terminal `startxref`. */
export function lastStartxrefOffset(bytes: Uint8Array): number {
    const last = xrefSections(bytes).at(-1);
    if (last === undefined) throw new Error("No startxref/%%EOF pair in the test PDF");
    return last.offset;
}
