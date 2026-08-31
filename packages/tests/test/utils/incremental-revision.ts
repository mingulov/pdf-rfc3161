import { lastStartxrefOffset } from "./xref-format.js";

const decoder = new TextDecoder("latin1");

function rootReference(bytes: Uint8Array): string {
    const match = /\/Root\s{1,4}(\d{1,6})\s{1,4}(\d{1,6})\s{1,4}R/.exec(decoder.decode(bytes));
    if (!match) throw new Error("No /Root reference in the test PDF");
    return `/Root ${String(match[1])} ${String(match[2])} R`;
}

function trailerSize(bytes: Uint8Array): number {
    const sizes = [...decoder.decode(bytes).matchAll(/\/Size\s{1,4}(\d{1,9})/g)];
    const last = sizes.at(-1)?.[1];
    if (last === undefined) throw new Error("No /Size entry in the test PDF");
    return Number(last);
}

/**
 * Appends one minimal classic-xref-table revision carrying a single no-op
 * object, with `/Prev` pointing at the input's terminal startxref offset.
 *
 * Two suites share this builder, for opposite reasons:
 *
 *   - Over a cross-reference-stream input it reproduces the pre-fix failure
 *     mode by hand -- a classic table whose /Prev points into a stream, the
 *     shape CoreGraphics (macOS Preview / Quick Look) refuses to open. That
 *     makes it the strict-reader oracle's negative control.
 *   - The same bytes are also the cheapest way to build a hybrid-history
 *     input: a document that already carries both cross-reference formats
 *     across its revisions, for the xref-format regression net.
 *
 * The revision is structurally well formed apart from the /Prev format
 * mismatch: the object is separated from the previous `%%EOF` by an EOL, the
 * xref entry records the object's real offset, and startxref records the
 * table's real offset. Without that leading EOL the appended object header
 * would abut `%%EOF`, which the project's own signature occurrence index
 * rejects as an unframed revision -- an unrelated defect that would mask what
 * either suite is trying to observe.
 */
export function appendClassicTableRevision(input: Uint8Array): Uint8Array {
    const previous = lastStartxrefOffset(input);
    const root = rootReference(input);
    const objectNumber = trailerSize(input);
    const body = `\n${String(objectNumber)} 0 obj\n<< /Type /PdfRfc3161Marker >>\nendobj\n`;
    const objectOffset = input.length + 1;
    const tableOffset = input.length + body.length;
    const table =
        [
            "xref",
            "0 1",
            "0000000000 65535 f ",
            `${String(objectNumber)} 1`,
            `${String(objectOffset).padStart(10, "0")} 00000 n `,
            "trailer",
            `<< /Size ${String(objectNumber + 1)} ${root} /Prev ${String(previous)} >>`,
            "startxref",
            String(tableOffset),
        ].join("\n") + "\n%%EOF";
    // The appended section is pure ASCII, so UTF-8 encoding is byte-identical
    // to the latin1 offsets the table above records.
    const appended = new TextEncoder().encode(body + table);
    const output = new Uint8Array(input.length + appended.length);
    output.set(input);
    output.set(appended, input.length);
    return output;
}
