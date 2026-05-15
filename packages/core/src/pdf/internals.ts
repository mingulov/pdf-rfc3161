// Internal helpers for working around pdf-lib-incremental-save quirks.
// Not part of the public API.

interface PDFContextInternal {
    largestObjectNumber: number;
}

/**
 * Scans the raw PDF bytes for object headers (`N G obj`) and forces
 * `context.largestObjectNumber` to at least that maximum. pdf-lib-incremental-save
 * does not always recover the highest object number from a PDF that has been
 * through prior incremental updates, which would corrupt subsequent updates
 * by reusing object IDs. Bounded regex quantifiers prevent ReDoS.
 */
export function restoreLargestObjectNumber(
    pdfBytes: Uint8Array,
    context: { largestObjectNumber: number }
): void {
    const pdfString = new TextDecoder("latin1").decode(pdfBytes);
    const objMatches = pdfString.matchAll(/(\d{1,20})\s{1,100}\d{1,20}\s{1,100}obj/g);
    let maxObjNum = context.largestObjectNumber;
    for (const match of objMatches) {
        const objNum = parseInt(match[1] ?? "0", 10);
        if (objNum > maxObjNum) {
            maxObjNum = objNum;
        }
    }
    (context as unknown as PDFContextInternal).largestObjectNumber = maxObjNum;
}
