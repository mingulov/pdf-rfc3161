import {
    PDFDocument,
    PDFDict,
    PDFName,
    PDFHexString,
    PDFArray,
    PDFNumber,
    PDFString,
    PDFRef,
    PDFObject,
} from "pdf-lib-incremental-save";
import { DEFAULT_SIGNATURE_SIZE } from "../constants.js";

/**
 * Result of preparing a PDF for timestamping.
 * Contains the PDF bytes with a placeholder for the signature,
 * and the byte ranges that will be signed.
 */
export interface PreparedPDF {
    /** PDF bytes with placeholder signature content */
    bytes: Uint8Array;
    /** Byte range [offset1, length1, offset2, length2] */
    byteRange: [number, number, number, number];
    /** Offset where the signature Contents hex string starts (after '<') */
    contentsOffset: number;
    /** Length of the placeholder (hex characters, not bytes) */
    contentsPlaceholderLength: number;
}

/**
 * Options for preparing a PDF for timestamping
 */
export interface PrepareOptions {
    /** Size to reserve for the timestamp token (default: 8192 bytes = 16384 hex chars) */
    signatureSize?: number;
    /** Optional reason for the timestamp */
    reason?: string;
    /** Optional location */
    location?: string;
    /** Optional contact info */
    contactInfo?: string;
    /** Optional name for the signature field (default: "Timestamp") */
    signatureFieldName?: string;
    /** Whether to omit the modification time (/M) from the signature dictionary */
    omitModificationTime?: boolean;
}

/**
 * Search window constants for ByteRange replacement.
 * These values ensure we find the correct ByteRange placeholder when
 * multiple signatures exist in a PDF.
 */

/**
 * Bytes to search backward from the dictionary start hint.
 * The hint points to the start of the signature dictionary (`<<`),
 * but the `/ByteRange` key might appear slightly before in edge cases
 * (e.g., whitespace or formatting variations). 100 bytes provides a
 * small safety margin without risking matching a previous signature.
 */
const BYTERANGE_SEARCH_BACKWARD = 100;

/**
 * Bytes to search forward from the dictionary start hint.
 * Must be large enough to cover:
 * - The entire signature dictionary structure (~1KB)
 * - The `/Contents` hex string which can be up to 65,536 hex chars (32KB token)
 * - Additional dictionary entries after `/Contents`
 * 100KB (102,400 bytes) provides ample headroom for the largest supported tokens.
 */
const BYTERANGE_SEARCH_FORWARD = 100 * 1024;

/**
 * Formats a Date object as a PDF date string (PDF spec Section 7.9.4).
 * Format: D:YYYYMMDDHHmmSS+HH'mm' or D:YYYYMMDDHHmmSS-HH'mm'
 * Uses UTC to avoid timezone ambiguity.
 *
 * @param date - The date to format
 * @returns PDF-formatted date string
 */
function formatPdfDate(date: Date): string {
    const pad = (n: number, len = 2) => String(n).padStart(len, "0");

    const year = date.getUTCFullYear();
    const month = pad(date.getUTCMonth() + 1);
    const day = pad(date.getUTCDate());
    const hours = pad(date.getUTCHours());
    const minutes = pad(date.getUTCMinutes());
    const seconds = pad(date.getUTCSeconds());

    // Use Z (UTC) timezone, represented as +00'00' in PDF format
    return `D:${String(year)}${month}${day}${hours}${minutes}${seconds}+00'00'`;
}

/**
 * Prepares a PDF for DocTimeStamp by adding a signature field with placeholder content.
 * Returns the prepared PDF and information needed to calculate the final ByteRange.
 *
 * @param pdfBytes - Original PDF bytes
 * @param options - Preparation options
 * @returns Prepared PDF with placeholder and byte range info
 */
export async function preparePdfForTimestamp(
    pdfBytes: Uint8Array,
    options: PrepareOptions = {}
): Promise<PreparedPDF> {
    const signatureSize =
        options.signatureSize && options.signatureSize > 0
            ? options.signatureSize
            : DEFAULT_SIGNATURE_SIZE;
    const placeholderHexLength = signatureSize * 2; // Each byte = 2 hex chars
    const signatureFieldName = options.signatureFieldName ?? "Timestamp";

    // Create placeholder content
    const placeholderHex = "0".repeat(placeholderHexLength);

    // Load the PDF document
    const sigPdfDoc = await PDFDocument.load(pdfBytes, { updateMetadata: false });

    // WORKAROUND: correctly track objects from input PDF.
    // Scan bytes to ensure largestObjectNumber matches the actual file content,
    // preserving the object numbering sequence for incremental updates.
    const sigContext = sigPdfDoc.context;
    const pdfString = new TextDecoder("latin1").decode(pdfBytes);
    const objMatches = pdfString.matchAll(/(\d{1,20})\s+\d{1,20}\s+obj/g);
    let maxObjNum = sigContext.largestObjectNumber;
    for (const match of objMatches) {
        const objNum = parseInt(match[1] ?? "0", 10);
        if (objNum > maxObjNum) {
            maxObjNum = objNum;
        }
    }
    // internal property of PDFContext needed for the workaround
    interface PDFContextInternal {
        largestObjectNumber: number;
    }

    const sigContextInternal = sigContext as unknown as PDFContextInternal;
    sigContextInternal.largestObjectNumber = maxObjNum;

    // Take snapshot before modifications
    const snapshot = sigPdfDoc.takeSnapshot();

    // Create new signature dictionary
    const sigDictFields: Record<string, PDFObject> = {
        Type: PDFName.of("Sig"),
        Filter: PDFName.of("Adobe.PPKLite"),
        SubFilter: PDFName.of("ETSI.RFC3161"),
        ByteRange: PDFArray.withContext(sigContext),
        Contents: PDFHexString.of(placeholderHex),
    };

    if (!options.omitModificationTime) {
        sigDictFields.M = PDFString.of(formatPdfDate(new Date()));
    }

    const newSigDict = sigContext.obj(sigDictFields);

    const newByteRangeArr = newSigDict.get(PDFName.of("ByteRange")) as PDFArray;
    newByteRangeArr.push(PDFNumber.of(0));
    newByteRangeArr.push(PDFNumber.of(111111111111));
    newByteRangeArr.push(PDFNumber.of(111111111111));
    newByteRangeArr.push(PDFNumber.of(111111111111));
    newByteRangeArr.push(PDFNumber.of(111111111111));
    newByteRangeArr.push(PDFNumber.of(111111111111));

    if (options.reason) {
        newSigDict.set(PDFName.of("Reason"), PDFString.of(options.reason));
    }
    if (options.location) {
        newSigDict.set(PDFName.of("Location"), PDFString.of(options.location));
    }
    if (options.contactInfo) {
        newSigDict.set(PDFName.of("ContactInfo"), PDFString.of(options.contactInfo));
    }

    const newSigRef = sigContext.register(newSigDict);

    // Get or create AcroForm
    let newAcroForm = sigPdfDoc.catalog.lookup(PDFName.of("AcroForm")) as PDFDict | undefined;
    if (!newAcroForm) {
        newAcroForm = sigContext.obj({
            SigFlags: 3,
            Fields: PDFArray.withContext(sigContext),
        });
        const newAcroFormRef = sigContext.register(newAcroForm);
        sigPdfDoc.catalog.set(PDFName.of("AcroForm"), newAcroFormRef);
    } else {
        if (!newAcroForm.has(PDFName.of("SigFlags"))) {
            newAcroForm.set(PDFName.of("SigFlags"), PDFNumber.of(3));
        }
    }

    // Create signature field widget
    const sigPages = sigPdfDoc.getPages();
    const sigFirstPage = sigPages[0];
    if (!sigFirstPage) {
        throw new Error("PDF has no pages");
    }

    const sigPageRef = sigFirstPage.ref;

    const newSigField = sigContext.obj({
        Type: PDFName.of("Annot"),
        Subtype: PDFName.of("Widget"),
        FT: PDFName.of("Sig"),
        T: PDFString.of(signatureFieldName),
        V: newSigRef,
        F: 132,
        P: sigPageRef,
        Rect: PDFArray.withContext(sigContext),
    });

    const newRectArray = newSigField.get(PDFName.of("Rect")) as PDFArray;
    newRectArray.push(PDFNumber.of(0));
    newRectArray.push(PDFNumber.of(0));
    newRectArray.push(PDFNumber.of(0));
    newRectArray.push(PDFNumber.of(0));

    const newSigFieldRef = sigContext.register(newSigField);

    const newFields = newAcroForm.get(PDFName.of("Fields"));
    if (newFields instanceof PDFArray) {
        newFields.push(newSigFieldRef);
    } else {
        const freshFields = PDFArray.withContext(sigContext);
        freshFields.push(newSigFieldRef);
        newAcroForm.set(PDFName.of("Fields"), freshFields);
    }

    let newAnnots = sigFirstPage.node.lookup(PDFName.of("Annots")) as PDFArray | undefined;
    if (!newAnnots) {
        newAnnots = PDFArray.withContext(sigContext);
        sigFirstPage.node.set(PDFName.of("Annots"), newAnnots);
    }
    newAnnots.push(newSigFieldRef);

    // Mark modified objects for incremental save
    const acroFormRef = sigPdfDoc.catalog.get(PDFName.of("AcroForm"));
    if (acroFormRef instanceof PDFRef) {
        snapshot.markRefForSave(acroFormRef);
    }
    snapshot.markRefForSave(sigFirstPage.ref);
    const catalogRef = sigContext.trailerInfo.Root;
    if (catalogRef instanceof PDFRef) {
        snapshot.markRefForSave(catalogRef);
    }

    const incrementalBytes = await sigPdfDoc.saveIncremental(snapshot);

    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);

    const prepared = calculateByteRanges(finalBytes, placeholderHexLength);
    return prepared;
}
/**
 * Finds the signature placeholder in the PDF and calculates byte ranges.
 * Optimized to search from the end of the file since signatures are appended.
 */
function calculateByteRanges(pdfBytes: Uint8Array, placeholderHexLength: number): PreparedPDF {
    // We only need to search the tail of the PDF because we just appended the signature
    // a few lines ago in preparePdfForTimestamp.
    // Ensure we read enough to cover the placeholder plus some overhead (e.g. 4KB for dict structure)
    const minSearchSize = 50 * 1024;
    const requiredSize = placeholderHexLength + 4096;
    const searchBufferSize = Math.min(pdfBytes.length, Math.max(minSearchSize, requiredSize));

    let searchStartOffset = pdfBytes.length - searchBufferSize;
    let tailBytes = pdfBytes.subarray(searchStartOffset);
    let tailString = new TextDecoder("latin1").decode(tailBytes);

    // Find the Contents hex string - it will look like: /Contents<000000...>
    // We look for a Contents with our exact placeholder length filled with zeros
    const contentsPattern = /\/Contents\s*<(0+)>/g;
    let placeholderMatch: RegExpExecArray | null = null;

    // Helper to find match in string
    const findMatch = (str: string) => {
        let m;
        let pMatch = null;
        // Reset regex state
        contentsPattern.lastIndex = 0;
        while ((m = contentsPattern.exec(str)) !== null) {
            if (m[1]?.length === placeholderHexLength) {
                pMatch = m;
                // Take the last match (most recently added signature)
            }
        }
        return pMatch;
    };

    placeholderMatch = findMatch(tailString);

    // If not found in tail, search the whole file (expensive but necessary fallback)
    if (!placeholderMatch?.[1]) {
        // console.warn("Signature placeholder not found in tail, scanning entire file...");
        searchStartOffset = 0;
        tailBytes = pdfBytes;
        tailString = new TextDecoder("latin1").decode(tailBytes);
        placeholderMatch = findMatch(tailString);
    }

    if (!placeholderMatch?.[1]) {
        throw new Error("Could not find signature placeholder in PDF tail");
    }

    // Now find the enclosing dictionary by searching backwards from the placeholder
    // The placeholder is inside a signature dictionary
    const placeholderLocalPos = placeholderMatch.index;

    // Search backwards for <<
    let dictStartLocal = placeholderLocalPos;
    let depth = 0;
    while (dictStartLocal > 0) {
        // Simple manual check for << without regex
        if (tailString[dictStartLocal] === "<" && tailString[dictStartLocal + 1] === "<") {
            if (depth === 0) {
                break;
            }
            depth--;
        } else if (tailString[dictStartLocal] === ">" && tailString[dictStartLocal + 1] === ">") {
            depth++;
        }
        dictStartLocal--;
    }

    // Calculate absolute positions
    const dictStartAbsolute = searchStartOffset + dictStartLocal;

    // contentsHexStart is where the hex STRING starts (after <)
    const contentsHexStartLocal = placeholderLocalPos + placeholderMatch[0].indexOf("<") + 1;
    const contentsHexStart = searchStartOffset + contentsHexStartLocal;
    const contentsHexEnd = contentsHexStart + placeholderHexLength;

    // Calculate final ByteRange values
    // Range 1: Start of file up to (but excluding) the '<' bracket
    // Range 2: After the '>' bracket to the end of the file
    // Hole: The entire hex string <HEX...HEX> including both brackets
    // This follows standard PDF signature practice for Adobe compatibility.

    const finalByteRange: [number, number, number, number] = [
        0,
        contentsHexStart - 1,
        contentsHexEnd + 1,
        pdfBytes.length - (contentsHexEnd + 1),
    ];

    // Update ByteRange in the PDF with correct values
    const updatedPdf = updateByteRange(pdfBytes, finalByteRange, dictStartAbsolute);

    return {
        bytes: updatedPdf,
        byteRange: finalByteRange,
        contentsOffset: contentsHexStart,
        contentsPlaceholderLength: placeholderHexLength,
    };
}

/**
 * Updates the ByteRange values in a prepared PDF.
 */
function updateByteRange(
    pdfBytes: Uint8Array,
    byteRange: [number, number, number, number],
    searchHintOffset = 0
): Uint8Array {
    // Only decode the relevant part around the hint
    // See BYTERANGE_SEARCH_BACKWARD and BYTERANGE_SEARCH_FORWARD for rationale
    const searchStart = Math.max(0, searchHintOffset - BYTERANGE_SEARCH_BACKWARD);
    const searchEnd = Math.min(pdfBytes.length, searchHintOffset + BYTERANGE_SEARCH_FORWARD);
    const searchRegion = pdfBytes.subarray(searchStart, searchEnd);
    const searchString = new TextDecoder("latin1").decode(searchRegion);

    // Find the ByteRange placeholder
    // Match any number of values since we use 6 placeholders for padding space
    // Simplified to avoid security/detect-unsafe-regex warning (catastrophic backtracking)
    const byteRangePattern = /\/ByteRange\s*\[[\s\d]+\]/;
    const match = byteRangePattern.exec(searchString);

    if (!match) {
        // Fallback to full search if not found in hint region
        const fullString = new TextDecoder("latin1").decode(pdfBytes);
        const fullMatch = byteRangePattern.exec(fullString);
        if (!fullMatch) return pdfBytes;

        // Recalculate match relative to start
        return replaceByteRangeAt(pdfBytes, byteRange, fullMatch.index, fullMatch[0].length);
    }

    return replaceByteRangeAt(pdfBytes, byteRange, searchStart + match.index, match[0].length);
}

function replaceByteRangeAt(
    pdfBytes: Uint8Array,
    byteRange: [number, number, number, number],
    index: number,
    oldLength: number
): Uint8Array {
    // Construct the new string
    // e.g. /ByteRange[0 12345 12345 12345]
    // We try to make it compact first to see if it fits
    const basicStr = `/ByteRange[${String(byteRange[0])} ${String(byteRange[1])} ${String(
        byteRange[2]
    )} ${String(byteRange[3])}]`;

    if (basicStr.length > oldLength) {
        throw new Error(
            `ByteRange placeholder too small! Need ${String(basicStr.length)} chars, found ${String(
                oldLength
            )}. ` + `Please increase placeholder size in preparePdfForTimestamp.`
        );
    }

    // Pad with spaces to match oldLength exactly
    // This is CRITICAL: We cannot change the file size or offsets,
    // otherwise the PDF's Xref table (at the end of the file) becomes invalid.
    const padding = oldLength - basicStr.length;
    const finalStr = basicStr + " ".repeat(padding);

    // Strict in-place replacement
    const result = new Uint8Array(pdfBytes);
    const replacement = new TextEncoder().encode(finalStr);

    result.set(replacement, index);

    return result;
}
