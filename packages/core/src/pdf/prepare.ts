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
import { TimestampError, TimestampErrorCode } from "../types.js";
import { checkedRegister, preflightPdfXref, restoreLargestObjectNumber } from "./internals.js";

/**
 * L5: caps how long a single user-supplied PDF string (reason / location /
 * contactInfo) may be. Anything past this is rejected. 2048 is what most
 * PDF viewers accept comfortably; longer strings serve no signal purpose
 * and bloat the incremental update.
 */
const MAX_PDF_STRING_LENGTH = 2048;

/**
 * Strip embedded NUL bytes and validate length on a user-supplied PDF
 * string. NULs in PDF strings can confuse legacy readers, and unbounded
 * strings let callers grow signature dictionaries arbitrarily.
 */
function sanitizePdfString(value: string, fieldName: string): string {
    if (value.length > MAX_PDF_STRING_LENGTH) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `${fieldName} exceeds maximum length of ${MAX_PDF_STRING_LENGTH.toString()} characters (got ${value.length.toString()})`
        );
    }
    if (value.includes("\x00")) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `${fieldName} contains embedded NUL character`
        );
    }
    return value;
}

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
    /**
     * Optional requested base name for the signature field (default: "Timestamp").
     * A numeric suffix may be added to avoid an existing fully qualified field name.
     */
    signatureFieldName?: string;
    /** Whether to omit the modification time (/M) from the signature dictionary (default: true) */
    omitModificationTime?: boolean;
    /**
     * Whether to ignore PDF encryption when loading the document.
     * @default false
     */
    ignoreEncryption?: boolean;
}

interface ResolvedPdfValue<T extends PDFObject> {
    value: T;
    ref?: PDFRef;
}

function pdfError(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.PDF_ERROR, message);
}

function resolvePdfValue<T extends PDFObject>(
    context: PDFDict["context"],
    rawValue: PDFObject | undefined,
    isExpectedType: (value: PDFObject) => value is T,
    description: string,
    expectedType: string
): ResolvedPdfValue<T> | undefined {
    if (rawValue === undefined) {
        return undefined;
    }

    const ref = rawValue instanceof PDFRef ? rawValue : undefined;
    const value = ref === undefined ? rawValue : context.lookup(ref);
    if (value === undefined || !isExpectedType(value)) {
        throw pdfError(`${description} must be a ${expectedType}`);
    }

    return ref === undefined ? { value } : { value, ref };
}

function resolvePdfDict(
    context: PDFDict["context"],
    rawValue: PDFObject | undefined,
    description: string
): ResolvedPdfValue<PDFDict> | undefined {
    return resolvePdfValue(
        context,
        rawValue,
        (value): value is PDFDict => value instanceof PDFDict,
        description,
        "PDF dictionary"
    );
}

function resolvePdfArray(
    context: PDFDict["context"],
    rawValue: PDFObject | undefined,
    description: string
): ResolvedPdfValue<PDFArray> | undefined {
    return resolvePdfValue(
        context,
        rawValue,
        (value): value is PDFArray => value instanceof PDFArray,
        description,
        "PDF array"
    );
}

function resolveFieldName(
    context: PDFDict["context"],
    rawValue: PDFObject | undefined
): string | undefined {
    if (rawValue === undefined) {
        return undefined;
    }

    const value = rawValue instanceof PDFRef ? context.lookup(rawValue) : rawValue;
    if (!(value instanceof PDFString) && !(value instanceof PDFHexString)) {
        throw pdfError("Field /T must be a PDF string");
    }
    return value.decodeText();
}

function collectFieldNames(context: PDFDict["context"], fields: PDFArray): Set<string> {
    const names = new Set<string>();
    const ancestors = new Set<PDFObject>();

    const visitField = (rawField: PDFObject, parentName: string | undefined): void => {
        const field = resolvePdfDict(context, rawField, "Field");
        if (field === undefined) {
            throw pdfError("Field must be a PDF dictionary");
        }

        const identity = field.ref ?? field.value;
        if (ancestors.has(identity)) {
            throw pdfError("Field hierarchy contains a cycle");
        }
        ancestors.add(identity);

        const partialName = resolveFieldName(context, field.value.get(PDFName.of("T"), true));
        const qualifiedName =
            partialName === undefined
                ? parentName
                : parentName === undefined
                  ? partialName
                  : `${parentName}.${partialName}`;
        if (partialName !== undefined && qualifiedName !== undefined) {
            names.add(qualifiedName);
        }

        const kids = resolvePdfArray(
            context,
            field.value.get(PDFName.of("Kids"), true),
            "Field /Kids"
        );
        if (kids !== undefined) {
            for (let index = 0; index < kids.value.size(); index++) {
                visitField(kids.value.get(index), qualifiedName);
            }
        }

        ancestors.delete(identity);
    };

    for (let index = 0; index < fields.size(); index++) {
        visitField(fields.get(index), undefined);
    }

    return names;
}

function allocateSignatureFieldName(requestedBaseName: string, existingNames: Set<string>): string {
    if (!existingNames.has(requestedBaseName)) {
        return requestedBaseName;
    }

    let suffix = 2;
    while (existingNames.has(`${requestedBaseName}_${String(suffix)}`)) {
        suffix++;
    }
    return `${requestedBaseName}_${String(suffix)}`;
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
    const requestedSignatureFieldName = options.signatureFieldName ?? "Timestamp";

    // Create placeholder content
    const placeholderHex = "0".repeat(placeholderHexLength);

    // Prove every xref/object-stream byte the dependency can decode before
    // handing untrusted PDF input to its loader.
    const xrefProof = preflightPdfXref(pdfBytes);

    // Load the PDF document
    const sigPdfDoc = await PDFDocument.load(pdfBytes, {
        updateMetadata: false,
        ignoreEncryption: options.ignoreEncryption ?? false,
    });

    const sigContext = sigPdfDoc.context;
    restoreLargestObjectNumber(pdfBytes, sigContext, xrefProof);

    // Take snapshot before modifications
    const snapshot = sigPdfDoc.takeSnapshot();

    // Create new signature dictionary
    const sigDictFields: Record<string, PDFObject> = {
        Type: PDFName.of("DocTimeStamp"),
        Filter: PDFName.of("Adobe.PPKLite"),
        SubFilter: PDFName.of("ETSI.RFC3161"),
        ByteRange: PDFArray.withContext(sigContext),
        Contents: PDFHexString.of(placeholderHex),
    };

    if (options.omitModificationTime === false) {
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

    // L5: sanitize and length-cap user-supplied PDF strings before passing them
    // to pdf-lib. pdf-lib's PDFString.of handles encoding, but rejects nothing
    // up front: extremely long strings bloat the signature dictionary and
    // embedded NULs / control chars confuse some PDF readers.
    if (options.reason !== undefined) {
        newSigDict.set(
            PDFName.of("Reason"),
            PDFString.of(sanitizePdfString(options.reason, "reason"))
        );
    }
    if (options.location !== undefined) {
        newSigDict.set(
            PDFName.of("Location"),
            PDFString.of(sanitizePdfString(options.location, "location"))
        );
    }
    if (options.contactInfo !== undefined) {
        newSigDict.set(
            PDFName.of("ContactInfo"),
            PDFString.of(sanitizePdfString(options.contactInfo, "contactInfo"))
        );
    }

    const newSigRef = checkedRegister(sigContext, newSigDict);

    const catalogRef = sigContext.trailerInfo.Root;
    const markCatalogForSave = (): void => {
        if (catalogRef instanceof PDFRef) {
            snapshot.markRefForSave(catalogRef);
        }
    };

    // Get or create AcroForm without replacing any present malformed value.
    let acroForm = resolvePdfDict(
        sigContext,
        sigPdfDoc.catalog.get(PDFName.of("AcroForm"), true),
        "AcroForm"
    );
    if (acroForm === undefined) {
        const newAcroForm = sigContext.obj({
            SigFlags: 3,
            Fields: PDFArray.withContext(sigContext),
        });
        const newAcroFormRef = checkedRegister(sigContext, newAcroForm);
        sigPdfDoc.catalog.set(PDFName.of("AcroForm"), newAcroFormRef);
        markCatalogForSave();
        acroForm = { value: newAcroForm, ref: newAcroFormRef };
    } else {
        if (!acroForm.value.has(PDFName.of("SigFlags"))) {
            acroForm.value.set(PDFName.of("SigFlags"), PDFNumber.of(3));
            if (acroForm.ref === undefined) {
                markCatalogForSave();
            } else {
                snapshot.markRefForSave(acroForm.ref);
            }
        }
    }

    const existingFields = resolvePdfArray(
        sigContext,
        acroForm.value.get(PDFName.of("Fields"), true),
        "AcroForm /Fields array"
    );
    const signatureFieldName = allocateSignatureFieldName(
        requestedSignatureFieldName,
        existingFields === undefined
            ? new Set<string>()
            : collectFieldNames(sigContext, existingFields.value)
    );

    // Create signature field widget
    const sigPages = sigPdfDoc.getPages();
    const sigFirstPage = sigPages[0];
    if (!sigFirstPage) {
        throw new TimestampError(TimestampErrorCode.PDF_ERROR, "PDF has no pages");
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

    const newSigFieldRef = checkedRegister(sigContext, newSigField);

    if (existingFields === undefined) {
        const freshFields = PDFArray.withContext(sigContext);
        freshFields.push(newSigFieldRef);
        acroForm.value.set(PDFName.of("Fields"), freshFields);
        if (acroForm.ref === undefined) {
            markCatalogForSave();
        } else {
            snapshot.markRefForSave(acroForm.ref);
        }
    } else {
        existingFields.value.push(newSigFieldRef);
        if (existingFields.ref === undefined) {
            if (acroForm.ref === undefined) {
                markCatalogForSave();
            } else {
                snapshot.markRefForSave(acroForm.ref);
            }
        } else {
            snapshot.markRefForSave(existingFields.ref);
        }
    }

    const existingAnnots = resolvePdfArray(
        sigContext,
        sigFirstPage.node.get(PDFName.of("Annots"), true),
        "Page /Annots array"
    );
    if (existingAnnots === undefined) {
        const newAnnots = PDFArray.withContext(sigContext);
        newAnnots.push(newSigFieldRef);
        sigFirstPage.node.set(PDFName.of("Annots"), newAnnots);
        snapshot.markRefForSave(sigFirstPage.ref);
    } else {
        existingAnnots.value.push(newSigFieldRef);
        if (existingAnnots.ref === undefined) {
            snapshot.markRefForSave(sigFirstPage.ref);
        } else {
            snapshot.markRefForSave(existingAnnots.ref);
        }
    }

    sigContext.pdfFileDetails.useObjectStreams = false;
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
    // We look for a Contents with our exact placeholder length filled with zeros.
    // We use a dynamic RegExp with bounded quantifiers to prevent ReDoS.
    // eslint-disable-next-line security/detect-non-literal-regexp
    const contentsPattern = new RegExp(
        `/Contents\\s{0,100}<(0{${String(placeholderHexLength)}})>`,
        "g"
    );
    // Helper to find match in string
    const findMatch = (str: string) => {
        let m;
        let pMatch = null;
        // Reset regex state
        contentsPattern.lastIndex = 0;
        while ((m = contentsPattern.exec(str)) !== null) {
            pMatch = m;
            // Take the last match (most recently added signature)
        }
        return pMatch;
    };

    let placeholderMatch: RegExpExecArray | null = findMatch(tailString);

    // If not found in tail, search the whole file (expensive but necessary fallback)
    if (!placeholderMatch?.[1]) {
        searchStartOffset = 0;
        tailBytes = pdfBytes;
        tailString = new TextDecoder("latin1").decode(tailBytes);
        placeholderMatch = findMatch(tailString);
    }

    if (!placeholderMatch?.[1]) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            "Could not find signature placeholder in PDF tail"
        );
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
    // Match any number of values since we use 6 placeholders for padding space.
    // We use bounded quantifiers to prevent ReDoS.
    const byteRangePattern = /\/ByteRange\s{0,100}\[[\s\d]{1,500}\]/;
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
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
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
