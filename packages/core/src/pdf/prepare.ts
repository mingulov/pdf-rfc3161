import {
    PDFDocument,
    PDFDict,
    PDFInvalidObject,
    PDFName,
    PDFHexString,
    PDFArray,
    PDFNumber,
    PDFString,
    PDFRef,
    PDFObject,
    type PDFContext,
} from "pdf-lib-incremental-save";
import {
    DEFAULT_SIGNATURE_SIZE,
    assertPdfWithinSize,
    assertValidSignatureSize,
} from "../constants.js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import {
    MAX_FIELD_HIERARCHY_DEPTH,
    MAX_FIELD_HIERARCHY_NODES,
} from "./field-traversal.js";
import {
    applyLastRevisionXrefFormat,
    assertIncrementalWriterHeadroom,
    checkedRegister,
    restoreLargestObjectNumber,
} from "./internals.js";

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
        throw pdfError(
            `${fieldName} exceeds maximum length of ${MAX_PDF_STRING_LENGTH.toString()} characters (got ${value.length.toString()})`
        );
    }
    if (value.includes("\x00")) {
        throw pdfError(`${fieldName} contains embedded NUL character`);
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
    /**
     * Size to reserve for the timestamp token (default: 8192 bytes = 16384 hex chars).
     * Omit or pass 0 for auto sizing; any other value must be a positive safe
     * integer of at most `MAX_SIGNATURE_SIZE` (65,536) bytes, else preparation
     * rejects with `INVALID_ARGUMENT` before allocating or parsing.
     */
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
    const visited = new Set<PDFObject>();

    const visitField = (
        rawField: PDFObject,
        parentName: string | undefined,
        depth: number
    ): void => {
        if (depth >= MAX_FIELD_HIERARCHY_DEPTH) {
            throw pdfError("Field hierarchy exceeds the supported depth");
        }
        if (visited.size >= MAX_FIELD_HIERARCHY_NODES) {
            throw pdfError("Field hierarchy exceeds the supported node count");
        }
        const field = resolvePdfDict(context, rawField, "Field");
        if (field === undefined) {
            throw pdfError("Field must be a PDF dictionary");
        }

        const identity = field.ref ?? field.value;
        if (ancestors.has(identity)) {
            throw pdfError("Field hierarchy contains a cycle");
        }
        if (visited.has(identity)) {
            throw pdfError("Field hierarchy reuses a field node");
        }
        ancestors.add(identity);
        visited.add(identity);

        try {
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
                    visitField(kids.value.get(index), qualifiedName, depth + 1);
                }
            }
        } finally {
            ancestors.delete(identity);
        }
    };

    for (let index = 0; index < fields.size(); index++) {
        visitField(fields.get(index), undefined, 0);
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
 * Bytes to search forward from the signature dictionary start hint for the
 * ByteRange placeholder. The hint is the `<<` of the newly serialized
 * signature object, whose frozen serialization always emits `/ByteRange`
 * before `/Contents`, so the first match at or after the hint is that
 * object's placeholder. Candidates before the hint belong to earlier
 * content and must never be patched; a miss is PDF_ERROR, never a
 * file-wide lexical fallback (R2).
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
 * Builds the /DocTimeStamp signature dictionary and registers it as a
 * pre-rendered object instead of a live PDFDict. Both incremental writers
 * exempt PDFInvalidObject from object-stream compression unconditionally, so
 * the raw /ByteRange and /Contents placeholder bytes keep physical file offsets
 * whichever cross-reference format the input uses. A live PDFDict would only
 * survive PDFStreamWriter (used for cross-reference-stream inputs) if that
 * writer exempted /Type /DocTimeStamp, which it does not.
 *
 * The mutable dictionary never leaves this function: once its bytes are copied
 * out they are frozen, and a later `set` would silently vanish from the output.
 * Returning only the ref makes that invariant a scope rule rather than a
 * comment the next editor has to notice.
 */
function registerFrozenSignatureDictionary(
    sigContext: PDFContext,
    placeholderHex: string,
    options: PrepareOptions
): PDFRef {
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

    // Nothing may mutate newSigDict past this point: the bytes are frozen here.
    const sigDictBytes = new Uint8Array(newSigDict.sizeInBytes());
    newSigDict.copyBytesInto(sigDictBytes, 0);
    return checkedRegister(sigContext, PDFInvalidObject.of(sigDictBytes));
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
    assertPdfWithinSize(pdfBytes, undefined);
    assertValidSignatureSize(options.signatureSize);
    const signatureSize =
        options.signatureSize === undefined || options.signatureSize === 0
            ? DEFAULT_SIGNATURE_SIZE
            : options.signatureSize;
    const placeholderHexLength = signatureSize * 2; // Each byte = 2 hex chars
    const requestedSignatureFieldName = options.signatureFieldName ?? "Timestamp";

    // Create placeholder content
    const placeholderHex = "0".repeat(placeholderHexLength);

    // Load the PDF document. The official dependency can throw its own parser
    // errors, but callers of this API receive TimestampError failure codes.
    let sigPdfDoc: PDFDocument;
    try {
        sigPdfDoc = await PDFDocument.load(pdfBytes, {
            updateMetadata: false,
            ignoreEncryption: options.ignoreEncryption ?? false,
        });
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `Failed to load PDF for timestamp preparation: ${error instanceof Error ? error.message : String(error)}`,
            error
        );
    }
    if (!(sigPdfDoc.catalog instanceof PDFDict)) {
        throw pdfError("Failed to load PDF for timestamp preparation: catalog is missing");
    }

    const sigContext = sigPdfDoc.context;
    restoreLargestObjectNumber(pdfBytes, sigContext);

    // Take snapshot before modifications
    const snapshot = sigPdfDoc.takeSnapshot();

    const newSigRef = registerFrozenSignatureDictionary(sigContext, placeholderHex, options);

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
        const rawSigFlags = acroForm.value.get(PDFName.of("SigFlags"));
        const resolved = rawSigFlags instanceof PDFRef ? sigContext.lookup(rawSigFlags) : rawSigFlags;
        const existing = resolved instanceof PDFNumber ? resolved.asNumber() : -1;
        if (rawSigFlags !== undefined && (!Number.isSafeInteger(existing) || existing < 0)) {
            throw pdfError("AcroForm /SigFlags is malformed");
        }
        // Set bits 1 and 2, keeping other bits.
        let updated = 3;
        if (rawSigFlags !== undefined) {
            updated = existing;
            if (updated % 2 === 0) updated += 1;
            if (updated % 4 < 2) updated += 2;
        }
        if (rawSigFlags === undefined || updated !== existing) {
            acroForm.value.set(PDFName.of("SigFlags"), PDFNumber.of(updated));
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
        throw pdfError("PDF has no pages");
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

    // Match the LAST revision's cross-reference format (see
    // updateValidationStore for the full rationale); the signature dictionary
    // is registered as a pre-rendered PDFInvalidObject above so ByteRange
    // offsets stay physical. The format has to be decided before the headroom
    // guard, which only reserves on the stream path.
    applyLastRevisionXrefFormat(pdfBytes, sigContext);
    assertIncrementalWriterHeadroom(sigContext);
    const incrementalBytes = await sigPdfDoc.saveIncremental(snapshot);

    const finalBytes = new Uint8Array(pdfBytes.length + incrementalBytes.length);
    finalBytes.set(pdfBytes, 0);
    finalBytes.set(incrementalBytes, pdfBytes.length);

    const prepared = calculateByteRanges(finalBytes, placeholderHexLength, pdfBytes.length);
    return prepared;
}
/**
 * Finds the new signature placeholder in the appended revision and calculates
 * byte ranges. The search never leaves the incremental update starting at
 * `revisionStart`: earlier revisions may hold same-length placeholders, and a
 * second match inside the update means a decoy (e.g. inside a field-name
 * string) shares it with the real placeholder, so the new signature's
 * identity is ambiguous and must reject with PDF_ERROR (R2).
 */
function calculateByteRanges(
    pdfBytes: Uint8Array,
    placeholderHexLength: number,
    revisionStart: number
): PreparedPDF {
    // Decode the appended revision only: the new signature object is always in
    // it, earlier revisions may hold same-length placeholders, and a tail
    // window could cut the real placeholder while keeping a decoy (ambiguous
    // identity must reject, never patch a positional guess).
    const searchStartOffset = revisionStart;
    const tailBytes = pdfBytes.subarray(searchStartOffset);
    const tailString = new TextDecoder("latin1").decode(tailBytes);

    // Find the Contents hex string - it will look like: /Contents<000000...>
    // We look for a Contents with our exact placeholder length filled with zeros.
    // We use a dynamic RegExp with bounded quantifiers to prevent ReDoS.
    // eslint-disable-next-line security/detect-non-literal-regexp
    const contentsPattern = new RegExp(
        `/Contents\\s{0,100}<(0{${String(placeholderHexLength)}})>`,
        "g"
    );
    // Helper to find the single placeholder match in a revision-scoped string.
    // The real placeholder is always inside the appended revision, so exactly
    // one match there is provably the new signature's; a second match is a
    // same-length decoy and the identity is ambiguous (R2: reject, never guess).
    const findMatch = (str: string) => {
        let m;
        let pMatch = null;
        // Reset regex state
        contentsPattern.lastIndex = 0;
        while ((m = contentsPattern.exec(str)) !== null) {
            if (pMatch !== null) throw pdfError("Ambiguous signature placeholder");
            pMatch = m;
        }
        return pMatch;
    };

    const placeholderMatch: RegExpExecArray | null = findMatch(tailString);

    if (!placeholderMatch?.[1]) {
        throw pdfError("Could not find signature placeholder in PDF tail");
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
 *
 * @internal Exported for PDF-invariant regression tests only; not part of
 * the package surface.
 */
export function updateByteRange(
    pdfBytes: Uint8Array,
    byteRange: [number, number, number, number],
    searchHintOffset = 0
): Uint8Array {
    // Decode only the forward window at/after the hint: the new signature
    // dictionary starts there, so its ByteRange placeholder is the first
    // match. Anything earlier belongs to prior content (R2).
    const searchStart = Math.min(Math.max(0, searchHintOffset), pdfBytes.length);
    const searchEnd = Math.min(pdfBytes.length, searchStart + BYTERANGE_SEARCH_FORWARD);
    const searchRegion = pdfBytes.subarray(searchStart, searchEnd);
    const searchString = new TextDecoder("latin1").decode(searchRegion);

    // Find the ByteRange placeholder
    // Match any number of values since we use 6 placeholders for padding space.
    // We use bounded quantifiers to prevent ReDoS.
    const byteRangePattern = /\/ByteRange\s{0,100}\[[\s\d]{1,500}\]/;
    const match = byteRangePattern.exec(searchString);

    if (!match) {
        throw pdfError("Could not find the new signature ByteRange placeholder");
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
        throw pdfError(
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
