import * as pkijs from "pkijs";
import {
    PDFDocument,
    PDFDict,
    PDFName,
    PDFArray,
    PDFHexString,
    PDFNumber,
    PDFRef,
} from "pdf-lib-incremental-save";
import {
    TimestampError,
    TimestampErrorCode,
    type TimestampInfo,
    type VerificationOptions,
    type ExtractOptions,
} from "../types.js";
import { toArrayBuffer, bytesToHex, extractBytesFromByteRange } from "../utils.js";
import { MAX_BATCH_TIMESTAMP_VERIFICATION_BYTES } from "../constants.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";
import { parsePdfDate } from "../utils/pdf-date.js";
import {
    parseTimestampToken as extractTimestampInfo,
    isCertValidAtTime,
} from "../pki/pki-utils.js";
import {
    getEmbeddedCertificates,
    hasTimestampingEKU,
    parseTimestampToken as parseStrictTimestampToken,
    selectSignerCertificate,
    validateTimestampESS,
    verifyTimestampCmsSignature,
} from "../tsa/token-validation.js";
import { collectAcroFormFields, type ResolvedAcroFormField } from "./field-traversal.js";
import {
    PdfSignatureOccurrenceIndex,
    type PdfContentsBinding,
    type PdfObjectIdentity,
} from "./signature-occurrence-index.js";

/**
 * Information about an extracted timestamp signature from a PDF
 */
export interface ExtractedTimestamp {
    /** Timestamp information */
    info: TimestampInfo;
    /**
     * The raw timestamp token (DER-encoded ContentInfo).
     *
     * Fields that inherit one selected PDF /V may share this buffer. Treat it
     * as read-only and copy it before mutation.
     */
    token: Uint8Array;
    /**
     * Complete decoded /Contents value bytes, including reserved zero padding.
     *
     * Fields that inherit one selected PDF /V may share this buffer. Treat it
     * as read-only and copy it before mutation.
     */
    contentsValueBytes: Uint8Array;
    /** The field name in the PDF */
    fieldName: string;
    /** Whether the signature covers the entire document */
    coversWholeDocument: boolean;
    /** Whether the signature is cryptographically valid */
    verified: boolean;
    /** Verification error message if verification failed */
    verificationError?: string;
    /**
     * The certificates found in the timestamp signature.
     * Useful for performing manual revocation checks (CRL/OCSP).
     *
     * Fields that inherit one verified PDF /V may share this array. Treat the
     * array and its certificate objects as read-only; copy before mutation.
     */
    certificates?: pkijs.Certificate[];
    /** Byte range [offset1, length1, offset2, length2] */
    byteRange: [number, number, number, number];
    /** @internal Raw indirect object that owns the selected /Contents token. */
    contentsObject?: PdfObjectIdentity;
    /** @internal Whether the selected signature dictionary is a direct /V value. */
    contentsDirectValue?: boolean;
    /** Number of CRLs found in the signature */
    crlCount?: number;
    /** Number of OCSP responses found in the signature */
    ocspCount?: number;
    /** The Reason entry from the PDF Signature Dictionary */
    reason?: string;
    /** The Location entry from the PDF Signature Dictionary */
    location?: string;
    /** The ContactInfo entry from the PDF Signature Dictionary */
    contactInfo?: string;
    /** The Modification Time (M) entry from the PDF Signature Dictionary */
    m?: Date;
}

/** @internal Detailed timestamp discovery used by archive renewal only. */
export interface ArchiveTimestampDiscovery {
    timestamps: ExtractedTimestamp[];
    malformedFieldNames: string[];
    /** @internal Shared bounded scanner retained for archive verification. */
    occurrenceIndex?: PdfSignatureOccurrenceIndex;
}

/**
 * Returns the exact length of one canonical DER TLV at the start of `bytes`.
 * PDF /Contents reserves a fixed-width hex string, so only the bytes after
 * this TLV can be considered placeholder padding.
 */
function derTlvLength(bytes: Uint8Array): number {
    const firstLengthOctet = bytes[1];
    if (bytes.length < 2 || firstLengthOctet === undefined) {
        throw new Error("Timestamp /Contents does not contain a DER TLV header");
    }
    if (firstLengthOctet < 0x80) {
        const total = 2 + firstLengthOctet;
        if (total > bytes.length)
            throw new Error("Timestamp /Contents DER length exceeds its contents");
        return total;
    }

    const lengthOctets = firstLengthOctet & 0x7f;
    if (lengthOctets === 0 || lengthOctets > 6 || 2 + lengthOctets > bytes.length) {
        throw new Error("Timestamp /Contents uses an invalid DER long-form length");
    }
    const firstLengthByte = bytes[2];
    if (firstLengthByte === undefined || firstLengthByte === 0) {
        throw new Error("Timestamp /Contents uses a non-canonical DER length");
    }

    let contentLength = 0;
    for (let index = 0; index < lengthOctets; index++) {
        const value = bytes[2 + index];
        if (value === undefined) throw new Error("Timestamp /Contents has a truncated DER length");
        contentLength = contentLength * 256 + value;
    }
    if (contentLength < 0x80) {
        throw new Error("Timestamp /Contents uses a non-canonical DER long-form length");
    }
    const total = 2 + lengthOctets + contentLength;
    if (!Number.isSafeInteger(total) || total > bytes.length) {
        throw new Error("Timestamp /Contents DER length exceeds its contents");
    }
    return total;
}

function tokenWithoutPdfContentsPadding(contents: Uint8Array): Uint8Array {
    const tokenLength = derTlvLength(contents);
    const suffix = contents.subarray(tokenLength);
    if (!suffix.every((byte) => byte === 0)) {
        throw new Error("Timestamp /Contents has a nonzero suffix after its DER token");
    }
    return contents.slice(0, tokenLength);
}

function isRfc3161SubFilter(value: unknown): boolean {
    return value instanceof PDFName && value.toString() === "/ETSI.RFC3161";
}

function isDocumentTimestampType(value: unknown): boolean {
    return value instanceof PDFName && value.toString() === "/DocTimeStamp";
}

function resolveIndirectPdfObject(
    context: PDFDocument["context"],
    value: unknown
): unknown {
    return value instanceof PDFRef ? context.lookup(value) : value;
}

function fieldNameForDiscovery(field: PDFDict, index: number): string {
    const fieldNameObj = field.get(PDFName.of("T"));
    return fieldNameObj
        ? fieldNameObj.toString().replace(/^\(/, "").replace(/\)$/, "")
        : `Signature${index.toString()}`;
}

type ByteRange = [number, number, number, number];

interface ParsedTimestampSignatureValue {
    kind: "timestamp";
    info: TimestampInfo;
    token: Uint8Array;
    contentsBytes: Uint8Array;
    byteRange: ByteRange;
    contentsBinding: PdfContentsBinding | undefined;
    coversWholeDocument: boolean;
    metadata: TimestampSignatureMetadata;
}

interface TimestampSignatureMetadata {
    reason?: string;
    location?: string;
    contactInfo?: string;
    m?: Date;
}

interface TimestampPlaceholderValue {
    kind: "placeholder";
}

type TimestampSignatureValue = ParsedTimestampSignatureValue | TimestampPlaceholderValue;

type CachedTimestampSignatureValue =
    | { value: TimestampSignatureValue }
    | { error: unknown };

interface TimestampFieldDescriptor {
    fieldEntry: ResolvedAcroFormField;
    fieldName: string;
    sigValueRef: PDFRef | PDFDict;
    sigValue: PDFDict;
}

/**
 * Classifies AcroForm entries before constructing the raw signature scanner.
 *
 * Only a resolved RFC 3161 value needs lexical /Contents ownership binding.
 * This keeps ordinary approval signatures and arbitrary structured values out
 * of the scanner while preserving archive-mode malformed-field reporting.
 */
function collectTimestampFieldDescriptors(
    pdfDoc: PDFDocument,
    fields: readonly ResolvedAcroFormField[],
    archiveDetailed: boolean,
    recordMalformedField: (fieldName: string | undefined) => void
): TimestampFieldDescriptor[] {
    const descriptors: TimestampFieldDescriptor[] = [];

    for (let index = 0; index < fields.length; index += 1) {
        const fieldEntry = fields[index];
        if (fieldEntry === undefined || fieldEntry.isWidget) continue;

        try {
            // FT and V are inheritable AcroForm field attributes. The shared
            // traversal resolves direct and indirect /Kids nodes while keeping
            // a fully qualified field name for each unique field node.
            const ft = resolveIndirectPdfObject(
                pdfDoc.context,
                fieldEntry.inheritedValue("FT")
            );
            if (ft?.toString() !== "/Sig") continue;

            const fieldName = fieldEntry.fieldName ?? fieldNameForDiscovery(fieldEntry.field, index);
            const fieldMarksRfc3161 = isRfc3161SubFilter(
                resolveIndirectPdfObject(pdfDoc.context, fieldEntry.inheritedValue("SubFilter"))
            );
            const fieldMarksDocumentTimestamp = isDocumentTimestampType(
                resolveIndirectPdfObject(pdfDoc.context, fieldEntry.inheritedValue("Type"))
            );

            const inheritedValue = fieldEntry.inheritedValue("V");
            if (inheritedValue === undefined) {
                if (archiveDetailed && (fieldMarksRfc3161 || fieldMarksDocumentTimestamp)) {
                    recordMalformedField(fieldName);
                }
                continue;
            }

            const sigValueRef =
                inheritedValue instanceof PDFRef || inheritedValue instanceof PDFDict
                    ? inheritedValue
                    : undefined;
            const sigValue =
                sigValueRef instanceof PDFRef
                    ? pdfDoc.context.lookup(sigValueRef)
                    : sigValueRef;
            if (!(sigValue instanceof PDFDict) || sigValueRef === undefined) {
                if (archiveDetailed && (fieldMarksRfc3161 || fieldMarksDocumentTimestamp)) {
                    recordMalformedField(fieldName);
                }
                continue;
            }

            // Public extraction retains its historical SubFilter-only match.
            // Archive renewal requires the exact Type/SubFilter pair and
            // reports either one alone as a malformed timestamp candidate.
            const valueMarksRfc3161 = isRfc3161SubFilter(sigValue.get(PDFName.of("SubFilter")));
            const valueMarksDocumentTimestamp = isDocumentTimestampType(sigValue.get(PDFName.of("Type")));
            if (archiveDetailed && valueMarksRfc3161 !== valueMarksDocumentTimestamp) {
                recordMalformedField(fieldName);
                continue;
            }
            if (!valueMarksRfc3161) continue;

            descriptors.push({ fieldEntry, fieldName, sigValueRef, sigValue });
        } catch {
            // Keep public discovery best-effort. A field cannot be identified
            // as an RFC 3161 candidate unless its marker/value checks above
            // completed, so this mirrors the existing per-field behavior.
            continue;
        }
    }

    return descriptors;
}

function assertTimestampByteRangeGeometry(
    pdfBytes: Uint8Array,
    byteRange: ByteRange,
    contents: Uint8Array,
    contentsBinding: PdfContentsBinding | undefined,
    occurrenceIndex: PdfSignatureOccurrenceIndex
): void {
    const [offset1, length1, offset2, length2] = byteRange;
    const values = [offset1, length1, offset2, length2];
    if (!values.every((value) => Number.isSafeInteger(value) && value >= 0)) {
        throw new Error("RFC 3161 document timestamp /ByteRange must contain non-negative safe integers");
    }
    if (offset1 !== 0) {
        throw new Error("RFC 3161 document timestamp /ByteRange must begin at offset zero");
    }
    const firstEnd = offset1 + length1;
    const secondEnd = offset2 + length2;
    if (!Number.isSafeInteger(firstEnd) || !Number.isSafeInteger(secondEnd)) {
        throw new Error("RFC 3161 document timestamp /ByteRange has an unsafe endpoint");
    }
    if (firstEnd >= offset2) {
        throw new Error(
            "RFC 3161 document timestamp /ByteRange must be ordered, disjoint, and leave a non-empty gap"
        );
    }
    if (firstEnd > pdfBytes.length || secondEnd > pdfBytes.length) {
        throw new Error("RFC 3161 document timestamp /ByteRange extends beyond the PDF");
    }
    if (
        !occurrenceIndex.hasSelectedContents(
            contentsBinding,
            firstEnd,
            offset2,
            contents,
            byteRange,
            pdfBytes
        )
    ) {
        throw new Error(
            "RFC 3161 document timestamp /ByteRange gap must exactly exclude its /Contents hex string"
        );
    }
    if (!occurrenceIndex.isRevisionBoundary(secondEnd, pdfBytes.length)) {
        throw new Error(
            "RFC 3161 document timestamp /ByteRange endpoint must be the current PDF end or an earlier revision boundary"
        );
    }
}

function optionalSignatureText(sigValue: PDFDict, name: string): string | undefined {
    const value = sigValue.get(PDFName.of(name));
    if (value === undefined) return undefined;
    return value instanceof PDFHexString
        ? value.asString()
        : value.toString().replace(/^\(/, "").replace(/\)$/, "");
}

function timestampSignatureMetadata(sigValue: PDFDict): TimestampSignatureMetadata {
    const reason = optionalSignatureText(sigValue, "Reason");
    const location = optionalSignatureText(sigValue, "Location");
    const contactInfo = optionalSignatureText(sigValue, "ContactInfo");
    const mValue = sigValue.get(PDFName.of("M"));
    return {
        ...(reason === undefined ? {} : { reason }),
        ...(location === undefined ? {} : { location }),
        ...(contactInfo === undefined ? {} : { contactInfo }),
        ...(mValue === undefined ? {} : { m: parsePdfDate(mValue.toString()) }),
    };
}

function parseTimestampSignatureValue(
    pdfBytes: Uint8Array,
    sigValue: PDFDict,
    contentsBinding: PdfContentsBinding | undefined,
    occurrenceIndex: PdfSignatureOccurrenceIndex,
    archiveDetailed: boolean
): TimestampSignatureValue {
    const contents = sigValue.get(PDFName.of("Contents"));
    if (!(contents instanceof PDFHexString)) {
        throw new Error("RFC 3161 document timestamp /Contents must be a hex string");
    }

    // Keep the exact decoded PDF value, including all reserved zero padding.
    const contentsBytes = contents.asBytes();
    if (contentsBytes.every((byte) => byte === 0)) {
        if (archiveDetailed) {
            throw new Error("RFC 3161 document timestamp /Contents is an all-zero placeholder");
        }
        return { kind: "placeholder" };
    }

    // A signature placeholder is fixed-width and therefore carries zero
    // bytes after the DER token. Derive the token boundary from its outer DER
    // TLV rather than relaxing the strict token parser.
    const token = tokenWithoutPdfContentsPadding(contentsBytes);
    const byteRange = sigValue.get(PDFName.of("ByteRange"));
    if (!(byteRange instanceof PDFArray) || byteRange.size() !== 4) {
        throw new Error("RFC 3161 document timestamp /ByteRange must contain four numbers");
    }

    const byteRangeStart = byteRange.get(0);
    const byteRangeFirstLength = byteRange.get(1);
    const byteRangeSecondStart = byteRange.get(2);
    const byteRangeSecondLength = byteRange.get(3);
    if (
        !(byteRangeStart instanceof PDFNumber) ||
        !(byteRangeFirstLength instanceof PDFNumber) ||
        !(byteRangeSecondStart instanceof PDFNumber) ||
        !(byteRangeSecondLength instanceof PDFNumber)
    ) {
        throw new Error("RFC 3161 document timestamp /ByteRange must contain four numbers");
    }

    const values = [
        byteRangeStart.asNumber(),
        byteRangeFirstLength.asNumber(),
        byteRangeSecondStart.asNumber(),
        byteRangeSecondLength.asNumber(),
    ] as ByteRange;
    assertTimestampByteRangeGeometry(pdfBytes, values, contentsBytes, contentsBinding, occurrenceIndex);

    return {
        kind: "timestamp",
        info: extractTimestampInfo(token),
        token,
        contentsBytes,
        byteRange: values,
        contentsBinding,
        coversWholeDocument: values[2] + values[3] === pdfBytes.length,
        metadata: timestampSignatureMetadata(sigValue),
    };
}

function cloneTimestampInfo(info: TimestampInfo): TimestampInfo {
    // The decoded nonce belongs to the cached token. Sharing it across fields
    // that inherit one /V keeps imported, attacker-controlled nonce lengths
    // from multiplying by field count; callers that intend to mutate it must
    // make their own copy.
    return {
        ...info,
        genTime: new Date(info.genTime.getTime()),
    };
}

/**
 * Extracts all RFC 3161 document timestamps from a PDF.
 *
 * @param pdfBytes - The PDF document bytes
 * @param options - Extraction options
 * @returns Array of extracted timestamps
 */
export async function extractTimestamps(
    pdfBytes: Uint8Array,
    options?: ExtractOptions
): Promise<ExtractedTimestamp[]> {
    const discovery = await discoverTimestamps(pdfBytes, options, false);
    return discovery.timestamps;
}

/**
 * Discovers RFC 3161 document timestamp fields for archive renewal.
 *
 * Unlike the compatible public {@link extractTimestamps} API, this retains
 * the field names of recognized timestamp fields that cannot be parsed, so
 * archive renewal can warn or reject rather than silently overlook them.
 *
 * @internal
 */
export async function discoverArchiveTimestamps(
    pdfBytes: Uint8Array,
    options?: ExtractOptions
): Promise<ArchiveTimestampDiscovery> {
    return discoverTimestamps(pdfBytes, options, true);
}

async function discoverTimestamps(
    pdfBytes: Uint8Array,
    options: ExtractOptions | undefined,
    archiveDetailed: boolean
): Promise<ArchiveTimestampDiscovery> {
    let pdfDoc;
    try {
        pdfDoc = await PDFDocument.load(pdfBytes, {
            updateMetadata: false,
            ignoreEncryption: options?.ignoreEncryption ?? false,
        });
    } catch (error) {
        throw new TimestampError(
            TimestampErrorCode.PDF_ERROR,
            `Failed to parse PDF: ${error instanceof Error ? error.message : String(error)}`
        );
    }
    // pdf-lib can synthesize a document instance with no catalog for a
    // truncated header/xref. Preserve the public parse-error contract for
    // that case rather than treating it as an ordinary PDF without fields.
    if (!(pdfDoc.catalog instanceof PDFDict)) {
        throw new TimestampError(TimestampErrorCode.PDF_ERROR, "Failed to parse PDF: missing catalog");
    }

    const timestamps: ExtractedTimestamp[] = [];
    const malformedFieldNames: string[] = [];
    const recordMalformedField = (fieldName: string | undefined): void => {
        if (!archiveDetailed) return;
        const name = fieldName ?? "<AcroForm>";
        if (!malformedFieldNames.includes(name)) malformedFieldNames.push(name);
    };

    let fields: ReturnType<typeof collectAcroFormFields>;
    try {
        fields = collectAcroFormFields(pdfDoc, {
            continueOnError: true,
            onMalformedField: recordMalformedField,
        });
    } catch {
        // Public extraction has always been best-effort. A malformed ordinary
        // AcroForm tree must not turn a timestamp listing into a PDF-load
        // error. Archive renewal must not silently treat a malformed field
        // graph as a document with no timestamps, because strict renewal
        // needs an auditable rejection target even when no field name can be
        // resolved safely.
        recordMalformedField(undefined);
        return { timestamps, malformedFieldNames };
    }

    // First classify actual RFC 3161 candidates. Do not construct a physical
    // scanner for ordinary fields, arbitrary structured /V values, or an
    // AcroForm with no fields at all.
    const descriptors = collectTimestampFieldDescriptors(
        pdfDoc,
        fields,
        archiveDetailed,
        recordMalformedField
    );
    if (descriptors.length === 0) return { timestamps, malformedFieldNames };

    // Build one physical lexical index for only selected RFC 3161 /V owners.
    // This deduplicates shared signature values and avoids multiplying a raw
    // scan by the number of form fields.
    const wantedContentsOwners: PdfObjectIdentity[] = [];
    for (const descriptor of descriptors) {
        const { fieldEntry, sigValueRef } = descriptor;
        if (sigValueRef instanceof PDFRef) {
            wantedContentsOwners.push({
                objectNumber: sigValueRef.objectNumber,
                generationNumber: sigValueRef.generationNumber,
            });
        } else {
            const owner = fieldEntry.inheritedOwnerRef("V");
            if (owner !== undefined) {
                wantedContentsOwners.push({
                    objectNumber: owner.objectNumber,
                    generationNumber: owner.generationNumber,
                });
            }
        }
    }

    let occurrenceIndex: PdfSignatureOccurrenceIndex;
    try {
        occurrenceIndex = new PdfSignatureOccurrenceIndex(pdfBytes, wantedContentsOwners);
    } catch {
        recordMalformedField(undefined);
        return { timestamps, malformedFieldNames };
    }

    const signatureValueCache = new Map<string, CachedTimestampSignatureValue>();
    const directValueIds = new WeakMap<PDFDict, number>();
    let nextDirectValueId = 0;

    // Bind and parse only the preclassified timestamp signature values.
    for (const descriptor of descriptors) {
        try {
            const { fieldEntry, fieldName, sigValueRef, sigValue } = descriptor;

            const rawContentsBinding: PdfContentsBinding | undefined =
                sigValueRef instanceof PDFRef
                    ? {
                          owner: {
                              objectNumber: sigValueRef.objectNumber,
                              generationNumber: sigValueRef.generationNumber,
                          },
                          directValue: false,
                          requireDocumentTimestamp: archiveDetailed,
                      }
                    : (() => {
                          const fieldOwner = fieldEntry.inheritedOwnerRef("V");
                          return fieldOwner === undefined
                              ? undefined
                              : {
                                    owner: {
                                        objectNumber: fieldOwner.objectNumber,
                                        generationNumber: fieldOwner.generationNumber,
                                    },
                                    directValue: true,
                                    requireDocumentTimestamp: archiveDetailed,
                                };
                      })();
            const cacheKey =
                sigValueRef instanceof PDFRef
                    ? `indirect:${sigValueRef.objectNumber.toString()}:${sigValueRef.generationNumber.toString()}`
                    : (() => {
                          let directValueId = directValueIds.get(sigValue);
                          if (directValueId === undefined) {
                              nextDirectValueId += 1;
                              directValueId = nextDirectValueId;
                              directValueIds.set(sigValue, directValueId);
                          }
                          const owner = rawContentsBinding?.owner;
                          return `direct:${owner?.objectNumber.toString() ?? "none"}:${owner?.generationNumber.toString() ?? "none"}:${directValueId.toString()}`;
                      })();
            let cached = signatureValueCache.get(cacheKey);
            if (cached === undefined) {
                try {
                    cached = {
                        value: parseTimestampSignatureValue(
                            pdfBytes,
                            sigValue,
                            rawContentsBinding,
                            occurrenceIndex,
                            archiveDetailed
                        ),
                    };
                } catch (error) {
                    cached = { error };
                }
                signatureValueCache.set(cacheKey, cached);
            }
            if ("error" in cached) throw cached.error;
            if (cached.value.kind === "placeholder") continue;
            const parsedValue = cached.value;

            timestamps.push({
                info: cloneTimestampInfo(parsedValue.info),
                token: parsedValue.token,
                contentsValueBytes: parsedValue.contentsBytes,
                fieldName,
                coversWholeDocument: parsedValue.coversWholeDocument,
                byteRange: [...parsedValue.byteRange] as ByteRange,
                contentsObject: parsedValue.contentsBinding?.owner,
                contentsDirectValue: parsedValue.contentsBinding?.directValue,
                verified: false, // Not verified until verifyTimestamp is called
                ...parsedValue.metadata,
                ...(parsedValue.metadata.m === undefined
                    ? {}
                    : { m: new Date(parsedValue.metadata.m.getTime()) }),
            });
        } catch {
            recordMalformedField(descriptor.fieldName);
            continue;
        }
    }

    return { timestamps, malformedFieldNames, occurrenceIndex };
}

/**
 * Verifies an extracted timestamp's cryptographic signature and trust
 * properties.
 *
 * The verification runs in order:
 *   1. The raw CMS token is parsed strictly and its signer is selected by
 *      the original issuer/serial or SubjectKeyIdentifier SID.
 *   2. (optional, when `options.pdf` is supplied) The document ByteRange
 *      hash matches the parsed messageImprint.
 *   3. The shared CMS verifier checks signed attributes, content digest, and
 *      signature math with the SID-selected certificate.
 *   4. (optional, when `options.trustStore` is supplied) The caller's trust
 *      policy validates that signer's certificate chain. No default trust is
 *      assumed by this function.
 *   5. (optional for historical files) The selected certificate has one
 *      critical EKU whose sole value is id-kp-timeStamping.
 *   6. (optional for historical files) The selected certificate is valid at
 *      the token's generation time.
 *   7. (optional for historical files) Complete signed ESS v1/v2 bindings
 *      match the selected certificate.
 *
 * @param timestamp - The {@link ExtractedTimestamp} to verify.
 * @param options - Optional {@link VerificationOptions}.
 * @returns The same `timestamp` object with `verified` and possibly
 *   `verificationError` and `certificates` populated.
 *
 * @example
 * Basic verify (CMS signature and the default RFC 3161 profile checks; no
 * trust policy is implied):
 * ```typescript
 * const verified = await verifyTimestamp(extracted);
 * if (!verified.verified) throw new Error(verified.verificationError);
 * ```
 *
 * @example
 * Strict verification with chain + opt-in PAdES ESS check:
 * ```typescript
 * // Since 0.2.0, requireTimestampingEKU and requireCertValidAtGenTime
 * // default to `true`. The only remaining opt-in is strictESSValidation.
 * const verified = await verifyTimestamp(extracted, {
 *     trustStore: myTSARoots,
 *     pdf: originalPdfBytes,
 *     strictESSValidation: true,
 * });
 * ```
 *
 * @example
 * Lenient verification for a legacy token whose TSA cert lacks the
 * id-kp-timeStamping EKU (or had expired by signing time):
 * ```typescript
 * const verified = await verifyTimestamp(extracted, {
 *     trustStore: myTSARoots,
 *     pdf: originalPdfBytes,
 *     requireTimestampingEKU: false,
 *     requireCertValidAtGenTime: false,
 * });
 * ```
 */
async function verifyTimestampWithIndex(
    timestamp: ExtractedTimestamp,
    options: VerificationOptions = {},
    suppliedOccurrenceIndex?: PdfSignatureOccurrenceIndex
): Promise<ExtractedTimestamp> {
    try {
        const parsed = parseStrictTimestampToken(timestamp.token);
        const certificates = getEmbeddedCertificates(parsed.signedData);
        const signingCertificate = selectSignerCertificate(parsed.signerInfo, certificates);
        const crlCount = parsed.signedData.crls?.length ?? 0;
        const ocspCount =
            (parsed.signedData as unknown as { ocsps?: unknown[] }).ocsps?.length ?? 0;

        // Step 1: Verify document hash if PDF is provided. Use the parsed
        // TSTInfo rather than caller-supplied metadata.
        if (options.pdf) {
            await ensureWebCrypto();
            const contentsBinding: PdfContentsBinding | undefined =
                timestamp.contentsObject === undefined
                    ? undefined
                    : {
                          owner: timestamp.contentsObject,
                          // Older caller-created ExtractedTimestamp values
                          // represented indirect signature dictionaries only.
                          directValue: timestamp.contentsDirectValue ?? false,
                      };
            const occurrenceIndex =
                suppliedOccurrenceIndex ??
                new PdfSignatureOccurrenceIndex(
                    options.pdf,
                    contentsBinding === undefined ? [] : [contentsBinding.owner]
                );
            assertTimestampByteRangeGeometry(
                options.pdf,
                timestamp.byteRange,
                timestamp.contentsValueBytes,
                contentsBinding,
                occurrenceIndex
            );
            const dataToHash = extractBytesFromByteRange(options.pdf, timestamp.byteRange);
            const hashBuffer = await crypto.subtle.digest(
                parsed.info.hashAlgorithm,
                toArrayBuffer(dataToHash)
            );
            const actualHash = bytesToHex(hashBuffer);

            if (actualHash.toLowerCase() !== parsed.info.messageDigest.toLowerCase()) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: `Document hash mismatch. Expected ${parsed.info.messageDigest}, found ${actualHash}`,
                    certificates,
                };
            }
        }

        // Step 2: Reuse the pre-embed CMS verifier after selecting the signer
        // by its original SID. This validates signed attributes, content digest,
        // and the CMS signature without treating certificate order as authority.
        await verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signingCertificate);

        // If trust store is provided, verify the certificate chain
        if (options.trustStore) {
            // Put the SID-selected signer first. This remains caller-owned
            // trust policy; self-consistency alone never establishes TSA trust.
            const chain = [
                signingCertificate,
                ...certificates.filter((certificate) => certificate !== signingCertificate),
            ];
            const isTrusted = await options.trustStore.verifyChain(chain);
            if (!isTrusted) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: "Certificate chain not trusted",
                    certificates,
                };
            }
        }

        // G1: strict RFC 3161 EKU validation. This opt-out is retained only
        // for post-embed historical verification, never the pre-embed gate.
        const requireEKU = options.requireTimestampingEKU ?? true;
        if (requireEKU) {
            if (!hasTimestampingEKU(signingCertificate)) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "Signing certificate must have one critical exclusive id-kp-timeStamping ExtendedKeyUsage required by RFC 3161 Sec. 2.3",
                    certificates,
                };
            }
        }

        // G2: enforce that the signing TSA cert is valid at genTime.
        // Otherwise an expired or not-yet-valid TSA cert can mint timestamps.
        // Defaults to `true` since 0.2.0; opt out with
        // `requireCertValidAtGenTime: false`.
        const requireValidity = options.requireCertValidAtGenTime ?? true;
        if (requireValidity) {
            const genTime = parsed.info.genTime;
            if (!(genTime instanceof Date)) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "requireCertValidAtGenTime: token has no genTime to compare against",
                    certificates,
                };
            }
            if (!isCertValidAtTime(signingCertificate, genTime)) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: `Signing certificate was not valid at genTime ${genTime.toISOString()} (notBefore=${signingCertificate.notBefore.value instanceof Date ? signingCertificate.notBefore.value.toISOString() : "unknown"}, notAfter=${signingCertificate.notAfter.value instanceof Date ? signingCertificate.notAfter.value.toISOString() : "unknown"})`,
                    certificates,
                };
            }
        }

        // Strict PAdES/ESS check
        if (options.strictESSValidation) {
            await validateTimestampESS(parsed.signerInfo, signingCertificate);
        }

        return {
            ...timestamp,
            info: parsed.info,
            verified: true,
            certificates,
            crlCount,
            ocspCount,
        };
    } catch (error) {
        return {
            ...timestamp,
            verified: false,
            verificationError: error instanceof Error ? error.message : String(error),
        };
    }
}

/**
 * Verifies an extracted RFC 3161 timestamp. When PDF bytes are supplied, the
 * selected /ByteRange is bound to the lexical occurrence of that signature's
 * /Contents token before its message imprint is checked.
 */
export async function verifyTimestamp(
    timestamp: ExtractedTimestamp,
    options: VerificationOptions = {}
): Promise<ExtractedTimestamp> {
    return verifyTimestampWithIndex(timestamp, options);
}

function verificationCacheKey(timestamp: ExtractedTimestamp): string | undefined {
    if (timestamp.contentsObject === undefined) return undefined;
    const [offset1, length1, offset2, length2] = timestamp.byteRange;
    return [
        timestamp.contentsObject.objectNumber,
        timestamp.contentsObject.generationNumber,
        timestamp.contentsDirectValue ? "direct" : "indirect",
        offset1,
        length1,
        offset2,
        length2,
    ].join(":");
}

function coveredByteLength(timestamp: ExtractedTimestamp): number | undefined {
    const length1 = timestamp.byteRange[1];
    const length2 = timestamp.byteRange[3];
    if (
        !Number.isSafeInteger(length1) ||
        !Number.isSafeInteger(length2) ||
        length1 < 0 ||
        length2 < 0 ||
        length1 > Number.MAX_SAFE_INTEGER - length2
    ) {
        return undefined;
    }
    return length1 + length2;
}

function verificationWorkBudgetFailure(timestamp: ExtractedTimestamp): ExtractedTimestamp {
    return {
        ...timestamp,
        verified: false,
        verificationError: "Timestamp verification work budget exhausted",
    };
}

function cloneSharedVerification(
    timestamp: ExtractedTimestamp,
    shared: ExtractedTimestamp
): ExtractedTimestamp {
    const result: ExtractedTimestamp = {
        ...timestamp,
        verified: shared.verified,
    };
    if (shared.verified) {
        result.info = cloneTimestampInfo(shared.info);
        result.crlCount = shared.crlCount;
        result.ocspCount = shared.ocspCount;
    }
    if (shared.verificationError !== undefined) {
        result.verificationError = shared.verificationError;
    }
    if (shared.certificates !== undefined) {
        result.certificates = shared.certificates;
    }
    return result;
}

/**
 * Verifies extracted timestamp values in input order with one bounded scanner
 * and at most one CMS verification for each selected signature value.
 *
 * This is intentionally internal: public callers use {@link verifyTimestamp}
 * for one timestamp or {@link verifyPdfTimestamps} for a PDF. Archive renewal
 * supplies its strict discovery scanner so it cannot fall back to permissive
 * rediscovery. When PDF bytes are supplied, a fixed aggregate 512 MiB covered
 * byte budget is reserved before any per-value PDF copy or hash. Exhausted
 * values retain their input order and return `verified: false`; archive strict
 * renewal consequently rejects before mutation while default renewal warns.
 *
 * @internal
 */
export async function verifyTimestampsWithSharedIndex(
    timestamps: readonly ExtractedTimestamp[],
    options: VerificationOptions = {},
    suppliedOccurrenceIndex?: PdfSignatureOccurrenceIndex
): Promise<ExtractedTimestamp[]> {
    const verifiedValues = new Map<string, ExtractedTimestamp>();
    const results: ExtractedTimestamp[] = [];
    let coveredBytesReserved = 0;
    for (const timestamp of timestamps) {
        const key = verificationCacheKey(timestamp);
        const shared = key === undefined ? undefined : verifiedValues.get(key);
        if (shared !== undefined) {
            results.push(cloneSharedVerification(timestamp, shared));
            continue;
        }

        // Reserve the exact PDF bytes that this distinct signature would copy
        // and hash before entering verifyTimestampWithIndex. Invalid geometry
        // keeps its established verifier error; only valid safe lengths are
        // charged to the aggregate work budget.
        const coveredBytes = options.pdf === undefined ? undefined : coveredByteLength(timestamp);
        if (
            coveredBytes !== undefined &&
            coveredBytes > MAX_BATCH_TIMESTAMP_VERIFICATION_BYTES - coveredBytesReserved
        ) {
            const exhausted = verificationWorkBudgetFailure(timestamp);
            if (key !== undefined) verifiedValues.set(key, exhausted);
            results.push(exhausted);
            continue;
        }
        if (coveredBytes !== undefined) coveredBytesReserved += coveredBytes;

        // Sequential processing gives untrusted PDFs a fixed peak of one CMS
        // parse/signature verification. The cache avoids repeating that work
        // when several AcroForm fields inherit the same selected /V value.
        const verified = await verifyTimestampWithIndex(timestamp, options, suppliedOccurrenceIndex);
        if (key !== undefined) verifiedValues.set(key, verified);
        results.push(verified);
    }
    return results;
}

/**
 * Extracts and verifies every RFC 3161 timestamp in a PDF in one call.
 *
 * Produces the same ordered results as extracting then verifying each value,
 * while sharing one bounded occurrence index and processing unique signature
 * values sequentially. The original PDF bytes are automatically forwarded to
 * `verifyTimestamp` so document-hash checks run by default.
 *
 * @param pdfBytes - The PDF document to inspect.
 * @param options - Combined extract+verify options (all optional).
 * @returns One `ExtractedTimestamp` per signature, each with `verified`
 *   reflecting the verify-step outcome.
 *
 * @example
 * ```typescript
 * // EKU enforcement is on by default since 0.2.0; just pass trustStore.
 * const verified = await verifyPdfTimestamps(pdf, { trustStore });
 * console.log(`${verified.filter(t => t.verified).length}/${verified.length} valid`);
 * ```
 */
export async function verifyPdfTimestamps(
    pdfBytes: Uint8Array,
    options: ExtractOptions & Omit<VerificationOptions, "pdf"> = {}
): Promise<ExtractedTimestamp[]> {
    const discovery = await discoverTimestamps(pdfBytes, options, false);
    const timestamps = discovery.timestamps;
    if (timestamps.length === 0) return [];
    let occurrenceIndex: PdfSignatureOccurrenceIndex;
    try {
        occurrenceIndex =
            discovery.occurrenceIndex ??
            new PdfSignatureOccurrenceIndex(
                pdfBytes,
                timestamps.flatMap((timestamp) =>
                    timestamp.contentsObject === undefined ? [] : [timestamp.contentsObject]
                )
            );
    } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        return timestamps.map((timestamp) => ({
            ...timestamp,
            verified: false,
            verificationError: message,
        }));
    }
    return verifyTimestampsWithSharedIndex(timestamps, { ...options, pdf: pdfBytes }, occurrenceIndex);
}
