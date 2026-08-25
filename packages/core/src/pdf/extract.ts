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

/**
 * Information about an extracted timestamp signature from a PDF
 */
export interface ExtractedTimestamp {
    /** Timestamp information */
    info: TimestampInfo;
    /** The raw timestamp token (DER-encoded ContentInfo) */
    token: Uint8Array;
    /** Complete decoded /Contents value bytes, including reserved zero padding. */
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
     */
    certificates?: pkijs.Certificate[];
    /** Byte range [offset1, length1, offset2, length2] */
    byteRange: [number, number, number, number];
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

function fieldNameForDiscovery(field: PDFDict, index: number): string {
    const fieldNameObj = field.get(PDFName.of("T"));
    return fieldNameObj
        ? fieldNameObj.toString().replace(/^\(/, "").replace(/\)$/, "")
        : `Signature${index.toString()}`;
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

    const timestamps: ExtractedTimestamp[] = [];
    const malformedFieldNames: string[] = [];

    // Get the AcroForm
    const acroForm = pdfDoc.catalog.lookup(PDFName.of("AcroForm"));
    if (!acroForm || !(acroForm instanceof PDFDict)) {
        return { timestamps, malformedFieldNames };
    }

    // Get fields array
    const fields = acroForm.lookup(PDFName.of("Fields"));
    if (!fields || !(fields instanceof PDFArray)) {
        return { timestamps, malformedFieldNames };
    }

    // Iterate through fields looking for signature fields
    for (let i = 0; i < fields.size(); i++) {
        let recognizedFieldName: string | undefined;
        try {
            const fieldRef = fields.get(i);
            if (!(fieldRef instanceof PDFRef)) continue;

            const field = pdfDoc.context.lookup(fieldRef);
            if (!field || !(field instanceof PDFDict)) continue;

            // Check if it's a signature field (FT = /Sig)
            const ft = field.get(PDFName.of("FT"));
            if (ft?.toString() !== "/Sig") continue;

            const fieldName = fieldNameForDiscovery(field, i);
            const fieldMarksRfc3161 = isRfc3161SubFilter(field.get(PDFName.of("SubFilter")));
            const fieldMarksDocumentTimestamp = isDocumentTimestampType(
                field.get(PDFName.of("Type"))
            );

            // Get the signature value (V). A direct field marker is retained
            // only to surface a malformed RFC 3161 field whose value cannot
            // be resolved as a signature dictionary.
            const sigValueRef = field.get(PDFName.of("V"));
            if (!sigValueRef) {
                if (archiveDetailed && (fieldMarksRfc3161 || fieldMarksDocumentTimestamp)) {
                    recognizedFieldName = fieldName;
                    throw new Error("RFC 3161 document timestamp has no /V dictionary");
                }
                continue;
            }

            let sigValue: PDFDict;
            if (sigValueRef instanceof PDFRef) {
                const looked = pdfDoc.context.lookup(sigValueRef);
                if (!(looked instanceof PDFDict)) {
                    if (archiveDetailed && (fieldMarksRfc3161 || fieldMarksDocumentTimestamp)) {
                        recognizedFieldName = fieldName;
                        throw new Error("RFC 3161 document timestamp /V is not a dictionary");
                    }
                    continue;
                }
                sigValue = looked;
            } else if (sigValueRef instanceof PDFDict) {
                sigValue = sigValueRef;
            } else {
                if (archiveDetailed && (fieldMarksRfc3161 || fieldMarksDocumentTimestamp)) {
                    recognizedFieldName = fieldName;
                    throw new Error("RFC 3161 document timestamp /V is not a dictionary");
                }
                continue;
            }

            // Public extraction keeps its established permissive RFC 3161
            // SubFilter match. Archive renewal is intentionally stricter:
            // the resolved signature value dictionary must carry both exact
            // document-timestamp markers. Field-level markers cannot rescue
            // or invalidate a resolved signature value dictionary.
            const valueMarksRfc3161 = isRfc3161SubFilter(sigValue.get(PDFName.of("SubFilter")));
            const valueMarksDocumentTimestamp = isDocumentTimestampType(sigValue.get(PDFName.of("Type")));
            if (archiveDetailed && valueMarksRfc3161 !== valueMarksDocumentTimestamp) {
                recognizedFieldName = fieldName;
                throw new Error("RFC 3161 document timestamp has an incomplete /Type and /SubFilter pair");
            }
            if (!valueMarksRfc3161) {
                // Neither resolved marker identifies an ordinary signature.
                // Only a reciprocal marker mismatch is malformed above.
                continue;
            }
            recognizedFieldName = fieldName;

            // Extract the Contents (the actual timestamp token)
            const contents = sigValue.get(PDFName.of("Contents"));
            if (!(contents instanceof PDFHexString)) {
                throw new Error("RFC 3161 document timestamp /Contents must be a hex string");
            }

            // Keep the exact decoded PDF value, including all reserved zero padding.
            const contentsBytes = contents.asBytes();

            // Skip if token is all zeros (placeholder)
            if (contentsBytes.every((b) => b === 0)) continue;

            // A signature placeholder is fixed-width and therefore carries
            // zero bytes after the DER token. Derive the token boundary from
            // its outer DER TLV rather than relaxing the strict token parser.
            const token = tokenWithoutPdfContentsPadding(contentsBytes);

            // Extract ByteRange
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

            const brValues = [
                byteRangeStart.asNumber(),
                byteRangeFirstLength.asNumber(),
                byteRangeSecondStart.asNumber(),
                byteRangeSecondLength.asNumber(),
            ] as [number, number, number, number];

            // Parse the timestamp details
            const info = extractTimestampInfo(token);

            // Check if it covers the whole document
            const coversWholeDocument = brValues[2] + brValues[3] === pdfBytes.length;

            // Extract additional optional fields from Signature Dictionary
            let reason: string | undefined;
            const reasonObj = sigValue.get(PDFName.of("Reason"));
            if (reasonObj) {
                reason =
                    reasonObj instanceof PDFHexString
                        ? reasonObj.asString()
                        : reasonObj.toString().replace(/^\(/, "").replace(/\)$/, "");
            }

            let location: string | undefined;
            const locObj = sigValue.get(PDFName.of("Location"));
            if (locObj) {
                location =
                    locObj instanceof PDFHexString
                        ? locObj.asString()
                        : locObj.toString().replace(/^\(/, "").replace(/\)$/, "");
            }

            let contactInfo: string | undefined;
            const ciObj = sigValue.get(PDFName.of("ContactInfo"));
            if (ciObj) {
                contactInfo =
                    ciObj instanceof PDFHexString
                        ? ciObj.asString()
                        : ciObj.toString().replace(/^\(/, "").replace(/\)$/, "");
            }

            let m: Date | undefined;
            const mObj = sigValue.get(PDFName.of("M"));
            if (mObj) {
                m = parsePdfDate(mObj.toString());
            }

            timestamps.push({
                info,
                token,
                contentsValueBytes: contentsBytes.slice(),
                fieldName,
                coversWholeDocument,
                byteRange: brValues,
                verified: false, // Not verified until verifyTimestamp is called
                reason,
                location,
                contactInfo,
                m,
            });
        } catch {
            if (recognizedFieldName !== undefined) {
                malformedFieldNames.push(recognizedFieldName);
            }
            // Skip fields that fail to parse
            continue;
        }
    }

    return { timestamps, malformedFieldNames };
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
export async function verifyTimestamp(
    timestamp: ExtractedTimestamp,
    options: VerificationOptions = {}
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
 * Extracts and verifies every RFC 3161 timestamp in a PDF in one call.
 *
 * Equivalent to `extractTimestamps(pdf, extractOptions)` followed by
 * `Promise.all` over `verifyTimestamp(ts, verifyOptions)`. The original PDF
 * bytes are automatically forwarded to `verifyTimestamp` so document-hash
 * checks run by default.
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
    options: ExtractOptions & VerificationOptions = {}
): Promise<ExtractedTimestamp[]> {
    const timestamps = await extractTimestamps(pdfBytes, options);
    return Promise.all(timestamps.map((ts) => verifyTimestamp(ts, { pdf: pdfBytes, ...options })));
}
