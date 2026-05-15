import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
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
import { toArrayBuffer, hexToBytes, bytesToHex, extractBytesFromByteRange } from "../utils.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";
import { parsePdfDate } from "../utils/pdf-date.js";
import { parseTimestampToken, hasTimestampingEKU, isCertValidAtTime } from "../pki/pki-utils.js";

/**
 * Information about an extracted timestamp signature from a PDF
 */
export interface ExtractedTimestamp {
    /** Timestamp information */
    info: TimestampInfo;
    /** The raw timestamp token (DER-encoded ContentInfo) */
    token: Uint8Array;
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

    // Get the AcroForm
    const acroForm = pdfDoc.catalog.lookup(PDFName.of("AcroForm"));
    if (!acroForm || !(acroForm instanceof PDFDict)) {
        return timestamps;
    }

    // Get fields array
    const fields = acroForm.lookup(PDFName.of("Fields"));
    if (!fields || !(fields instanceof PDFArray)) {
        return timestamps;
    }

    // Iterate through fields looking for signature fields
    for (let i = 0; i < fields.size(); i++) {
        try {
            const fieldRef = fields.get(i);
            if (!(fieldRef instanceof PDFRef)) continue;

            const field = pdfDoc.context.lookup(fieldRef);
            if (!field || !(field instanceof PDFDict)) continue;

            // Check if it's a signature field (FT = /Sig)
            const ft = field.get(PDFName.of("FT"));
            if (ft?.toString() !== "/Sig") continue;

            // Get the signature value (V)
            const sigValueRef = field.get(PDFName.of("V"));
            if (!sigValueRef) continue;

            let sigValue: PDFDict;
            if (sigValueRef instanceof PDFRef) {
                const looked = pdfDoc.context.lookup(sigValueRef);
                if (!(looked instanceof PDFDict)) continue;
                sigValue = looked;
            } else if (sigValueRef instanceof PDFDict) {
                sigValue = sigValueRef;
            } else {
                continue;
            }

            // Check if it's an RFC 3161 timestamp (SubFilter = /ETSI.RFC3161)
            const subFilter = sigValue.get(PDFName.of("SubFilter"));
            if (!subFilter?.toString().includes("ETSI.RFC3161")) continue;

            // Get field name
            const fieldNameObj = field.get(PDFName.of("T"));
            const fieldName = fieldNameObj
                ? fieldNameObj.toString().replace(/^\(/, "").replace(/\)$/, "")
                : `Signature${i.toString()}`;

            // Extract the Contents (the actual timestamp token)
            const contents = sigValue.get(PDFName.of("Contents"));
            if (!contents || !(contents instanceof PDFHexString)) continue;

            // Convert hex string to bytes
            const tokenHex = contents.asString();
            const token = hexToBytes(tokenHex);

            // Skip if token is all zeros (placeholder)
            if (token.every((b) => b === 0)) continue;

            // Extract ByteRange
            const byteRange = sigValue.get(PDFName.of("ByteRange"));
            if (!(byteRange instanceof PDFArray) || byteRange.size() !== 4) continue;

            const brValues = [
                (byteRange.get(0) as PDFNumber).asNumber(),
                (byteRange.get(1) as PDFNumber).asNumber(),
                (byteRange.get(2) as PDFNumber).asNumber(),
                (byteRange.get(3) as PDFNumber).asNumber(),
            ] as [number, number, number, number];

            // Parse the timestamp details
            const info = parseTimestampToken(token);

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
            // Skip fields that fail to parse
            continue;
        }
    }

    return timestamps;
}

/**
 * Verifies an extracted timestamp's cryptographic signature and trust
 * properties.
 *
 * The verification runs in order:
 *   1. (optional, when `options.pdf` is supplied) The document's
 *      ByteRange hash matches the messageImprint inside the TSTInfo.
 *   2. The SignedData's `eContentType` is `id-ct-TSTInfo` (1.2.840.113549.1.9.16.1.4)
 *      -- not the bare `id-data` workaround value (H2 guard).
 *   3. pkijs `signedData.verify(...)` confirms the signature math.
 *   4. (optional, when `options.trustStore` is supplied) The certificate
 *      chain validates against the supplied trust store.
 *   5. (optional, when `options.requireTimestampingEKU`) The signing
 *      certificate carries `id-kp-timeStamping` (1.3.6.1.5.5.7.3.8) or
 *      `anyExtendedKeyUsage` (G1).
 *   6. (optional, when `options.requireCertValidAtGenTime`) The signing
 *      certificate is valid at the genTime in the token (G2).
 *   7. (optional, when `options.strictESSValidation`) The ESS / ESSv2
 *      signing-certificate attribute is present.
 *
 * @param timestamp - The {@link ExtractedTimestamp} to verify.
 * @param options - Optional {@link VerificationOptions}.
 * @returns The same `timestamp` object with `verified` and possibly
 *   `verificationError` and `certificates` populated.
 *
 * @example
 * Basic verify (signature math only):
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
        // Step 1: Verify document hash if PDF is provided
        if (options.pdf) {
            await ensureWebCrypto();
            const dataToHash = extractBytesFromByteRange(options.pdf, timestamp.byteRange);
            const hashBuffer = await crypto.subtle.digest(
                timestamp.info.hashAlgorithm,
                toArrayBuffer(dataToHash)
            );
            const actualHash = bytesToHex(hashBuffer);

            if (actualHash.toLowerCase() !== timestamp.info.messageDigest.toLowerCase()) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: `Document hash mismatch. Expected ${timestamp.info.messageDigest}, found ${actualHash}`,
                };
            }
        }

        // Step 2: Verify cryptographic signature of the token
        const asn1 = asn1js.fromBER(toArrayBuffer(timestamp.token));
        if (asn1.offset === -1) {
            return {
                ...timestamp,
                verified: false,
                verificationError: "Failed to parse timestamp token",
            };
        }

        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        const signedData = new pkijs.SignedData({ schema: contentInfo.content });

        // Extract certificates to include in result
        const certificates: pkijs.Certificate[] = [];
        if (signedData.certificates) {
            for (const cert of signedData.certificates) {
                if (cert instanceof pkijs.Certificate) {
                    certificates.push(cert);
                } else {
                    // Handle CertificateSet member
                    try {
                        const certAsn1 = asn1js.fromBER(cert.toSchema().toBER(false));
                        certificates.push(new pkijs.Certificate({ schema: certAsn1.result }));
                    } catch {
                        // Ignore unparseable certs
                    }
                }
            }
        }

        // H2 guard: an attacker could craft a SignedData whose eContentType is
        // id-data (1.2.840.113549.1.7.1) with arbitrary content and a valid
        // signature -- without this check, the override below would silently
        // accept it as a "valid timestamp". A legitimate RFC 3161 token MUST
        // declare eContentType = id-ct-TSTInfo (1.2.840.113549.1.9.16.1.4).
        const TSTINFO_OID = "1.2.840.113549.1.9.16.1.4";
        const originalEContentType = signedData.encapContentInfo.eContentType;
        if (originalEContentType !== TSTINFO_OID) {
            return {
                ...timestamp,
                verified: false,
                verificationError: `Invalid content type: expected id-ct-TSTInfo (${TSTINFO_OID}), got ${originalEContentType}`,
                certificates,
            };
        }

        // Workaround: pkijs refuses to use attached content for non-id-data types
        // (including id-ct-TSTInfo). Temporarily set the type to id-data so pkijs
        // verifies the hash of the eContent. The H2 guard above ensures we only
        // reach this point for legitimate TSTInfo content.
        signedData.encapContentInfo.eContentType = "1.2.840.113549.1.7.1"; // id-data

        const crlCount = signedData.crls?.length ?? 0;
        const ocspCount = (signedData as unknown as { ocsps?: unknown[] }).ocsps?.length ?? 0;

        // Verify the SignedData structure (cryptographic integrity)
        const verifyResult = await signedData.verify({
            signer: 0,
            checkChain: false,
            extendedMode: true,
        });

        if (!verifyResult.signatureVerified) {
            return {
                ...timestamp,
                verified: false,
                verificationError: "Signature verification failed",
                certificates,
            };
        }

        // If trust store is provided, verify the certificate chain
        if (options.trustStore) {
            // Use the extracted certificates
            const isTrusted = await options.trustStore.verifyChain(certificates);
            if (!isTrusted) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: "Certificate chain not trusted",
                    certificates,
                };
            }
        }

        // G1: enforce id-kp-timeStamping ExtendedKeyUsage on the signing cert
        // (RFC 3161 Sec. 2.3). Defaults to `true` since 0.2.0 -- callers who
        // need to verify legacy tokens that pre-date the EKU requirement can
        // opt out with `requireTimestampingEKU: false`. The first cert in
        // `signedData.certificates` is by convention the signing TSA cert.
        const requireEKU = options.requireTimestampingEKU ?? true;
        if (requireEKU) {
            const signingCert = certificates[0];
            if (!signingCert) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "requireTimestampingEKU: no signing certificate available to check",
                    certificates,
                };
            }
            if (!hasTimestampingEKU(signingCert)) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "Signing certificate is missing id-kp-timeStamping (1.3.6.1.5.5.7.3.8) ExtendedKeyUsage required by RFC 3161 Sec. 2.3",
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
            const signingCert = certificates[0];
            const genTime = timestamp.info.genTime;
            if (!signingCert) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "requireCertValidAtGenTime: no signing certificate available to check",
                    certificates,
                };
            }
            if (!(genTime instanceof Date)) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "requireCertValidAtGenTime: token has no genTime to compare against",
                    certificates,
                };
            }
            if (!isCertValidAtTime(signingCert, genTime)) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: `Signing certificate was not valid at genTime ${genTime.toISOString()} (notBefore=${signingCert.notBefore.value instanceof Date ? signingCert.notBefore.value.toISOString() : "unknown"}, notAfter=${signingCert.notAfter.value instanceof Date ? signingCert.notAfter.value.toISOString() : "unknown"})`,
                    certificates,
                };
            }
        }

        // Strict PAdES/ESS check
        if (options.strictESSValidation) {
            // Check for signing-certificate (1.2.840.113549.1.9.16.2.12) or signing-certificate-v2 (1.2.840.113549.1.9.16.2.47)
            const signerInfo = signedData.signerInfos[0];
            if (!signerInfo) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError: "Strict validation: SignerInfo missing",
                    certificates,
                };
            }

            let hasESS = false;
            if (signerInfo.signedAttrs?.attributes) {
                for (const attr of signerInfo.signedAttrs.attributes) {
                    const oid = attr.type;
                    if (
                        oid === "1.2.840.113549.1.9.16.2.12" ||
                        oid === "1.2.840.113549.1.9.16.2.47"
                    ) {
                        hasESS = true;
                        break;
                    }
                }
            }

            if (!hasESS) {
                return {
                    ...timestamp,
                    verified: false,
                    verificationError:
                        "Strict validation: Missing 'signing-certificate' or 'signing-certificate-v2' (ESS) attribute",
                    certificates,
                };
            }
        }

        return {
            ...timestamp,
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
    return Promise.all(
        timestamps.map((ts) => verifyTimestamp(ts, { pdf: pdfBytes, ...options }))
    );
}
