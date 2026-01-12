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
} from "../types.js";
import { hexToBytes, bytesToHex, extractBytesFromByteRange } from "../utils.js";
import { parseTimestampToken } from "../pki/pki-utils.js";

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
 * @returns Array of extracted timestamps
 */
export async function extractTimestamps(pdfBytes: Uint8Array): Promise<ExtractedTimestamp[]> {
    let pdfDoc;
    try {
        pdfDoc = await PDFDocument.load(pdfBytes, {
            updateMetadata: false,
            ignoreEncryption: true, // Try to load even if encrypted (though signatures might fail)
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
                const mStr = mObj
                    .toString()
                    .replace(/^\(/, "")
                    .replace(/\)$/, "")
                    .replace("D:", "");
                // Format: YYYYMMDDHHmmSSOHH'mm' e.g. 20230101120000+00'00'
                // Simple parser attempt
                try {
                    const year = parseInt(mStr.substring(0, 4));
                    const month = parseInt(mStr.substring(4, 6)) - 1;
                    const day = parseInt(mStr.substring(6, 8));
                    const hour = parseInt(mStr.substring(8, 10));
                    const min = parseInt(mStr.substring(10, 12));
                    const sec = parseInt(mStr.substring(12, 14));
                    // Basic UTC Date if no timezone logic for now, or just use Date.parse logic if compatible?
                    // PDF dates are notoriously tricky. Let's try to construct a valid ISO string.
                    // YYYY-MM-DDTHH:mm:ss
                    // TZ info: OHH'mm' e.g. +02'00' or Z
                    let iso = `${String(year)}-${String(month + 1).padStart(2, "0")}-${String(day).padStart(2, "0")}T${String(hour).padStart(2, "0")}:${String(min).padStart(2, "0")}:${String(sec).padStart(2, "0")}`;

                    if (mStr.length > 14) {
                        const rest = mStr.substring(14);
                        // Handle Z
                        if (rest === "Z") iso += "Z";
                        else {
                            // Handle offset +HH'mm' -> +HH:mm
                            const cleanOffset = rest.replace(/^([+-]\d{2})'(\d{2})'$/, "$1:$2");
                            iso += cleanOffset;
                        }
                    } else {
                        iso += "Z"; // Assume UTC if missing
                    }
                    m = new Date(iso);
                    if (isNaN(m.getTime())) m = undefined;
                } catch {
                    // Ignore date parse error
                }
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
 * Verifies an extracted timestamp's cryptographic signature.
 *
 * @param timestamp - The extracted timestamp to verify
 * @param options - Verification options (including optional pdf bytes for hash verification)
 * @returns The timestamp with verification status updated
 */
export async function verifyTimestamp(
    timestamp: ExtractedTimestamp,
    options: VerificationOptions = {}
): Promise<ExtractedTimestamp> {
    try {
        // Step 1: Verify document hash if PDF is provided
        if (options.pdf) {
            const dataToHash = extractBytesFromByteRange(options.pdf, timestamp.byteRange);
            const hashBuffer = await crypto.subtle.digest(
                timestamp.info.hashAlgorithm,
                dataToHash.slice().buffer
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
        const asn1 = asn1js.fromBER(timestamp.token.slice().buffer);
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

        // Hack: pkijs often refuses to use attached content for non-id-data types (like id-ct-TSTInfo).
        // Best fix: Temporarily set type to id-data so pkijs verifies the hash of eContent content.
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

        // Strict PAdES/ESS check
        if (options.strictESSValidation) {
            // Check for signing-certificate (1.2.840.113549.1.9.16.2.12) or signing-certificate-v2 (1.2.840.113549.1.9.16.2.47)
            const signerInfo = signedData.signerInfos[0] as pkijs.SignerInfo | undefined;
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
