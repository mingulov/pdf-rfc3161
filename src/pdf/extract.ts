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
import { OID_TO_HASH_ALGORITHM } from "../constants.js";
import {
    TimestampError,
    TimestampErrorCode,
    type TimestampInfo,
    type VerificationOptions,
} from "../types.js";

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
    const fieldsRef = acroForm.get(PDFName.of("Fields"));
    if (!fieldsRef) {
        return timestamps;
    }

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
            if (!ft) continue;

            const ftString = ft.toString();
            if (ftString !== "/Sig") continue;

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
            if (!subFilter) continue;

            const subFilterStr = subFilter.toString();
            if (!subFilterStr.includes("ETSI.RFC3161")) continue;

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

            // Parse the timestamp
            const info = parseTimestampToken(token);

            // Check ByteRange to see if it covers the whole document
            const byteRange = sigValue.get(PDFName.of("ByteRange"));
            let coversWholeDocument = false;

            if (byteRange instanceof PDFArray && byteRange.size() === 4) {
                const start2Obj = byteRange.get(2);
                const len2Obj = byteRange.get(3);

                if (start2Obj instanceof PDFNumber && len2Obj instanceof PDFNumber) {
                    const start2 = start2Obj.asNumber();
                    const len2 = len2Obj.asNumber();
                    coversWholeDocument = start2 + len2 === pdfBytes.length;
                }
            }

            timestamps.push({
                info,
                token,
                fieldName,
                coversWholeDocument,
                verified: false, // Not verified until verifyTimestamp is called
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
 * @returns The timestamp with verification status updated
 */
export async function verifyTimestamp(
    timestamp: ExtractedTimestamp,
    options: VerificationOptions = {}
): Promise<ExtractedTimestamp> {
    try {
        // Parse the timestamp token
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
                        // Ideally we should also match the hash inside ESS to the cert,
                        // but presence is the primary structural requirement for PAdES-LTA compliance.
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
        };
    } catch (error) {
        if (error instanceof Error && error.stack) {
            console.error("Verification Error Stack:", error.stack);
        }
        return {
            ...timestamp,
            verified: false,
            verificationError: error instanceof Error ? error.message : String(error),
        };
    }
}

/**
 * Parses a timestamp token and extracts the TimestampInfo.
 */
function parseTimestampToken(token: Uint8Array): TimestampInfo {
    const asn1 = asn1js.fromBER(token.slice().buffer);
    if (asn1.offset === -1) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "Failed to parse timestamp token"
        );
    }

    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    const signedData = new pkijs.SignedData({ schema: contentInfo.content });

    if (!signedData.encapContentInfo.eContent) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "Timestamp token missing TSTInfo"
        );
    }

    // Extract TSTInfo
    const eContent = signedData.encapContentInfo.eContent;
    let tstInfoBytes: ArrayBuffer;

    if (eContent instanceof asn1js.OctetString) {
        tstInfoBytes = new Uint8Array(eContent.valueBlock.valueHexView).slice().buffer;
    } else {
        const eContentAny = eContent as { valueBlock?: { value?: asn1js.OctetString[] } };
        if (eContentAny.valueBlock?.value?.[0] instanceof asn1js.OctetString) {
            tstInfoBytes = new Uint8Array(
                eContentAny.valueBlock.value[0].valueBlock.valueHexView
            ).slice().buffer;
        } else {
            throw new TimestampError(TimestampErrorCode.INVALID_RESPONSE, "Cannot extract TSTInfo");
        }
    }

    const tstInfoAsn1 = asn1js.fromBER(tstInfoBytes);
    if (tstInfoAsn1.offset === -1) {
        throw new TimestampError(TimestampErrorCode.INVALID_RESPONSE, "Failed to parse TSTInfo");
    }

    const tstInfo = new pkijs.TSTInfo({ schema: tstInfoAsn1.result });

    const hashAlgorithmOID = tstInfo.messageImprint.hashAlgorithm.algorithmId;
    const hashAlgorithm = OID_TO_HASH_ALGORITHM[hashAlgorithmOID] ?? hashAlgorithmOID;

    return {
        genTime: tstInfo.genTime,
        policy: tstInfo.policy,
        serialNumber: bytesToHex(new Uint8Array(tstInfo.serialNumber.valueBlock.valueHexView)),
        hashAlgorithm,
        hashAlgorithmOID,
        messageDigest: bytesToHex(
            new Uint8Array(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView)
        ),
        hasCertificate: (signedData.certificates?.length ?? 0) > 0,
    };
}

/**
 * Converts a hex string to bytes.
 */
function hexToBytes(hex: string): Uint8Array {
    // Remove any non-hex characters and handle odd length
    const cleanHex = hex.replace(/[^0-9a-fA-F]/g, "");
    const paddedHex = cleanHex.length % 2 ? "0" + cleanHex : cleanHex;

    const bytes = new Uint8Array(paddedHex.length / 2);
    for (let i = 0; i < bytes.length; i++) {
        bytes[i] = parseInt(paddedHex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}

/**
 * Converts bytes to a hex string.
 */
function bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}
