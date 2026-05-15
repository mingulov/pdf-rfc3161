import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { OID_TO_HASH_ALGORITHM } from "../constants.js";
import { TimestampError, TimestampErrorCode, type TimestampInfo } from "../types.js";
import { toArrayBuffer, bytesToHex } from "../utils.js";

/**
 * Extracts TimestampInfo from a ContentInfo containing SignedData with TSTInfo.
 * This is a low-level utility shared between response parsing and PDF extraction.
 */
export function extractTimestampInfoFromContentInfo(contentInfo: pkijs.ContentInfo): TimestampInfo {
    // The token is a ContentInfo containing SignedData
    const signedData = new pkijs.SignedData({
        schema: contentInfo.content,
    });

    // The encapsulated content is the TSTInfo
    if (!signedData.encapContentInfo.eContent) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "SignedData does not contain encapsulated TSTInfo"
        );
    }

    // Extract the TSTInfo OctetString content
    const eContentAsn1 = signedData.encapContentInfo.eContent;
    let tstInfoBytes: ArrayBuffer;

    if (eContentAsn1 instanceof asn1js.OctetString) {
        tstInfoBytes = toArrayBuffer(new Uint8Array(eContentAsn1.valueBlock.valueHexView));
    } else {
        // It might be wrapped in a constructed OCTET STRING
        const eContentAny = eContentAsn1 as { valueBlock?: { value?: asn1js.OctetString[] } };
        if (
            eContentAny.valueBlock?.value &&
            eContentAny.valueBlock.value[0] instanceof asn1js.OctetString
        ) {
            tstInfoBytes = toArrayBuffer(new Uint8Array(
                eContentAny.valueBlock.value[0].valueBlock.valueHexView
            ));
        } else {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Cannot extract TSTInfo from encapsulated content"
            );
        }
    }

    // Parse TSTInfo
    const tstInfoAsn1 = asn1js.fromBER(tstInfoBytes);
    if (tstInfoAsn1.offset === -1) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "Failed to parse TSTInfo ASN.1"
        );
    }

    const tstInfo = new pkijs.TSTInfo({ schema: tstInfoAsn1.result });

    // Extract message imprint details
    const hashAlgorithmOID = tstInfo.messageImprint.hashAlgorithm.algorithmId;
    const hashAlgorithm = OID_TO_HASH_ALGORITHM[hashAlgorithmOID] ?? hashAlgorithmOID;
    const messageDigest = bytesToHex(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);

    // Extract serial number
    const serialNumber = bytesToHex(tstInfo.serialNumber.valueBlock.valueHexView);

    // Check if certificate was included
    const hasCertificate =
        signedData.certificates !== undefined && signedData.certificates.length > 0;

    // Detect ESSCertID vs ESSCertIDv2 format
    let certIdHashAlgorithm: "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512" | undefined;
    let usesESSCertIDv2: boolean | undefined;

    if (signedData.signerInfos.length > 0) {
        const signerInfo = signedData.signerInfos[0] as pkijs.SignerInfo & {
            signingCertificateV2?: {
                certs?: {
                    hashAlgorithm?: { algorithmId: string };
                }[];
            };
            signingCertificate?: unknown;
        };

        // Check for ESSCertIDv2 (RFC 5816) - signingCertificateV2 attribute
        if (signerInfo.signingCertificateV2) {
            usesESSCertIDv2 = true;
            // Extract hash algorithm from the certID in signingCertificateV2
            const signingCertV2 = signerInfo.signingCertificateV2;
            if (signingCertV2.certs && signingCertV2.certs.length > 0) {
                const certID = signingCertV2.certs[0];
                if (certID?.hashAlgorithm?.algorithmId) {
                    const oid = certID.hashAlgorithm.algorithmId;
                    certIdHashAlgorithm = OID_TO_HASH_ALGORITHM[oid] as
                        | "SHA-1"
                        | "SHA-256"
                        | "SHA-384"
                        | "SHA-512";
                }
            }
        }
        // Check for legacy ESSCertID - signingCertificate attribute
        else if (signerInfo.signingCertificate) {
            usesESSCertIDv2 = false;
            // Legacy ESSCertID always uses SHA-1 for certificate identification
            certIdHashAlgorithm = "SHA-1";
        }
    }

    // Extract nonce (optional in TSTInfo) for replay-defence checks
    let nonce: Uint8Array | undefined;
    const tstInfoWithNonce = tstInfo as pkijs.TSTInfo & { nonce?: asn1js.Integer };
    if (tstInfoWithNonce.nonce) {
        nonce = new Uint8Array(tstInfoWithNonce.nonce.valueBlock.valueHexView);
    }

    return {
        genTime: tstInfo.genTime,
        policy: tstInfo.policy,
        serialNumber,
        hashAlgorithm,
        hashAlgorithmOID,
        messageDigest,
        hasCertificate,
        certIdHashAlgorithm,
        usesESSCertIDv2,
        nonce,
    };
}

/**
 * Parses a raw DER encoded timestamp token and extracts the TimestampInfo.
 */
export function parseTimestampToken(token: Uint8Array): TimestampInfo {
    try {
        const asn1 = asn1js.fromBER(toArrayBuffer(token));
        if (asn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse timestamp token"
            );
        }

        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        return extractTimestampInfoFromContentInfo(contentInfo);
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        // PKI.js might throw generic Error if schema verification fails
        // or RangeError if there's a stack overflow on deep structures
        const message = error instanceof Error ? error.message : "Unknown error";
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `Failed to parse timestamp token: ${message}`
        );
    }
}

/** OID for ExtendedKeyUsage extension (RFC 5280) */
const EKU_EXTENSION_OID = "2.5.29.37";
/** OID for id-kp-timeStamping (RFC 3161 Sec. 2.3) */
const ID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
/** OID for anyExtendedKeyUsage (RFC 5280) */
const ID_ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

/**
 * Reports whether a certificate is valid at a given point in time
 * (notBefore <= time <= notAfter). Returns false defensively when the
 * cert is missing either bound -- callers should treat that as
 * "do not trust" rather than "trust by default".
 */
export function isCertValidAtTime(cert: pkijs.Certificate, time: Date): boolean {
    const notBefore = cert.notBefore.value as unknown;
    const notAfter = cert.notAfter.value as unknown;
    if (!(notBefore instanceof Date) || !(notAfter instanceof Date)) {
        return false;
    }
    return time.getTime() >= notBefore.getTime() && time.getTime() <= notAfter.getTime();
}

/**
 * Reports whether a certificate's ExtendedKeyUsage allows the timestamping
 * role per RFC 3161 Sec. 2.3. Accepts the explicit id-kp-timeStamping OID or
 * anyExtendedKeyUsage (the catch-all from RFC 5280). Returns false when no
 * EKU extension is present -- this rejects certs that haven't been issued
 * specifically for the TSA role, which is the whole point of the check.
 */
export function hasTimestampingEKU(cert: pkijs.Certificate): boolean {
    if (!cert.extensions) {
        return false;
    }
    for (const ext of cert.extensions) {
        if (ext.extnID !== EKU_EXTENSION_OID) {
            continue;
        }
        try {
            const parsed = asn1js.fromBER(ext.extnValue.valueBlock.valueHexView);
            if (parsed.offset === -1 || !(parsed.result instanceof asn1js.Sequence)) {
                return false;
            }
            for (const item of parsed.result.valueBlock.value) {
                if (item instanceof asn1js.ObjectIdentifier) {
                    const oid = item.valueBlock.toString();
                    if (oid === ID_KP_TIMESTAMPING || oid === ID_ANY_EXTENDED_KEY_USAGE) {
                        return true;
                    }
                }
            }
            return false;
        } catch {
            return false;
        }
    }
    return false;
}
