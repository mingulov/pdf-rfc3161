import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { OID_TO_HASH_ALGORITHM } from "../constants.js";
import { TimestampError, TimestampErrorCode, type TimestampInfo } from "../types.js";
import { bytesToHex } from "../utils.js";

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
        tstInfoBytes = new Uint8Array(eContentAsn1.valueBlock.valueHexView).slice().buffer;
    } else {
        // It might be wrapped in a constructed OCTET STRING
        const eContentAny = eContentAsn1 as { valueBlock?: { value?: asn1js.OctetString[] } };
        if (
            eContentAny.valueBlock?.value &&
            eContentAny.valueBlock.value[0] instanceof asn1js.OctetString
        ) {
            tstInfoBytes = new Uint8Array(
                eContentAny.valueBlock.value[0].valueBlock.valueHexView
            ).slice().buffer;
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

    return {
        genTime: tstInfo.genTime,
        policy: tstInfo.policy,
        serialNumber,
        hashAlgorithm,
        hashAlgorithmOID,
        messageDigest,
        hasCertificate,
    };
}

/**
 * Parses a raw DER encoded timestamp token and extracts the TimestampInfo.
 */
export function parseTimestampToken(token: Uint8Array): TimestampInfo {
    const asn1 = asn1js.fromBER(token.slice().buffer);
    if (asn1.offset === -1) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "Failed to parse timestamp token"
        );
    }

    const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
    return extractTimestampInfoFromContentInfo(contentInfo);
}
