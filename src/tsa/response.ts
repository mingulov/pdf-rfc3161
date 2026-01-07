import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { OID_TO_HASH_ALGORITHM } from "../constants.js";
import {
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
    type ParsedTimestampResponse,
    type TimestampInfo,
} from "../types.js";

/**
 * Parses an RFC 3161 TimeStampResp from DER-encoded bytes.
 *
 * @param responseBytes - The DER-encoded TimeStampResp
 * @returns Parsed timestamp response with status and token
 * @throws TimestampError if the response cannot be parsed
 */
export function parseTimestampResponse(responseBytes: Uint8Array): ParsedTimestampResponse {
    try {
        // Parse the ASN.1 structure
        const asn1 = asn1js.fromBER(responseBytes.slice().buffer);
        if (asn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse ASN.1 structure"
            );
        }

        // Create TimeStampResp from the parsed ASN.1
        const tsResp = new pkijs.TimeStampResp({ schema: asn1.result });

        // Extract status information - pkijs returns a number
        const statusValue = tsResp.status.status as number;
        let statusString: string | undefined;
        let failInfo: number | undefined;

        if (tsResp.status.statusStrings && tsResp.status.statusStrings.length > 0) {
            statusString = tsResp.status.statusStrings.map((s) => s.valueBlock.value).join("; ");
        }

        if (tsResp.status.failInfo) {
            failInfo = tsResp.status.failInfo.valueBlock.valueHexView[0];
        }

        // Map to our TSAStatus enum
        const status = statusValue as TSAStatus;

        // If status is not granted, return early
        if (status !== TSAStatus.GRANTED && status !== TSAStatus.GRANTED_WITH_MODS) {
            return {
                status,
                statusString,
                failInfo,
            };
        }

        // Extract the timestamp token
        if (!tsResp.timeStampToken) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "TimeStampResp is granted but contains no token"
            );
        }

        // Encode the token back to DER for embedding
        const tokenSchema = tsResp.timeStampToken.toSchema();
        const tokenBytes = new Uint8Array(tokenSchema.toBER(false));

        // Parse TSTInfo from the token to extract timestamp details
        const info = extractTimestampInfo(tsResp.timeStampToken);

        return {
            status,
            statusString,
            token: tokenBytes,
            info,
        };
    } catch (error) {
        if (error instanceof TimestampError) {
            throw error;
        }
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `Failed to parse timestamp response: ${error instanceof Error ? error.message : String(error)}`,
            error
        );
    }
}

/**
 * Extracts TimestampInfo from a ContentInfo containing SignedData with TSTInfo.
 */
function extractTimestampInfo(contentInfo: pkijs.ContentInfo): TimestampInfo {
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
        // Cast to access the internal structure - asn1js uses dynamic types
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
    const messageDigest = bufferToHex(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView);

    // Extract serial number
    const serialNumber = bufferToHex(tstInfo.serialNumber.valueBlock.valueHexView);

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
 * Converts an ArrayBuffer or Uint8Array to a hex string.
 */
function bufferToHex(buffer: ArrayBuffer | Uint8Array): string {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    return Array.from(bytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
}

/**
 * Validates that a timestamp response matches the original request.
 *
 * @param responseInfo - Parsed timestamp info
 * @param originalHash - The hash that was sent in the request
 * @param hashAlgorithm - The algorithm used for hashing
 * @returns true if the response matches the request
 */
export function validateTimestampResponse(
    responseInfo: TimestampInfo,
    originalHash: Uint8Array,
    hashAlgorithm: string
): boolean {
    // Verify the hash algorithm matches
    if (responseInfo.hashAlgorithm !== hashAlgorithm) {
        return false;
    }

    // Verify the message digest matches
    const expectedDigest = bufferToHex(originalHash);
    if (responseInfo.messageDigest.toLowerCase() !== expectedDigest.toLowerCase()) {
        return false;
    }

    return true;
}
