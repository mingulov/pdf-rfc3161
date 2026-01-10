import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
    type ParsedTimestampResponse,
    type TimestampInfo,
} from "../types.js";
import { bytesToHex } from "../utils.js";
import { extractTimestampInfoFromContentInfo } from "../pki/pki-utils.js";

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
        const info = extractTimestampInfoFromContentInfo(tsResp.timeStampToken);

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
    const expectedDigest = bytesToHex(originalHash);
    if (responseInfo.messageDigest.toLowerCase() !== expectedDigest.toLowerCase()) {
        return false;
    }

    return true;
}
