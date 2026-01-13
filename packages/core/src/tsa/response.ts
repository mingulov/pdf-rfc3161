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
import { getLogger } from "../utils/logger.js";
import { extractTimestampInfoFromContentInfo } from "../pki/pki-utils.js";

interface StatusInfo {
    status: TSAStatus;
    statusString?: string;
    failInfo?: number;
}

/**
 * Attempts to extract status information from an ASN.1 block without using pkijs.
 * Used as fallback when pkijs schema validation fails.
 */
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/prefer-optional-chain */
function tryExtractStatusFromASN1(asn1Block: unknown): StatusInfo | null {
    try {
        const result: StatusInfo = { status: TSAStatus.GRANTED };

        const block = asn1Block;
        if (!block || typeof block !== "object") {
            return null;
        }

        const getField = (keys: number[]): any => {
            let current: any = block;
            for (const key of keys) {
                if (current && typeof current === "object" && key in current) {
                    current = current[key];
                } else {
                    return null;
                }
            }
            return current;
        };

        const innerSequence = getField([0]);
        if (
            innerSequence &&
            innerSequence.valueBlock &&
            Array.isArray(innerSequence.valueBlock.value)
        ) {
            const statusValue = innerSequence.valueBlock.value[0];
            if (statusValue && statusValue.valueBlock) {
                if (Array.isArray(statusValue.valueBlock.valueHexView)) {
                    result.status = statusValue.valueBlock.valueHexView[0] as TSAStatus;
                } else if (typeof statusValue.valueBlock.value === "number") {
                    result.status = statusValue.valueBlock.value as TSAStatus;
                }
            }

            if (innerSequence.valueBlock.value[1]) {
                const statusStringValue = innerSequence.valueBlock.value[1];
                if (
                    statusStringValue &&
                    statusStringValue.valueBlock &&
                    Array.isArray(statusStringValue.valueBlock.value)
                ) {
                    const utf8String = statusStringValue.valueBlock.value[0];
                    if (utf8String && utf8String.valueBlock && utf8String.valueBlock.value) {
                        result.statusString = utf8String.valueBlock.value;
                    }
                }
            }

            if (innerSequence.valueBlock.value[2]) {
                const failInfoValue = innerSequence.valueBlock.value[2];
                if (
                    failInfoValue &&
                    failInfoValue.valueBlock &&
                    Array.isArray(failInfoValue.valueBlock.valueHexView)
                ) {
                    result.failInfo = failInfoValue.valueBlock.valueHexView[0];
                }
            }
        }

        return result;
    } catch {
        return null;
    }
}
/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/prefer-optional-chain */

/**
 * Attempts to extract the timeStampToken from an ASN.1 block without using pkijs.
 * Used as fallback when pkijs schema validation fails.
 */
/* eslint-disable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call */
function tryExtractTokenFromASN1(asn1Block: unknown): Uint8Array | null {
    try {
        if (!asn1Block || typeof asn1Block !== "object") {
            return null;
        }

        const getField = (keys: number[]): any => {
            let current: any = asn1Block;
            for (const key of keys) {
                if (current && typeof current === "object" && key in current) {
                    current = current[key];
                } else {
                    return null;
                }
            }
            return current;
        };

        const timeStampToken = getField([1]);
        if (timeStampToken) {
            try {
                const schema = timeStampToken.toSchema();
                return new Uint8Array(schema.toBER(false));
            } catch {
                return null;
            }
        }

        return null;
    } catch {
        return null;
    }
}
/* eslint-enable @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call */

/**
 * Attempts to extract timestamp info from a token's ContentInfo structure.
 */
function tryExtractInfoFromToken(tokenBytes: Uint8Array): TimestampInfo | null {
    try {
        const asn1 = asn1js.fromBER(tokenBytes.slice().buffer);
        if (asn1.offset === -1) {
            return null;
        }

        const contentInfo = new pkijs.ContentInfo({ schema: asn1.result });
        return extractTimestampInfoFromContentInfo(contentInfo);
    } catch {
        return null;
    }
}

/**
 * Parses an RFC 3161 TimeStampResp from DER-encoded bytes.
 *
 * @param responseBytes - The DER-encoded TimeStampResp
 * @returns Parsed timestamp response with status and token
 * @throws TimestampError if the response cannot be parsed
 */
export function parseTimestampResponse(responseBytes: Uint8Array): ParsedTimestampResponse {
    // Validate response is not empty
    if (responseBytes.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "TSA returned empty response"
        );
    }

    // Validate minimum response size (a valid TimeStampResp with status=0 needs at least ~11 bytes)
    if (responseBytes.length < 11) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `TSA response too small (${responseBytes.length.toString()} bytes), expected at least 11 bytes for valid TimeStampResp`
        );
    }

    try {
        const asn1 = asn1js.fromBER(responseBytes.slice().buffer);
        if (asn1.offset === -1) {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Failed to parse ASN.1 structure"
            );
        }

        let tsResp: pkijs.TimeStampResp | null = null;
        let extractedStatus: StatusInfo | null = null;

        try {
            tsResp = new pkijs.TimeStampResp({ schema: asn1.result });
        } catch (schemaError) {
            extractedStatus = tryExtractStatusFromASN1(asn1.result);
            if (!extractedStatus) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    `Failed to parse timestamp response: ${schemaError instanceof Error ? schemaError.message : String(schemaError)}`,
                    schemaError
                );
            }
        }

        let status: TSAStatus;
        let statusString: string | undefined;
        let failInfo: number | undefined;

        if (extractedStatus) {
            status = extractedStatus.status;
            statusString = extractedStatus.statusString;
            failInfo = extractedStatus.failInfo;
        } else if (tsResp) {
            const statusValue = tsResp.status.status as number;
            status = statusValue as TSAStatus;
            if (tsResp.status.statusStrings && tsResp.status.statusStrings.length > 0) {
                statusString = tsResp.status.statusStrings
                    .map((s) => s.valueBlock.value)
                    .join("; ");
            }
            if (tsResp.status.failInfo) {
                failInfo = tsResp.status.failInfo.valueBlock.valueHexView[0];
            }
        } else {
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "Could not parse timestamp response status"
            );
        }

        if (
            status !== TSAStatus.GRANTED &&
            status !== TSAStatus.GRANTED_WITH_MODS &&
            status !== TSAStatus.REVOCATION_WARNING &&
            status !== TSAStatus.REVOCATION_NOTIFICATION
        ) {
            return {
                status,
                statusString,
                failInfo,
            };
        }

        if (
            status === TSAStatus.REVOCATION_WARNING ||
            status === TSAStatus.REVOCATION_NOTIFICATION
        ) {
            const statusName =
                status === TSAStatus.REVOCATION_WARNING
                    ? "REVOCATION_WARNING"
                    : "REVOCATION_NOTIFICATION";
            getLogger().warn(
                `TSA returned ${statusName}: ${statusString ?? "Response is valid but a revocation is pending."}`
            );
        }

        if (!tsResp?.timeStampToken) {
            const manuallyExtractedToken = tryExtractTokenFromASN1(asn1.result);
            if (manuallyExtractedToken) {
                const info = tryExtractInfoFromToken(manuallyExtractedToken);
                return {
                    status,
                    statusString,
                    token: manuallyExtractedToken,
                    info: info ?? undefined,
                };
            }
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                `TimeStampResp status was extracted (status=${String(status as number)}) but no token found - TSA response may be incomplete or malformed (statusString: ${statusString ?? "none"})`
            );
        }

        const tokenSchema = tsResp.timeStampToken.toSchema();
        const tokenBytes = new Uint8Array(tokenSchema.toBER(false));

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
 * @param responseInfo - The parsed timestamp info from the response
 * @param originalHash - The hash that was sent to the TSA
 * @param hashAlgorithm - The hash algorithm that was used
 * @returns true if the response is valid for the request
 */
export function validateTimestampResponse(
    responseInfo: TimestampInfo,
    originalHash: Uint8Array,
    hashAlgorithm: string
): boolean {
    if (responseInfo.hashAlgorithm !== hashAlgorithm) {
        return false;
    }

    const expectedDigest = bytesToHex(originalHash);
    if (responseInfo.messageDigest.toLowerCase() !== expectedDigest.toLowerCase()) {
        return false;
    }

    return true;
}
