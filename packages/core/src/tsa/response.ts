import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import {
    TimestampError,
    TimestampErrorCode,
    TSAStatus,
    type ParsedTimestampResponse,
    type TimestampInfo,
} from "../types.js";
import { toArrayBuffer, bytesToHex } from "../utils.js";
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
 *
 * Arch-2 note: the two `tryExtract*` helpers below reach into asn1js's
 * internal ValueBlock structure to recover from schema-validation failures
 * (some TSAs emit slightly-non-conformant DER). asn1js does not expose
 * stable public types for these internals, so the helpers use `any` plus
 * structural type guards rather than typed access. Refactoring this would
 * require either forking asn1js or duplicating its internal schemas; out
 * of scope for 0.2.0. The functions are well-covered by tests
 * (tsa-response.test.ts + integration round-trips), so the type-safety
 * gap is bounded.
 */
function isObject(x: unknown): x is Record<PropertyKey, unknown> {
    return typeof x === "object" && x !== null;
}

function getField(root: unknown, keys: PropertyKey[]): unknown {
    let current: unknown = root;
    for (const key of keys) {
        if (!isObject(current) || !(key in current)) return null;
        current = current[key];
    }
    return current;
}

function tryExtractStatusFromASN1(asn1Block: unknown): StatusInfo | null {
    try {
        // Audit F9: do NOT default `status` to GRANTED. The fall-back parser
        // is reached when pkijs's schema validation rejects bytes that still
        // parsed as ASN.1. Defaulting an unknown blob to "granted" is unsafe --
        // downstream code (and external consumers via parseTimestampResponse)
        // would treat the response as valid even though we never identified
        // a real PKIStatus.
        //
        // If we cannot pin a real PKIStatus, return null so the caller throws
        // INVALID_RESPONSE rather than silently labelling the input "granted".
        //
        // Implementation note: asn1js Sequence objects expose children at
        // `valueBlock.value` (an array), NOT as indexed properties. Earlier
        // versions of this helper used `getField(asn1Block, [0])`, which
        // tested `0 in asn1Block` -- always false for asn1js objects -- and
        // so silently fell through to the default. Walk the structure
        // explicitly here so the extraction actually works.
        if (!isObject(asn1Block) || !isObject(asn1Block.valueBlock)) return null;
        const outerValue: unknown = asn1Block.valueBlock.value;
        if (!Array.isArray(outerValue)) return null;
        const outerChildren = outerValue as unknown[];

        const innerSequence = outerChildren[0];
        if (!isObject(innerSequence) || !isObject(innerSequence.valueBlock)) return null;
        const innerValue: unknown = innerSequence.valueBlock.value;
        if (!Array.isArray(innerValue)) return null;
        const seqValues = innerValue as unknown[];

        // Only proceed if seqValues[0] actually parses as an INTEGER-shaped
        // status value. Otherwise this isn't a PKIStatusInfo SEQUENCE.
        const statusValue = seqValues[0];
        if (!isObject(statusValue) || !isObject(statusValue.valueBlock)) return null;

        const result: StatusInfo = { status: TSAStatus.GRANTED };
        {
            const vb = statusValue.valueBlock;
            const hexView = vb.valueHexView;
            const numericValue = vb.value;
            if (
                (Array.isArray(hexView) || hexView instanceof Uint8Array) &&
                hexView.length > 0
            ) {
                result.status = (hexView as ArrayLike<number>)[0] as TSAStatus;
            } else if (typeof numericValue === "number") {
                result.status = numericValue as TSAStatus;
            } else {
                // No identifiable status value -- bail rather than guess.
                return null;
            }
        }

        const statusStringValue = seqValues[1];
        if (isObject(statusStringValue) && isObject(statusStringValue.valueBlock)) {
            const stringValues = statusStringValue.valueBlock.value;
            if (Array.isArray(stringValues)) {
                const utf8 = stringValues[0] as unknown;
                if (isObject(utf8) && isObject(utf8.valueBlock)) {
                    const v = utf8.valueBlock.value;
                    if (typeof v === "string") result.statusString = v;
                }
            }
        }

        const failInfoValue = seqValues[2];
        if (isObject(failInfoValue) && isObject(failInfoValue.valueBlock)) {
            const hexView = failInfoValue.valueBlock.valueHexView;
            if (
                (Array.isArray(hexView) || hexView instanceof Uint8Array) &&
                hexView.length > 0
            ) {
                result.failInfo = (hexView as ArrayLike<number>)[0];
            }
        }

        return result;
    } catch {
        return null;
    }
}

/**
 * Attempts to extract the timeStampToken from an ASN.1 block without using pkijs.
 * Used as fallback when pkijs schema validation fails.
 */
function tryExtractTokenFromASN1(asn1Block: unknown): Uint8Array | null {
    try {
        const timeStampToken = getField(asn1Block, [1]);
        if (!isObject(timeStampToken) || typeof timeStampToken.toSchema !== "function") {
            return null;
        }
        const toSchema = timeStampToken.toSchema as () => { toBER: (sizeOnly: boolean) => ArrayBuffer };
        const schema = toSchema.call(timeStampToken);
        return new Uint8Array(schema.toBER(false));
    } catch {
        return null;
    }
}

/**
 * Attempts to extract timestamp info from a token's ContentInfo structure.
 */
function tryExtractInfoFromToken(tokenBytes: Uint8Array): TimestampInfo | null {
    try {
        const asn1 = asn1js.fromBER(toArrayBuffer(tokenBytes));
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
        const asn1 = asn1js.fromBER(toArrayBuffer(responseBytes));
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
                if (!info) {
                    // Parsed but inner TSTInfo broken -- distinct from "outer parse failed"
                    // so the session catch can refuse to swallow this.
                    throw new TimestampError(
                        TimestampErrorCode.MALFORMED_RESPONSE,
                        `TimeStampResp granted but TSTInfo could not be extracted from token`
                    );
                }
                return {
                    status,
                    statusString,
                    token: manuallyExtractedToken,
                    info,
                };
            }
            throw new TimestampError(
                TimestampErrorCode.MALFORMED_RESPONSE,
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
 * @param expectedNonce - The nonce from the original TimeStampReq (RFC 3161 §2.4.2 replay defence).
 *                       When provided, the response MUST contain a matching nonce.
 *                       Omit to skip the nonce check (e.g. when verifying tokens fetched
 *                       outside the original request flow).
 * @returns true if the response is valid for the request
 */
export function validateTimestampResponse(
    responseInfo: TimestampInfo,
    originalHash: Uint8Array,
    hashAlgorithm: string,
    expectedNonce?: Uint8Array
): boolean {
    if (responseInfo.hashAlgorithm !== hashAlgorithm) {
        return false;
    }

    const expectedDigest = bytesToHex(originalHash);
    if (responseInfo.messageDigest.toLowerCase() !== expectedDigest.toLowerCase()) {
        return false;
    }

    if (expectedNonce) {
        if (responseInfo.nonce?.length !== expectedNonce.length) {
            return false;
        }
        for (let i = 0; i < expectedNonce.length; i++) {
            if (responseInfo.nonce[i] !== expectedNonce[i]) {
                return false;
            }
        }
    }

    return true;
}
