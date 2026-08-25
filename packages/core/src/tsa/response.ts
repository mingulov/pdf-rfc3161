import {
    TimestampError,
    TimestampErrorCode,
    type ParsedTimestampResponse,
    type TimestampInfo,
} from "../types.js";
import { bytesToHex } from "../utils.js";
import { parseTimestampToken } from "./token-validation.js";

function positiveIntegerValue(bytes: Uint8Array): Uint8Array | undefined {
    const first = bytes[0];
    if (first === undefined || (first & 0x80) !== 0) return undefined;
    const second = bytes[1];
    if (bytes.length > 1 && first === 0 && (second === undefined || (second & 0x80) === 0)) {
        return undefined;
    }

    let offset = 0;
    while (offset < bytes.length && bytes[offset] === 0) offset++;
    return offset === bytes.length ? undefined : bytes.slice(offset);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    let different = 0;
    for (let index = 0; index < left.length; index++) {
        const leftByte = left[index];
        const rightByte = right[index];
        if (leftByte === undefined || rightByte === undefined) return false;
        different |= leftByte ^ rightByte;
    }
    return different === 0;
}

/**
 * Parses a complete RFC 3161 TimeStampResp. Only status 0 (granted) and 1
 * (grantedWithMods) can produce a usable response; all other statuses are
 * fatal and are reported as TSA_ERROR by the shared strict token parser.
 */
export function parseTimestampResponse(responseBytes: Uint8Array): ParsedTimestampResponse {
    const parsed = parseTimestampToken(responseBytes);
    if (parsed.responseStatus === undefined) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "Expected a complete TimeStampResp rather than a raw timestamp token"
        );
    }
    return {
        status: parsed.responseStatus,
        ...(parsed.responseStatusString !== undefined && {
            statusString: parsed.responseStatusString,
        }),
        token: parsed.token,
        info: parsed.info,
    };
}

/**
 * Checks a parsed response's request binding only. This compatibility helper
 * does not authenticate CMS, ESS, EKU, or TSA trust; callers embedding a PDF
 * must use TimestampSession's mandatory token validator instead.
 *
 * @param responseInfo Parsed TSTInfo fields from a response.
 * @param originalHash Digest that was sent to the TSA.
 * @param hashAlgorithm Hash algorithm that was requested.
 * @param expectedNonce Optional positive request nonce, compared as INTEGER values.
 * @param expectedPolicy Optional requested policy OID, matched exactly.
 */
export function validateTimestampResponse(
    responseInfo: TimestampInfo,
    originalHash: Uint8Array,
    hashAlgorithm: string,
    expectedNonce?: Uint8Array,
    expectedPolicy?: string
): boolean {
    if (responseInfo.hashAlgorithm !== hashAlgorithm) return false;

    const expectedDigest = bytesToHex(originalHash);
    if (responseInfo.messageDigest.toLowerCase() !== expectedDigest.toLowerCase()) return false;

    if (expectedNonce) {
        const expected = positiveIntegerValue(expectedNonce);
        const actual = responseInfo.nonce ? positiveIntegerValue(responseInfo.nonce) : undefined;
        if (!expected || !actual || !equalBytes(actual, expected)) return false;
    }

    return expectedPolicy === undefined || responseInfo.policy === expectedPolicy;
}
