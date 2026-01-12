/**
 * Simplified Synthetic TSA Test Fixtures
 *
 * This module provides simplified synthetic TSA responses for testing
 * edge cases and error conditions without complex ASN.1 encoding.
 */

export type HashAlgorithm = "SHA-256" | "SHA-384" | "SHA-512" | "SHA-1" | "MD5";

export type TSAStatusCode = 0 | 1 | 2 | 3 | 4 | 5;

export const STATUS_CODE_NAMES: Record<TSAStatusCode, string> = {
    0: "GRANTED",
    1: "GRANTED_WITH_MODS",
    2: "REJECTION",
    3: "WAITING",
    4: "REVOCATION_WARNING",
    5: "REVOCATION_NOTIFICATION",
};

export const FAIL_INFO_CODES = {
    BAD_ALGORITHM: 0,
    BAD_REQUEST: 1,
    BAD_DATA_FORMAT: 2,
    TIME_NOT_AVAILABLE: 3,
    UNADDED_POLICY: 4,
    UNSUPPORTED_OPTS: 5,
    POLICY_MISMATCH: 6,
    REQUEST_INITIALLY_REJECTED: 7,
    REQUEST_RETRY: 8,
} as const;

function createMinimalResponse(status: number): Uint8Array {
    return new Uint8Array([
        0x30,
        0x0d,
        0xa0,
        0x0b,
        0x02,
        0x01,
        status,
        0x30,
        0x06,
        0x02,
        0x01,
        0x00,
        0x02,
        0x01,
        0x00,
    ]);
}

function createResponseWithStatusString(status: number, statusText: string): Uint8Array {
    const textBytes = new TextEncoder().encode(statusText);
    const statusStringLen = 3 + textBytes.length;
    const statusLen = 1 + statusStringLen;
    const totalLen = 2 + statusLen;
    const fullLen = 2 + totalLen + textBytes.length;

    const result = new Uint8Array(fullLen);
    let pos = 0;
    result[pos++] = 0x30;
    result[pos++] = totalLen + textBytes.length;
    result[pos++] = 0xa0;
    result[pos++] = statusLen;
    result[pos++] = 0x02;
    result[pos++] = 0x01;
    result[pos++] = status;
    result[pos++] = 0xa0;
    result[pos++] = statusStringLen - 1;
    result[pos++] = 0x0c;
    result[pos++] = textBytes.length;
    result.set(textBytes, pos);
    return result;
}

export function generateGrantedResponse(): Uint8Array {
    return createMinimalResponse(0);
}

export function generateGrantedWithModsResponse(): Uint8Array {
    return createResponseWithStatusString(1, "Request granted with modifications");
}

export function generateRejectionResponse(
    failInfo: keyof typeof FAIL_INFO_CODES,
    statusString?: string
): Uint8Array {
    const text = statusString ?? `Request rejected: ${failInfo}`;
    return createResponseWithStatusString(2, text);
}

export function generateWaitingResponse(): Uint8Array {
    return createResponseWithStatusString(3, "Request queued, please retry");
}

export function generateRevocationWarningResponse(): Uint8Array {
    return createResponseWithStatusString(4, "Certificate revocation warning");
}

export function generateRevocationNotificationResponse(): Uint8Array {
    return createResponseWithStatusString(5, "Certificate revocation notification");
}

export function generateMalformedResponse(type: "truncated" | "empty" | "invalid"): Uint8Array {
    switch (type) {
        case "truncated":
            return new Uint8Array([0x30, 0x02, 0x02, 0x01]);
        case "empty":
            return new Uint8Array([]);
        case "invalid":
            return new Uint8Array([0x02, 0x01, 0x00]);
        default:
            return new Uint8Array([]);
    }
}

export function generateHttpErrorBody(httpStatus: number): Uint8Array {
    const messages: Record<number, string> = {
        400: "HTTP 400: Bad Request",
        401: "HTTP 401: Unauthorized",
        403: "HTTP 403: Forbidden",
        404: "HTTP 404: Not Found",
        429: "HTTP 429: Too Many Requests - Rate limit exceeded",
        500: "HTTP 500: Internal Server Error",
        503: "HTTP 503: Service Unavailable",
    };
    const msg = messages[httpStatus] ?? `HTTP ${httpStatus.toString()}: Error`;
    return createResponseWithStatusString(2, msg);
}

export function generateTimeoutResponse(): Uint8Array {
    return new Uint8Array([]);
}

export function generateOldTimestampResponse(): Uint8Array {
    return generateGrantedResponse();
}

export function generateExpiringResponse(): Uint8Array {
    return generateGrantedResponse();
}

export function generateLargeNonceResponse(): Uint8Array {
    return generateGrantedResponse();
}

export function generateZeroNonceResponse(): Uint8Array {
    return generateGrantedResponse();
}

export function generateNonStandardNonceResponse(_size: number): Uint8Array {
    return generateGrantedResponse();
}

export function generateNoCertificateResponse(): Uint8Array {
    return generateGrantedResponse();
}

export function generateResponseWithPolicy(_policyOid: string): Uint8Array {
    return generateGrantedResponse();
}

export function generateResponseWithHashAlgorithm(_hashAlgo: HashAlgorithm): Uint8Array {
    return generateGrantedResponse();
}

export const SYNTHETIC_FIXTURES = {
    granted: generateGrantedResponse,
    grantedWithMods: generateGrantedWithModsResponse,
    rejection: (failInfo?: keyof typeof FAIL_INFO_CODES, statusString?: string) =>
        failInfo
            ? generateRejectionResponse(failInfo, statusString)
            : generateRejectionResponse("BAD_REQUEST"),
    rejectionBadAlgorithm: () => generateRejectionResponse("BAD_ALGORITHM"),
    rejectionBadRequest: () => generateRejectionResponse("BAD_REQUEST"),
    rejectionBadDataFormat: () => generateRejectionResponse("BAD_DATA_FORMAT"),
    rejectionTimeNotAvailable: () => generateRejectionResponse("TIME_NOT_AVAILABLE"),
    waiting: generateWaitingResponse,
    revocationWarning: generateRevocationWarningResponse,
    revocationNotification: generateRevocationNotificationResponse,
    malformedTruncated: () => generateMalformedResponse("truncated"),
    malformedInvalidStructure: () => generateMalformedResponse("invalid"),
    malformedEmpty: () => generateMalformedResponse("empty"),
    noCertificate: generateNoCertificateResponse,
    withPolicy: generateResponseWithPolicy,
    withHashAlgorithm: generateResponseWithHashAlgorithm,
    oldTimestamp: generateOldTimestampResponse,
    expiring: generateExpiringResponse,
    nonStandardNonce: generateNonStandardNonceResponse,
    httpError: generateHttpErrorBody,
    timeout: generateTimeoutResponse,
    largeNonce: generateLargeNonceResponse,
    zeroNonce: generateZeroNonceResponse,
};

export type SyntheticFixtureType = keyof typeof SYNTHETIC_FIXTURES;
