import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { getLogger } from "../utils/logger.js";
import { toArrayBuffer } from "../utils.js";

/**
 * OCSP Response Status values (RFC 6960)
 */
export enum OCSPResponseStatus {
    SUCCESSFUL = 0,
    MALFORMED_REQUEST = 1,
    INTERNAL_ERROR = 2,
    TRY_LATER = 3,
    SIG_REQUIRED = 4,
    UNAUTHORIZED = 5,
}

/**
 * Certificate Status values in OCSP SingleResponse
 */
export enum CertificateStatus {
    GOOD = 0,
    REVOKED = 1,
    UNKNOWN = 2,
}

/**
 * Parsed OCSP Response information
 */
export interface ParsedOCSPResponse {
    status: OCSPResponseStatus;
    certStatus: CertificateStatus;
    thisUpdate: Date;
    nextUpdate?: Date;
    responderName?: string;
}

/**
 * Validates and parses an OCSP response.
 *
 * @param responseBytes - DER-encoded OCSP Response
 * @returns ParsedOCSPResponse with status details
 * @throws TimestampError if response is invalid or indicates failure
 */
export function parseOCSPResponse(responseBytes: Uint8Array): ParsedOCSPResponse {
    const asn1 = asn1js.fromBER(toArrayBuffer(responseBytes));
    if (asn1.offset === -1) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "Failed to parse OCSP response ASN.1"
        );
    }

    const ocspResponse = new pkijs.OCSPResponse({ schema: asn1.result });

    // Check response status - pkijs returns an Enumerated type
    // Check response status - pkijs returns an Enumerated type (object)
    // We need to extract the actual number from it
    let statusValue: number;

    const rawStatus = ocspResponse.responseStatus as unknown;

    if (typeof rawStatus === "number") {
        statusValue = rawStatus;
    } else if (
        rawStatus &&
        typeof rawStatus === "object" &&
        "valueBlock" in rawStatus &&
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
        typeof (rawStatus as any).valueBlock.valueDec === "number"
    ) {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-explicit-any
        statusValue = (rawStatus as any).valueBlock.valueDec as number;
    } else {
        // Fallback or error if structure is unexpected
        // Defaulting to a value that isn't SUCCESSFUL (0) if we can't parse it
        statusValue = OCSPResponseStatus.INTERNAL_ERROR;
    }

    const status: OCSPResponseStatus = statusValue;

    if (status !== OCSPResponseStatus.SUCCESSFUL) {
        const statusNames: Record<number, string> = {
            [OCSPResponseStatus.SUCCESSFUL]: "Successful",
            [OCSPResponseStatus.MALFORMED_REQUEST]: "Malformed Request",
            [OCSPResponseStatus.INTERNAL_ERROR]: "Internal Error",
            [OCSPResponseStatus.TRY_LATER]: "Try Later",
            [OCSPResponseStatus.SIG_REQUIRED]: "Signature Required",
            [OCSPResponseStatus.UNAUTHORIZED]: "Unauthorized",
        };
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            `OCSP responder error: ${statusNames[status] ?? "Unknown error"} (code: ${String(status)})`
        );
    }

    // Extract SingleResponse with certificate status
    if (!ocspResponse.responseBytes) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP response has no responseBytes"
        );
    }

    // Parse the response bytes (should be BasicOCSPResponse)
    const responseBytesValue = ocspResponse.responseBytes.response.valueBlock.valueHexView;
    const responseBytesAsn1 = asn1js.fromBER(responseBytesValue).result;
    const basicOCSPResponse = new pkijs.BasicOCSPResponse({ schema: responseBytesAsn1 });

    // Get the single response
    const singleResponses = basicOCSPResponse.tbsResponseData.responses;
    if (singleResponses.length === 0) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP response has no single responses"
        );
    }

    const singleResponse = singleResponses[0];
    if (!singleResponse) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP response has no single responses"
        );
    }

    // Extract certificate status
    let certStatus: CertificateStatus;

    if (singleResponse.certStatus === null || singleResponse.certStatus === undefined) {
        certStatus = CertificateStatus.GOOD;
    } else {
        // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
        const statusAsn1 = singleResponse.certStatus;

        if (statusAsn1 && "idBlock" in (statusAsn1 as object)) {
            // CertStatus ::= CHOICE { good [0] NULL, revoked [1] RevokedInfo,
            // unknown [2] UnknownInfo }  -- RFC 6960
            // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
            const tagNumber = statusAsn1.idBlock.tagNumber as number;

            switch (tagNumber) {
                case 0:
                    certStatus = CertificateStatus.GOOD;
                    break;
                case 1:
                    certStatus = CertificateStatus.REVOKED;
                    break;
                case 2:
                    certStatus = CertificateStatus.UNKNOWN;
                    break;
                default:
                    certStatus = CertificateStatus.UNKNOWN;
            }
        } else {
            getLogger().warn(`OCSP CertStatus missing idBlock; treating as UNKNOWN`);
            certStatus = CertificateStatus.UNKNOWN;
        }
    }

    // Extract timestamps
    const thisUpdate = singleResponse.thisUpdate;
    const nextUpdate = singleResponse.nextUpdate;

    return {
        status,
        certStatus,
        thisUpdate,
        nextUpdate,
    };
}

/**
 * Extracts the OCSP Responder URI from a certificate's Authority Information Access (AIA) extension.
 *
 * @param cert - The certificate to inspect
 * @returns The OCSP URI if found, or null
 */
export function getOCSPURI(cert: pkijs.Certificate): string | null {
    if (!cert.extensions) {
        return null;
    }

    // OID for Authority Information Access is 1.3.6.1.5.5.7.1.1
    const aiaExtension = cert.extensions.find((ext) => ext.extnID === "1.3.6.1.5.5.7.1.1");

    if (!aiaExtension?.extnValue) {
        return null;
    }

    // Parse the extension value
    const extRaw = asn1js.fromBER(aiaExtension.extnValue.valueBlock.valueHexView).result;
    const extValue: unknown = (aiaExtension as { parsedValue?: unknown }).parsedValue ?? extRaw;

    let accessDescriptions: pkijs.AccessDescription[] = [];

    if (extValue && typeof extValue === "object" && "accessDescriptions" in extValue) {
        const parsed = extValue as { accessDescriptions: unknown[] };
        if (Array.isArray(parsed.accessDescriptions)) {
            accessDescriptions = parsed.accessDescriptions as pkijs.AccessDescription[];
        }
    }

    for (const desc of accessDescriptions) {
        // accessMethod OID for OCSP is 1.3.6.1.5.5.7.48.1
        if (desc.accessMethod === "1.3.6.1.5.5.7.48.1") {
            const location = desc.accessLocation;
            if (location.type === 6 && typeof location.value === "string") {
                return location.value;
            }
        }
    }

    return null;
}

/**
 * OCSP Nonce Extension OID (RFC 6960)
 * id-pkix-ocsp-nonce = 1.3.6.1.5.5.7.48.1.2
 */
const OCSP_NONCE_OID = "1.3.6.1.5.5.7.48.1.2";

/**
 * Creates a raw DER-encoded OCSP Request for a given certificate and its issuer.
 *
 * @param cert - The certificate to be checked
 * @param issuerCert - The issuer's certificate (needed to hash the issuer name/key)
 * @param options - Optional parameters
 * @returns DER-encoded OCSP Request
 */
export async function createOCSPRequest(
    cert: pkijs.Certificate,
    issuerCert: pkijs.Certificate,
    options?: { includeNonce?: boolean }
): Promise<Uint8Array> {
    const ocspReq = new pkijs.OCSPRequest();

    // Create the CertID
    await ocspReq.createForCertificate(cert, {
        hashAlgorithm: "SHA-1", // Standard for CertID per RFC 6960
        issuerCertificate: issuerCert,
    });

    // Optionally add nonce extension for freshness protection
    // The nonce prevents replay attacks and ensures the response is fresh
    if (options?.includeNonce !== false) {
        // Generate a random 8-byte nonce
        const nonceBytes = new Uint8Array(8);
        crypto.getRandomValues(nonceBytes);

        // Add the nonce extension to the request
        const nonceOctetString = new asn1js.OctetString({ valueHex: nonceBytes.buffer });
        const nonceExtension = new pkijs.Extension({
            extnID: OCSP_NONCE_OID,
            critical: false,
            extnValue: nonceOctetString.toBER(false),
        });

        // Add extensions using pkijs type assertion
        (ocspReq.tbsRequest as { extensions?: pkijs.Extension[] }).extensions = [nonceExtension];
    }

    const ocspReqDer = ocspReq.toSchema(true).toBER(false);
    return new Uint8Array(ocspReqDer);
}
