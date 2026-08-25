import * as pkijs from "pkijs";
import * as asn1js from "asn1js";
import { TimestampError, TimestampErrorCode } from "../types.js";
import { parseCanonicalDERSequenceTree, requireSchemaRoundTrip } from "./der-utils.js";

/**
 * OCSP Response Status values (RFC 6960)
 */
export enum OCSPResponseStatus {
    SUCCESSFUL = 0,
    MALFORMED_REQUEST = 1,
    INTERNAL_ERROR = 2,
    TRY_LATER = 3,
    UNUSED = 4,
    SIG_REQUIRED = 5,
    UNAUTHORIZED = 6,
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

function isCertStatusBlock(value: unknown): value is asn1js.Primitive | asn1js.Constructed {
    return value instanceof asn1js.Primitive || value instanceof asn1js.Constructed;
}

function invalidOcspSchema(message: string): TimestampError {
    return new TimestampError(TimestampErrorCode.INVALID_RESPONSE, `OCSP response: ${message}`);
}

function sequenceChildren(value: asn1js.BaseBlock, description: string): asn1js.BaseBlock[] {
    if (!(value instanceof asn1js.Sequence)) {
        throw invalidOcspSchema(`${description} must be a SEQUENCE`);
    }
    return value.valueBlock.value;
}

/**
 * Checks the RFC 6960 OCSPResponse and nested explicit ResponseBytes framing
 * before PKIjs maps them into object properties.
 */
function parseRawResponseStatus(value: asn1js.BaseBlock): OCSPResponseStatus {
    if (
        !(value instanceof asn1js.Enumerated) ||
        value.idBlock.isConstructed ||
        value.valueBlock.valueHexView.byteLength !== 1
    ) {
        throw invalidOcspSchema(
            "responseStatus must be a primitive, one-octet ENUMERATED value"
        );
    }

    const status = value.valueBlock.valueHexView[0];
    // RFC 6960 defines nonnegative responseStatus values 0 through 6.
    if (status === undefined || status > 6) {
        throw invalidOcspSchema("responseStatus must be an RFC 6960 value from 0 through 6");
    }
    return status;
}

function validateOcspResponseSchema(value: asn1js.BaseBlock): OCSPResponseStatus {
    const children = sequenceChildren(value, "outer value");
    if (children.length < 1 || children.length > 2) {
        throw invalidOcspSchema("outer value must contain responseStatus and optional responseBytes only");
    }

    const responseStatus = children[0];
    if (responseStatus === undefined) {
        throw invalidOcspSchema("outer value must contain responseStatus");
    }
    const status = parseRawResponseStatus(responseStatus);

    if (children.length === 1) return status;

    const responseBytesExplicit = children[1];
    if (
        !(responseBytesExplicit instanceof asn1js.Constructed) ||
        responseBytesExplicit.idBlock.tagClass !== 3 ||
        responseBytesExplicit.idBlock.tagNumber !== 0
    ) {
        throw invalidOcspSchema("responseBytes must be [0] EXPLICIT");
    }

    const explicitChildren = responseBytesExplicit.valueBlock.value;
    if (explicitChildren.length !== 1) {
        throw invalidOcspSchema("responseBytes explicit wrapper must contain exactly one value");
    }

    const responseBytesValue = explicitChildren[0];
    if (responseBytesValue === undefined) {
        throw invalidOcspSchema("responseBytes explicit wrapper must contain exactly one value");
    }
    const responseBytes = sequenceChildren(responseBytesValue, "responseBytes");
    if (
        responseBytes.length !== 2 ||
        !(responseBytes[0] instanceof asn1js.ObjectIdentifier) ||
        !(responseBytes[1] instanceof asn1js.OctetString)
    ) {
        throw invalidOcspSchema("responseBytes must contain an OBJECT IDENTIFIER and OCTET STRING only");
    }
    return status;
}

/**
 * Validates and parses an OCSP response.
 *
 * @param responseBytes - DER-encoded OCSP Response
 * @returns ParsedOCSPResponse with status details
 * @throws TimestampError if response is invalid or indicates failure
 */
export function parseOCSPResponse(responseBytes: Uint8Array): ParsedOCSPResponse {
    const asn1 = parseCanonicalDERSequenceTree(responseBytes, "OCSP response");
    const status = validateOcspResponseSchema(asn1);

    const ocspResponse = new pkijs.OCSPResponse({ schema: asn1 });
    requireSchemaRoundTrip(
        responseBytes,
        ocspResponse.toSchema().toBER(false),
        "OCSP response"
    );

    if (status !== OCSPResponseStatus.SUCCESSFUL) {
        const statusNames: Record<number, string> = {
            [OCSPResponseStatus.SUCCESSFUL]: "Successful",
            [OCSPResponseStatus.MALFORMED_REQUEST]: "Malformed Request",
            [OCSPResponseStatus.INTERNAL_ERROR]: "Internal Error",
            [OCSPResponseStatus.TRY_LATER]: "Try Later",
            [OCSPResponseStatus.UNUSED]: "Unused",
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

    if (ocspResponse.responseBytes.responseType !== "1.3.6.1.5.5.7.48.1.1") {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP response does not contain a BasicOCSPResponse"
        );
    }

    // Parse the response bytes (should be BasicOCSPResponse)
    const responseBytesValue = ocspResponse.responseBytes.response.valueBlock.valueHexView;
    const responseBytesAsn1 = parseCanonicalDERSequenceTree(
        responseBytesValue,
        "BasicOCSPResponse"
    );
    const basicOCSPResponse = new pkijs.BasicOCSPResponse({ schema: responseBytesAsn1 });
    requireSchemaRoundTrip(
        responseBytesValue,
        basicOCSPResponse.toSchema().toBER(false),
        "BasicOCSPResponse"
    );

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
    const statusCandidate: unknown = singleResponse.certStatus;
    if (!isCertStatusBlock(statusCandidate) || statusCandidate.idBlock.tagClass !== 3) {
        throw new TimestampError(
            TimestampErrorCode.INVALID_RESPONSE,
            "OCSP response certificate status is malformed"
        );
    }

    // CertStatus ::= CHOICE { good [0] IMPLICIT NULL, revoked [1] RevokedInfo,
    // unknown [2] UnknownInfo }  -- RFC 6960. Good must be primitive with no content.
    let certStatus: CertificateStatus;
    switch (statusCandidate.idBlock.tagNumber) {
        case 0:
            if (
                !(statusCandidate instanceof asn1js.Primitive) ||
                statusCandidate.valueBlock.valueHexView.byteLength !== 0
            ) {
                throw new TimestampError(
                    TimestampErrorCode.INVALID_RESPONSE,
                    "OCSP response certificate status is malformed"
                );
            }
            certStatus = CertificateStatus.GOOD;
            break;
        case 1:
            certStatus = CertificateStatus.REVOKED;
            break;
        case 2:
            certStatus = CertificateStatus.UNKNOWN;
            break;
        default:
            throw new TimestampError(
                TimestampErrorCode.INVALID_RESPONSE,
                "OCSP response certificate status is malformed"
            );
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
