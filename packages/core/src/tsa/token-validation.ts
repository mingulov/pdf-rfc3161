import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { HASH_ALGORITHM_TO_OID, OID_TO_HASH_ALGORITHM } from "../constants.js";
import {
    TSAStatus,
    TimestampError,
    TimestampErrorCode,
    type HashAlgorithm,
    type TimestampInfo,
    type TimestampResponseValidationOptions,
} from "../types.js";
import { bytesToHex, toArrayBuffer } from "../utils.js";
import { ensureWebCrypto } from "../utils/web-crypto.js";

const ID_SIGNED_DATA = "1.2.840.113549.1.7.2";
const ID_DATA = "1.2.840.113549.1.7.1";
const ID_CT_TST_INFO = "1.2.840.113549.1.9.16.1.4";
const ID_CONTENT_TYPE = "1.2.840.113549.1.9.3";
const ID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
const ID_SIGNING_CERTIFICATE = "1.2.840.113549.1.9.16.2.12";
const ID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";
const ID_QT_CPS = "1.3.6.1.5.5.7.2.1";
const ID_QT_UNOTICE = "1.3.6.1.5.5.7.2.2";
const ID_SUBJECT_KEY_IDENTIFIER = "2.5.29.14";
const ID_EXTENDED_KEY_USAGE = "2.5.29.37";
const ID_KP_TIMESTAMPING = "1.3.6.1.5.5.7.3.8";
const ID_SHA1 = "1.3.14.3.2.26";

type EssHashAlgorithm = "SHA-1" | HashAlgorithm;

const ESS_HASH_ALGORITHMS: Readonly<
    Record<string, { algorithm: EssHashAlgorithm; digestLength: number }>
> = {
    [ID_SHA1]: { algorithm: "SHA-1", digestLength: 20 },
    "2.16.840.1.101.3.4.2.1": { algorithm: "SHA-256", digestLength: 32 },
    "2.16.840.1.101.3.4.2.2": { algorithm: "SHA-384", digestLength: 48 },
    "2.16.840.1.101.3.4.2.3": { algorithm: "SHA-512", digestLength: 64 },
};

const HASH_LENGTHS: Readonly<Record<HashAlgorithm, number>> = {
    "SHA-256": 32,
    "SHA-384": 48,
    "SHA-512": 64,
};

export interface TimestampRequestContext {
    data: Uint8Array;
    hashAlgorithm: HashAlgorithm;
    nonce: Uint8Array;
    policy?: string;
    requestCertificate: boolean;
}

export interface ValidatedTimestampToken {
    token: Uint8Array;
    info: TimestampInfo;
    signerCertificate: pkijs.Certificate;
    certificates: pkijs.Certificate[];
    responseStatus?: TSAStatus.GRANTED | TSAStatus.GRANTED_WITH_MODS;
}

export interface ParsedTimestampToken {
    token: Uint8Array;
    contentInfo: pkijs.ContentInfo;
    signedData: pkijs.SignedData;
    signerInfo: pkijs.SignerInfo;
    tstInfo: pkijs.TSTInfo;
    info: TimestampInfo;
    responseStatus?: TSAStatus.GRANTED | TSAStatus.GRANTED_WITH_MODS;
    responseStatusString?: string;
}

function timestampError(
    code: TimestampErrorCode,
    message: string,
    cause?: unknown
): TimestampError {
    return new TimestampError(code, message, cause);
}

function invalidResponse(message: string, cause?: unknown): TimestampError {
    return timestampError(TimestampErrorCode.INVALID_RESPONSE, message, cause);
}

function malformedResponse(message: string, cause?: unknown): TimestampError {
    return timestampError(TimestampErrorCode.MALFORMED_RESPONSE, message, cause);
}

function verificationFailed(message: string, cause?: unknown): TimestampError {
    return timestampError(TimestampErrorCode.VERIFICATION_FAILED, message, cause);
}

function toExactArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return toArrayBuffer(bytes);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
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

function completeDerTlvLength(bytes: Uint8Array, message: string): number {
    const firstTag = bytes[0];
    if (firstTag === undefined) throw invalidResponse(`${message}: empty input`);
    if (firstTag !== 0x30) {
        throw invalidResponse(`${message}: expected canonical DER SEQUENCE tag`);
    }

    let offset = 1;
    const firstLength = bytes[offset];
    if (firstLength === undefined) throw invalidResponse(`${message}: ASN.1 parse failed`);
    offset++;
    if (firstLength < 0x80) return offset + firstLength;
    if (firstLength === 0x80) {
        throw invalidResponse(`${message}: indefinite-length BER is not permitted`);
    }

    const lengthOctets = firstLength & 0x7f;
    if (lengthOctets > 6 || offset + lengthOctets > bytes.length) {
        throw invalidResponse(`${message}: ASN.1 parse failed`);
    }
    const firstLengthOctet = bytes[offset];
    if (firstLengthOctet === undefined || firstLengthOctet === 0) {
        throw invalidResponse(`${message}: non-minimal DER length encoding`);
    }

    let length = 0;
    for (let index = 0; index < lengthOctets; index++) {
        const octet = bytes[offset + index];
        if (octet === undefined) throw invalidResponse(`${message}: ASN.1 parse failed`);
        length = length * 0x100 + octet;
    }
    if (length < 0x80) {
        throw invalidResponse(`${message}: non-minimal DER length encoding`);
    }
    return offset + lengthOctets + length;
}

function parseCompleteDER(bytes: Uint8Array, message: string): asn1js.BaseBlock {
    const length = completeDerTlvLength(bytes, message);
    if (length !== bytes.length) {
        throw invalidResponse(`${message}: trailing bytes are not permitted`);
    }
    const parsed = asn1js.fromBER(toExactArrayBuffer(bytes));
    if (parsed.offset === -1) throw invalidResponse(`${message}: ASN.1 parse failed`);
    if (parsed.offset !== bytes.length) {
        throw invalidResponse(`${message}: trailing bytes are not permitted`);
    }
    return parsed.result;
}

function sequenceChildren(schema: asn1js.BaseBlock, message: string): asn1js.BaseBlock[] {
    if (!(schema instanceof asn1js.Sequence)) throw malformedResponse(message);
    return schema.valueBlock.value;
}

function contentInfoFromSchema(schema: asn1js.BaseBlock): pkijs.ContentInfo {
    const children = sequenceChildren(schema, "Timestamp token ContentInfo is not a SEQUENCE");
    if (children.length !== 2) {
        throw malformedResponse(
            "Timestamp token ContentInfo must contain exactly contentType and content"
        );
    }
    const contentType = children[0];
    const wrappedContent = children[1];
    if (
        !(contentType instanceof asn1js.ObjectIdentifier) ||
        contentType.valueBlock.toString() !== ID_SIGNED_DATA
    ) {
        throw malformedResponse("Timestamp token ContentInfo must use id-signedData");
    }
    if (
        !(wrappedContent instanceof asn1js.Constructed) ||
        wrappedContent.idBlock.tagClass !== 3 ||
        wrappedContent.idBlock.tagNumber !== 0 ||
        wrappedContent.valueBlock.value.length !== 1
    ) {
        throw malformedResponse("Timestamp token ContentInfo has malformed explicit content");
    }
    try {
        return new pkijs.ContentInfo({ schema });
    } catch (error) {
        throw malformedResponse("Timestamp token ContentInfo is malformed", error);
    }
}

function responseStatusValue(schema: asn1js.BaseBlock): { status: number; statusString?: string } {
    const children = sequenceChildren(schema, "TimeStampResp status must be a SEQUENCE");
    if (children.length < 1 || children.length > 3) {
        throw malformedResponse("TimeStampResp status has an invalid number of fields");
    }
    const status = children[0];
    if (
        !(status instanceof asn1js.Integer) ||
        status.valueBlock.isHexOnly ||
        !Number.isSafeInteger(status.valueBlock.valueDec) ||
        status.valueBlock.valueDec < 0
    ) {
        throw malformedResponse("TimeStampResp status must be a non-negative INTEGER");
    }

    let index = 1;
    let statusString: string | undefined;
    const statusStrings = children[index];
    if (statusStrings instanceof asn1js.Sequence) {
        const values: string[] = [];
        for (const value of statusStrings.valueBlock.value) {
            if (!(value instanceof asn1js.Utf8String)) {
                throw malformedResponse("TimeStampResp status strings are malformed");
            }
            values.push(value.valueBlock.value);
        }
        if (values.length === 0) throw malformedResponse("TimeStampResp status strings are malformed");
        statusString = values.join("; ");
        index++;
    }
    const failInfo = children[index];
    if (failInfo !== undefined) {
        if (!(failInfo instanceof asn1js.BitString) || index !== children.length - 1) {
            throw malformedResponse("TimeStampResp failure information is malformed");
        }
        index++;
    }
    if (index !== children.length) {
        throw malformedResponse("TimeStampResp status contains an unexpected field");
    }
    return {
        status: status.valueBlock.valueDec,
        ...(statusString !== undefined && { statusString }),
    };
}

function classifyToken(bytes: Uint8Array): {
    token: Uint8Array;
    contentInfo: pkijs.ContentInfo;
    responseStatus?: TSAStatus.GRANTED | TSAStatus.GRANTED_WITH_MODS;
    responseStatusString?: string;
} {
    const outer = parseCompleteDER(bytes, "Timestamp token");
    const children = sequenceChildren(outer, "Timestamp token must be a SEQUENCE");
    const first = children[0];
    if (first instanceof asn1js.ObjectIdentifier) {
        return { token: bytes, contentInfo: contentInfoFromSchema(outer) };
    }
    if (!(first instanceof asn1js.Sequence)) {
        throw invalidResponse("Timestamp token is neither ContentInfo nor TimeStampResp");
    }
    if (children.length < 1 || children.length > 2) {
        throw malformedResponse("TimeStampResp must contain a status and at most one token");
    }

    const responseStatus = responseStatusValue(first);
    const status = responseStatus.status;

    const hasToken = children.length === 2;
    const isGranted = status === 0 || status === 1;
    if (!isGranted && hasToken) {
        throw malformedResponse("A non-granted TimeStampResp must not contain a timestamp token");
    }
    if (isGranted && !hasToken) {
        throw malformedResponse("A granted TimeStampResp must contain exactly one timestamp token");
    }
    if (!isGranted) {
        const message =
            status === 2
                ? "TSA rejected request"
                : `TSA returned non-granted status ${status.toString()}`;
        throw timestampError(TimestampErrorCode.TSA_ERROR, message);
    }

    const tokenSchema = children[1];
    if (!tokenSchema) throw malformedResponse("Granted TimeStampResp is missing a timestamp token");
    const token = new Uint8Array(tokenSchema.valueBeforeDecodeView);
    const tokenOuter = parseCompleteDER(token, "TimeStampResp timestamp token");
    const contentInfo = contentInfoFromSchema(tokenOuter);
    return {
        token,
        contentInfo,
        responseStatus: status,
        responseStatusString: responseStatus.statusString,
    };
}

function getEncapsulatedContent(signedData: pkijs.SignedData): Uint8Array {
    const content = signedData.encapContentInfo.eContent;
    if (!(content instanceof asn1js.OctetString)) {
        throw malformedResponse(
            "Timestamp SignedData must contain an encapsulated TSTInfo OCTET STRING"
        );
    }

    if (!content.idBlock.isConstructed) {
        const value = new Uint8Array(content.valueBlock.valueHexView);
        if (value.length === 0) {
            throw malformedResponse("Timestamp SignedData contains an empty TSTInfo");
        }
        return value;
    }

    const segments = content.valueBlock.value;
    if (segments.length === 0) {
        throw malformedResponse("Timestamp SignedData contains an empty TSTInfo");
    }

    const values: Uint8Array[] = [];
    let length = 0;
    for (const segment of segments) {
        if (!(segment instanceof asn1js.OctetString) || segment.idBlock.isConstructed) {
            throw malformedResponse("Timestamp SignedData contains an invalid TSTInfo segment");
        }
        const value = new Uint8Array(segment.valueBlock.valueHexView);
        if (value.length === 0) {
            throw malformedResponse("Timestamp SignedData contains an empty TSTInfo segment");
        }
        values.push(value);
        length += value.length;
    }
    if (length === 0) throw malformedResponse("Timestamp SignedData contains an empty TSTInfo");

    const bytes = new Uint8Array(length);
    let offset = 0;
    for (const value of values) {
        bytes.set(value, offset);
        offset += value.length;
    }
    return bytes;
}

function timestampInfoFromTstInfo(
    signedData: pkijs.SignedData,
    signerInfo: pkijs.SignerInfo,
    tstInfo: pkijs.TSTInfo
): TimestampInfo {
    const hashAlgorithmOID = tstInfo.messageImprint.hashAlgorithm.algorithmId;
    const hashAlgorithm = OID_TO_HASH_ALGORITHM[hashAlgorithmOID] ?? hashAlgorithmOID;
    const attributes = signerInfo.signedAttrs?.attributes ?? [];
    const hasEssV2 = attributes.some((attribute) => attribute.type === ID_SIGNING_CERTIFICATE_V2);
    const hasEssV1 = attributes.some((attribute) => attribute.type === ID_SIGNING_CERTIFICATE);
    const nonce = tstInfo.nonce ? new Uint8Array(tstInfo.nonce.valueBlock.valueHexView) : undefined;

    return {
        genTime: tstInfo.genTime,
        policy: tstInfo.policy,
        serialNumber: bytesToHex(tstInfo.serialNumber.valueBlock.valueHexView),
        hashAlgorithm,
        hashAlgorithmOID,
        messageDigest: bytesToHex(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView),
        hasCertificate: (signedData.certificates?.length ?? 0) > 0,
        ...(hasEssV2
            ? { usesESSCertIDv2: true }
            : hasEssV1
              ? { usesESSCertIDv2: false, certIdHashAlgorithm: "SHA-1" as const }
              : {}),
        ...(nonce !== undefined && { nonce }),
    };
}

/**
 * Strictly parses the CMS portion shared by pre-embed and post-embed validation.
 */
export function parseTimestampToken(bytes: Uint8Array): ParsedTimestampToken {
    const classified = classifyToken(bytes);
    let signedData: pkijs.SignedData;
    try {
        signedData = new pkijs.SignedData({ schema: classified.contentInfo.content });
    } catch (error) {
        throw malformedResponse("Timestamp token id-signedData content is malformed", error);
    }
    if (signedData.encapContentInfo.eContentType !== ID_CT_TST_INFO) {
        throw malformedResponse("Timestamp SignedData must encapsulate id-ct-TSTInfo");
    }
    if (signedData.signerInfos.length !== 1) {
        throw malformedResponse("Timestamp SignedData must contain exactly one SignerInfo");
    }
    const signerInfo = signedData.signerInfos[0];
    if (!signerInfo) throw malformedResponse("Timestamp SignedData is missing its SignerInfo");

    const tstInfoBytes = getEncapsulatedContent(signedData);
    const tstSchema = parseCompleteDER(tstInfoBytes, "TSTInfo");
    let tstInfo: pkijs.TSTInfo;
    let info: TimestampInfo;
    try {
        tstInfo = new pkijs.TSTInfo({ schema: tstSchema });
        info = timestampInfoFromTstInfo(signedData, signerInfo, tstInfo);
    } catch (error) {
        throw malformedResponse("Timestamp TSTInfo is malformed", error);
    }
    return {
        token: classified.token,
        contentInfo: classified.contentInfo,
        signedData,
        signerInfo,
        tstInfo,
        info,
        responseStatus: classified.responseStatus,
        responseStatusString: classified.responseStatusString,
    };
}

function expectedHashOid(hashAlgorithm: HashAlgorithm): string {
    const oid = HASH_ALGORITHM_TO_OID[hashAlgorithm];
    if (!oid) throw verificationFailed(`Unsupported request hash algorithm ${hashAlgorithm}`);
    return oid;
}

function positiveIntegerValue(integer: asn1js.Integer): Uint8Array | undefined {
    const encoded = new Uint8Array(integer.valueBlock.valueHexView);
    const first = encoded[0];
    if (first === undefined || (first & 0x80) !== 0) return undefined;
    const second = encoded[1];
    if (encoded.length > 1 && first === 0 && (second === undefined || (second & 0x80) === 0)) {
        return undefined;
    }
    let offset = 0;
    while (offset < encoded.length && encoded[offset] === 0) offset++;
    if (offset === encoded.length) return undefined;
    return encoded.slice(offset);
}

function positiveRequestNonceValue(bytes: Uint8Array): Uint8Array | undefined {
    // TimestampSession captures the nonce octets before they are encoded as
    // an INTEGER. buildRequest guarantees a nonzero first octet with its high
    // bit clear, which is the unique positive DER-minimal representation.
    const first = bytes[0];
    if (first === undefined || first === 0 || (first & 0x80) !== 0) return undefined;
    return bytes;
}

async function validateRequestBinding(
    tstInfo: pkijs.TSTInfo,
    context: TimestampRequestContext
): Promise<void> {
    const expectedOid = expectedHashOid(context.hashAlgorithm);
    if (tstInfo.messageImprint.hashAlgorithm.algorithmId !== expectedOid) {
        throw verificationFailed("Timestamp message-imprint algorithm does not match the request");
    }
    const responseDigest = new Uint8Array(
        tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView
    );
    if (responseDigest.length !== HASH_LENGTHS[context.hashAlgorithm]) {
        throw verificationFailed("Timestamp message-imprint has an invalid digest length");
    }
    await ensureWebCrypto();
    const expectedDigest = new Uint8Array(
        await crypto.subtle.digest(context.hashAlgorithm, toExactArrayBuffer(context.data))
    );
    if (!bytesEqual(responseDigest, expectedDigest)) {
        throw verificationFailed("Timestamp message-imprint does not match the prepared PDF bytes");
    }

    const actualNonce = tstInfo.nonce ? positiveIntegerValue(tstInfo.nonce) : undefined;
    const expectedNonce = positiveRequestNonceValue(context.nonce);
    if (!actualNonce || !expectedNonce || !bytesEqual(actualNonce, expectedNonce)) {
        throw verificationFailed("Timestamp nonce does not match the positive request nonce");
    }
    if (context.policy !== undefined && tstInfo.policy !== context.policy) {
        throw verificationFailed("Timestamp policy does not match the requested policy");
    }
}

function parseCertificate(bytes: Uint8Array, source: string): pkijs.Certificate {
    const schema = parseCompleteDER(bytes, source);
    try {
        return new pkijs.Certificate({ schema });
    } catch (error) {
        throw malformedResponse(`${source} is not a valid X.509 certificate`, error);
    }
}

export function getEmbeddedCertificates(signedData: pkijs.SignedData): pkijs.Certificate[] {
    const certificateSet = signedData.certificates;
    if (!certificateSet) return [];
    const certificates: pkijs.Certificate[] = [];
    for (const value of certificateSet) {
        if (value instanceof pkijs.Certificate) {
            certificates.push(value);
            continue;
        }
        try {
            certificates.push(new pkijs.Certificate({ schema: value.toSchema() }));
        } catch (error) {
            throw malformedResponse(
                "Timestamp certificate set contains a malformed certificate",
                error
            );
        }
    }
    return certificates;
}

function getSubjectKeyIdentifier(certificate: pkijs.Certificate): Uint8Array | undefined {
    const extensions = certificate.extensions?.filter(
        (extension) => extension.extnID === ID_SUBJECT_KEY_IDENTIFIER
    );
    if (extensions?.length !== 1) return undefined;
    const extension = extensions[0];
    if (!extension) return undefined;
    const parsed = asn1js.fromBER(extension.extnValue.valueBlock.valueHexView);
    if (
        parsed.offset !== extension.extnValue.valueBlock.valueHexView.length ||
        !(parsed.result instanceof asn1js.OctetString) ||
        parsed.result.idBlock.isConstructed
    ) {
        return undefined;
    }
    const value = new Uint8Array(parsed.result.valueBlock.valueHexView);
    return value.length > 0 ? value : undefined;
}

/** Selects a signer using the original CMS SID, never certificate order. */
export function selectSignerCertificate(
    signerInfo: pkijs.SignerInfo,
    candidates: readonly pkijs.Certificate[]
): pkijs.Certificate {
    const sid: unknown = signerInfo.sid;
    let matches: pkijs.Certificate[];
    if (sid instanceof pkijs.IssuerAndSerialNumber) {
        matches = candidates.filter(
            (certificate) =>
                certificate.issuer.isEqual(sid.issuer) &&
                certificate.serialNumber.isEqual(sid.serialNumber)
        );
    } else if (
        sid instanceof asn1js.Primitive &&
        sid.idBlock.tagClass === 3 &&
        sid.idBlock.tagNumber === 0 &&
        !sid.idBlock.isConstructed
    ) {
        const keyIdentifier = new Uint8Array(sid.valueBlock.valueHexView);
        matches = candidates.filter((certificate) => {
            const subjectKeyIdentifier = getSubjectKeyIdentifier(certificate);
            return (
                subjectKeyIdentifier !== undefined &&
                bytesEqual(subjectKeyIdentifier, keyIdentifier)
            );
        });
    } else {
        throw verificationFailed("Timestamp SignerInfo contains an unsupported SID");
    }
    if (matches.length !== 1) {
        throw verificationFailed(
            `Timestamp SignerInfo SID matched ${matches.length.toString()} signer certificates; exactly one is required`
        );
    }
    const signer = matches[0];
    if (!signer)
        throw verificationFailed("Timestamp SignerInfo did not select a signer certificate");
    return signer;
}

function requireSingleSignedAttribute(
    signerInfo: pkijs.SignerInfo,
    oid: string,
    description: string
): pkijs.Attribute {
    const attributes =
        signerInfo.signedAttrs?.attributes.filter((attribute) => attribute.type === oid) ?? [];
    if (attributes.length !== 1) {
        throw verificationFailed(`Timestamp signed attributes require exactly one ${description}`);
    }
    const attribute = attributes[0];
    if (!attribute)
        throw verificationFailed(`Timestamp signed attributes are missing ${description}`);
    return attribute;
}

function validateRequiredCmsAttributes(signerInfo: pkijs.SignerInfo): void {
    if (!signerInfo.signedAttrs) {
        throw verificationFailed("Timestamp CMS signature must contain signed attributes");
    }
    const contentType = requireSingleSignedAttribute(
        signerInfo,
        ID_CONTENT_TYPE,
        "content-type attribute"
    );
    const contentTypeValue: unknown = contentType.values[0];
    if (
        contentType.values.length !== 1 ||
        !(contentTypeValue instanceof asn1js.ObjectIdentifier) ||
        contentTypeValue.valueBlock.toString() !== ID_CT_TST_INFO
    ) {
        throw verificationFailed("Timestamp signed content-type attribute must bind id-ct-TSTInfo");
    }
    const messageDigest = requireSingleSignedAttribute(
        signerInfo,
        ID_MESSAGE_DIGEST,
        "message-digest attribute"
    );
    if (
        messageDigest.values.length !== 1 ||
        !(messageDigest.values[0] instanceof asn1js.OctetString)
    ) {
        throw verificationFailed("Timestamp signed message-digest attribute is malformed");
    }
}

/** Verifies CMS content digest and signature after a prior original-SID selection. */
export async function verifyTimestampCmsSignature(
    signedData: pkijs.SignedData,
    signerInfo: pkijs.SignerInfo,
    signerCertificate: pkijs.Certificate
): Promise<void> {
    validateRequiredCmsAttributes(signerInfo);
    const originalCertificates = signedData.certificates;
    const originalContentType = signedData.encapContentInfo.eContentType;
    const originalSid = signerInfo.sid as asn1js.BaseBlock | pkijs.IssuerAndSerialNumber;
    try {
        // PKIjs' verifier derives SKI from the subject public key rather than the
        // actual certificate extension. Selection above intentionally follows the
        // RFC 5280 SKI extension, so temporarily switch only PKIjs' lookup key.
        signedData.certificates = [signerCertificate];
        signedData.encapContentInfo.eContentType = ID_DATA;
        signerInfo.sid = new pkijs.IssuerAndSerialNumber({
            issuer: signerCertificate.issuer,
            serialNumber: signerCertificate.serialNumber,
        });
        await ensureWebCrypto();
        const result = await signedData.verify({
            signer: 0,
            checkChain: false,
            extendedMode: true,
        });
        if (!result.signatureVerified) {
            throw verificationFailed("Timestamp CMS signature verification failed");
        }
    } catch (error) {
        if (error instanceof TimestampError) throw error;
        throw verificationFailed("Timestamp CMS signature verification failed", error);
    } finally {
        signedData.certificates = originalCertificates;
        signedData.encapContentInfo.eContentType = originalContentType;
        signerInfo.sid = originalSid;
    }
}

function parseEssIssuerSerial(schema: asn1js.BaseBlock): pkijs.IssuerSerial {
    if (!(schema instanceof asn1js.Sequence)) {
        throw verificationFailed("Timestamp ESS issuerSerial is malformed");
    }
    const fields = schema.valueBlock.value;
    const issuer = fields[0];
    const serialNumber = fields[1];
    if (
        fields.length !== 2 ||
        !(issuer instanceof asn1js.Sequence) ||
        !(serialNumber instanceof asn1js.Integer)
    ) {
        throw verificationFailed("Timestamp ESS issuerSerial is malformed");
    }
    try {
        const issuerSerial = new pkijs.IssuerSerial({ schema });
        if (issuerSerial.issuer.names.length === 0) {
            throw verificationFailed("Timestamp ESS issuerSerial is malformed");
        }
        return issuerSerial;
    } catch (error) {
        if (error instanceof TimestampError) throw error;
        throw verificationFailed("Timestamp ESS issuerSerial is malformed", error);
    }
}

function validateIssuerSerial(schema: asn1js.BaseBlock, certificate: pkijs.Certificate): void {
    const issuerSerial = parseEssIssuerSerial(schema);
    const names = issuerSerial.issuer.names;
    const name = names[0];
    if (
        names.length !== 1 ||
        name?.type !== 4 ||
        !(name.value instanceof pkijs.RelativeDistinguishedNames) ||
        !name.value.isEqual(certificate.issuer) ||
        !issuerSerial.serialNumber.isEqual(certificate.serialNumber)
    ) {
        throw verificationFailed("Timestamp ESS issuerSerial does not bind the selected signer");
    }
}

function isDisplayText(schema: asn1js.BaseBlock): boolean {
    if (
        !(
            schema instanceof asn1js.IA5String ||
            schema instanceof asn1js.VisibleString ||
            schema instanceof asn1js.BmpString ||
            schema instanceof asn1js.Utf8String
        )
    ) {
        return false;
    }
    const value = schema.valueBlock.value;
    return typeof value === "string" && value.length >= 1 && value.length <= 200;
}

function parseNoticeReference(schema: asn1js.Sequence, description: string): void {
    const fields = schema.valueBlock.value;
    const organization = fields[0];
    const noticeNumbers = fields[1];
    if (
        fields.length !== 2 ||
        organization === undefined ||
        !isDisplayText(organization) ||
        !(noticeNumbers instanceof asn1js.Sequence) ||
        noticeNumbers.valueBlock.value.length === 0 ||
        !noticeNumbers.valueBlock.value.every((number) => number instanceof asn1js.Integer)
    ) {
        throw verificationFailed(description + " UserNotice noticeRef is malformed");
    }
}

function parseUserNotice(schema: asn1js.BaseBlock, description: string): void {
    if (!(schema instanceof asn1js.Sequence)) {
        throw verificationFailed(description + " UserNotice qualifier is malformed");
    }
    const fields = schema.valueBlock.value;
    if (fields.length > 2) {
        throw verificationFailed(description + " UserNotice qualifier is malformed");
    }

    let index = 0;
    const noticeReference = fields[index];
    if (noticeReference instanceof asn1js.Sequence) {
        parseNoticeReference(noticeReference, description);
        index++;
    }
    const explicitText = fields[index];
    if (explicitText !== undefined) {
        if (!isDisplayText(explicitText)) {
            throw verificationFailed(description + " UserNotice qualifier is malformed");
        }
        index++;
    }
    if (index !== fields.length) {
        throw verificationFailed(description + " UserNotice qualifier is malformed");
    }
}

function parseKnownPolicyQualifier(
    identifier: asn1js.ObjectIdentifier,
    value: asn1js.BaseBlock,
    description: string
): void {
    const oid = identifier.valueBlock.toString();
    if (oid === ID_QT_CPS && !(value instanceof asn1js.IA5String)) {
        throw verificationFailed(description + " CPS qualifier is malformed");
    }
    if (oid === ID_QT_UNOTICE) parseUserNotice(value, description);
}

function parseEssPolicies(schema: asn1js.BaseBlock, description: string): void {
    if (!(schema instanceof asn1js.Sequence)) {
        throw verificationFailed(`${description} policies are malformed`);
    }
    for (const policy of schema.valueBlock.value) {
        if (!(policy instanceof asn1js.Sequence)) {
            throw verificationFailed(`${description} policy entry is malformed`);
        }
        const policyFields = policy.valueBlock.value;
        const policyIdentifier = policyFields[0];
        if (
            (policyFields.length !== 1 && policyFields.length !== 2) ||
            !(policyIdentifier instanceof asn1js.ObjectIdentifier) ||
            policyIdentifier.valueBlock.toString().length === 0
        ) {
            throw verificationFailed(`${description} policy entry is malformed`);
        }
        const qualifiers = policyFields[1];
        if (qualifiers === undefined) continue;
        if (!(qualifiers instanceof asn1js.Sequence) || qualifiers.valueBlock.value.length === 0) {
            throw verificationFailed(`${description} policy qualifiers are malformed`);
        }
        for (const qualifier of qualifiers.valueBlock.value) {
            if (
                !(qualifier instanceof asn1js.Sequence) ||
                qualifier.valueBlock.value.length !== 2
            ) {
                throw verificationFailed(`${description} policy qualifier is malformed`);
            }
            const qualifierIdentifier = qualifier.valueBlock.value[0];
            const qualifierValue = qualifier.valueBlock.value[1];
            if (
                !(qualifierIdentifier instanceof asn1js.ObjectIdentifier) ||
                qualifierIdentifier.valueBlock.toString().length === 0 ||
                qualifierValue === undefined ||
                qualifierValue instanceof asn1js.Any
            ) {
                throw verificationFailed(`${description} policy qualifier is malformed`);
            }
            parseKnownPolicyQualifier(qualifierIdentifier, qualifierValue, description);
        }
    }
}

function essCertificateSequence(
    attribute: pkijs.Attribute,
    description: string
): asn1js.Sequence[] {
    const value: unknown = attribute.values[0];
    if (attribute.values.length !== 1 || !(value instanceof asn1js.Sequence)) {
        throw verificationFailed(`${description} attribute is malformed`);
    }
    const outer = value.valueBlock.value;
    const certs = outer[0];
    if (
        (outer.length !== 1 && outer.length !== 2) ||
        !(certs instanceof asn1js.Sequence) ||
        certs.valueBlock.value.length === 0 ||
        !certs.valueBlock.value.every((certId) => certId instanceof asn1js.Sequence)
    ) {
        throw verificationFailed(`${description} certificate identifiers are malformed`);
    }
    const policies = outer[1];
    if (policies !== undefined) parseEssPolicies(policies, description);
    return certs.valueBlock.value;
}

interface ParsedEssCertId {
    hash: Uint8Array;
    issuerSerial?: asn1js.BaseBlock;
}

function parseEssV1CertId(schema: asn1js.Sequence): ParsedEssCertId {
    const fields = schema.valueBlock.value;
    const certificateHash = fields[0];
    if (
        (fields.length !== 1 && fields.length !== 2) ||
        !(certificateHash instanceof asn1js.OctetString) ||
        certificateHash.idBlock.isConstructed
    ) {
        throw verificationFailed("Timestamp ESSCertID is malformed");
    }
    const hash = new Uint8Array(certificateHash.valueBlock.valueHexView);
    if (hash.length !== 20) {
        throw verificationFailed("Timestamp ESSCertID has an invalid SHA-1 hash length");
    }
    const issuerSerial = fields[1];
    if (issuerSerial !== undefined) parseEssIssuerSerial(issuerSerial);
    return { hash, ...(issuerSerial !== undefined && { issuerSerial }) };
}

interface ParsedEssCertIdV2 extends ParsedEssCertId {
    hashAlgorithm: EssHashAlgorithm;
}

function essV2HashAlgorithm(schema: asn1js.Sequence): {
    algorithm: EssHashAlgorithm;
    digestLength: number;
} {
    const fields = schema.valueBlock.value;
    const oid = fields[0];
    if (
        (fields.length !== 1 && fields.length !== 2) ||
        !(oid instanceof asn1js.ObjectIdentifier) ||
        oid.valueBlock.toString().length === 0
    ) {
        throw verificationFailed("Timestamp ESSCertIDv2 hash algorithm is malformed");
    }
    const configuredHash = ESS_HASH_ALGORITHMS[oid.valueBlock.toString()];
    if (!configuredHash) {
        throw verificationFailed("Timestamp ESSCertIDv2 uses an unsupported hash algorithm");
    }
    return configuredHash;
}

function parseEssV2CertId(schema: asn1js.Sequence): ParsedEssCertIdV2 {
    const fields = schema.valueBlock.value;
    let index = 0;
    let hashAlgorithm: EssHashAlgorithm = "SHA-256";
    let expectedDigestLength = 32;
    const first = fields[index];
    if (first instanceof asn1js.Sequence) {
        const configuredHash = essV2HashAlgorithm(first);
        hashAlgorithm = configuredHash.algorithm;
        expectedDigestLength = configuredHash.digestLength;
        index++;
    }
    const certificateHash = fields[index];
    if (!(certificateHash instanceof asn1js.OctetString) || certificateHash.idBlock.isConstructed) {
        throw verificationFailed("Timestamp ESSCertIDv2 is malformed");
    }
    index++;
    if (fields.length !== index && fields.length !== index + 1) {
        throw verificationFailed("Timestamp ESSCertIDv2 is malformed");
    }
    const hash = new Uint8Array(certificateHash.valueBlock.valueHexView);
    if (hash.length !== expectedDigestLength) {
        throw verificationFailed("Timestamp ESSCertIDv2 has an invalid certificate hash length");
    }
    const issuerSerial = fields[index];
    if (issuerSerial !== undefined) parseEssIssuerSerial(issuerSerial);
    return {
        hash,
        hashAlgorithm,
        ...(issuerSerial !== undefined && { issuerSerial }),
    };
}

async function validateEssV1(
    attribute: pkijs.Attribute,
    certificate: pkijs.Certificate
): Promise<void> {
    const certs = essCertificateSequence(attribute, "Timestamp SigningCertificate");
    const first = certs[0];
    if (!first) throw verificationFailed("Timestamp SigningCertificate is missing an ESSCertID");
    const firstCertId = parseEssV1CertId(first);
    for (const certId of certs.slice(1)) parseEssV1CertId(certId);

    await ensureWebCrypto();
    const expectedHash = new Uint8Array(
        await crypto.subtle.digest("SHA-1", certificate.toSchema().toBER(false))
    );
    if (!bytesEqual(firstCertId.hash, expectedHash)) {
        throw verificationFailed(
            "Timestamp ESSCertID does not bind the selected signer certificate"
        );
    }
    if (firstCertId.issuerSerial) {
        validateIssuerSerial(firstCertId.issuerSerial, certificate);
    }
}

async function validateEssV2(
    attribute: pkijs.Attribute,
    certificate: pkijs.Certificate
): Promise<void> {
    const certs = essCertificateSequence(attribute, "Timestamp SigningCertificateV2");
    const first = certs[0];
    if (!first)
        throw verificationFailed("Timestamp SigningCertificateV2 is missing an ESSCertIDv2");
    const firstCertId = parseEssV2CertId(first);
    for (const certId of certs.slice(1)) parseEssV2CertId(certId);

    await ensureWebCrypto();
    const expectedHash = new Uint8Array(
        await crypto.subtle.digest(firstCertId.hashAlgorithm, certificate.toSchema().toBER(false))
    );
    if (!bytesEqual(firstCertId.hash, expectedHash)) {
        throw verificationFailed(
            "Timestamp ESSCertIDv2 does not bind the selected signer certificate"
        );
    }
    if (firstCertId.issuerSerial) {
        validateIssuerSerial(firstCertId.issuerSerial, certificate);
    }
}

/** Validates complete signed ESS v1/v2 certificate bindings. */
export async function validateTimestampESS(
    signerInfo: pkijs.SignerInfo,
    signerCertificate: pkijs.Certificate
): Promise<void> {
    const attributes = signerInfo.signedAttrs?.attributes ?? [];
    const v1 = attributes.filter((attribute) => attribute.type === ID_SIGNING_CERTIFICATE);
    const v2 = attributes.filter((attribute) => attribute.type === ID_SIGNING_CERTIFICATE_V2);
    if (v1.length > 1 || v2.length > 1) {
        throw verificationFailed("Timestamp contains duplicate ESS signing-certificate attributes");
    }
    if (v1.length === 0 && v2.length === 0) {
        throw verificationFailed("Timestamp is missing a signed ESS signing-certificate attribute");
    }
    const v1Attribute = v1[0];
    const v2Attribute = v2[0];
    if (v1Attribute) await validateEssV1(v1Attribute, signerCertificate);
    if (v2Attribute) await validateEssV2(v2Attribute, signerCertificate);
}

/** RFC 3161 requires exactly one critical EKU with only id-kp-timeStamping. */
export function hasTimestampingEKU(certificate: pkijs.Certificate): boolean {
    const extensions = certificate.extensions?.filter(
        (extension) => extension.extnID === ID_EXTENDED_KEY_USAGE
    );
    if (extensions?.length !== 1) return false;
    const extension = extensions[0];
    if (!extension?.critical) return false;
    const encoded = extension.extnValue.valueBlock.valueHexView;
    const parsed = asn1js.fromBER(encoded);
    if (
        parsed.offset !== encoded.length ||
        !(parsed.result instanceof asn1js.Sequence) ||
        parsed.result.valueBlock.value.length !== 1
    ) {
        return false;
    }
    const purpose = parsed.result.valueBlock.value[0];
    return (
        purpose instanceof asn1js.ObjectIdentifier &&
        purpose.valueBlock.toString() === ID_KP_TIMESTAMPING
    );
}

function externalCertificates(options: TimestampResponseValidationOptions): pkijs.Certificate[] {
    const supplied = options.signerCertificates;
    if (!supplied || supplied.length === 0) {
        throw verificationFailed("certReq=false requires an external signer certificate");
    }
    return supplied.map((certificate, index) =>
        parseCertificate(certificate, `External signer certificate ${index.toString()}`)
    );
}

/**
 * Authenticates and request-binds a raw ContentInfo or complete TimeStampResp
 * before a caller embeds the returned token in a PDF. This intentionally does
 * not establish trust in a TSA; callers must apply their own trust policy.
 */
export async function validateTimestampToken(
    responseOrToken: Uint8Array,
    context: TimestampRequestContext,
    options: TimestampResponseValidationOptions = {}
): Promise<ValidatedTimestampToken> {
    const parsed = parseTimestampToken(responseOrToken);
    await validateRequestBinding(parsed.tstInfo, context);

    const embeddedCertificates = getEmbeddedCertificates(parsed.signedData);
    let candidates: pkijs.Certificate[];
    if (context.requestCertificate) {
        candidates = embeddedCertificates;
    } else {
        if (parsed.signedData.certificates !== undefined) {
            throw verificationFailed("certReq=false response must not embed certificates");
        }
        candidates = externalCertificates(options);
    }
    const signerCertificate = selectSignerCertificate(parsed.signerInfo, candidates);
    await verifyTimestampCmsSignature(parsed.signedData, parsed.signerInfo, signerCertificate);
    await validateTimestampESS(parsed.signerInfo, signerCertificate);
    if (!hasTimestampingEKU(signerCertificate)) {
        throw verificationFailed(
            "Timestamp signer certificate must have one critical exclusive id-kp-timeStamping EKU"
        );
    }

    return {
        token: parsed.token,
        info: parsed.info,
        signerCertificate,
        certificates: context.requestCertificate ? embeddedCertificates : candidates,
        responseStatus: parsed.responseStatus,
    };
}

/** Returns the RFC 3161 hash name for a supported message-imprint OID. */
export function hashAlgorithmForTimestampOid(oid: string): HashAlgorithm | undefined {
    const value = OID_TO_HASH_ALGORITHM[oid];
    return value === "SHA-256" || value === "SHA-384" || value === "SHA-512" ? value : undefined;
}
