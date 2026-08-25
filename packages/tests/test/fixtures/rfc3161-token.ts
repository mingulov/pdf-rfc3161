import * as asn1js from "asn1js";
import * as pkijs from "pkijs";
import { HASH_ALGORITHM_TO_OID, OID_TO_HASH_ALGORITHM } from "../../../core/src/constants.js";
import type { HashAlgorithm } from "../../../core/src/types.js";
import { cryptoEngine, generateRSAKeyPair, importKeyForCertificate } from "../utils/crypto.js";

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
const ID_KP_CLIENT_AUTH = "1.3.6.1.5.5.7.3.2";
const ID_ANY_EXTENDED_KEY_USAGE = "2.5.29.37.0";

export interface FixtureRequestContext {
    data: Uint8Array;
    hashAlgorithm: HashAlgorithm;
    nonce: Uint8Array;
    policy?: string;
    requestCertificate: boolean;
}

type ESSMode =
    | "v1"
    | "v2"
    | "both"
    | "missing"
    | "malformed"
    | "mismatched"
    | "duplicate"
    | "unsupported"
    | "conflicting";

type EKUMode = "strict" | "noncritical" | "extra" | "any" | "missing" | "duplicate" | "malformed";

type CertificateValidity = "valid" | "expired" | "notYetValid";
type ESSAdditionalMode = "valid" | "malformed" | "wrongFirst" | "unsupportedAlgorithm";
type ESSIssuerSerialMode = "extraUidFirst" | "extraUidAdditional";
type ESSPoliciesMode =
    | "empty"
    | "valid"
    | "malformed"
    | "wrongCpsType"
    | "wrongUserNoticeType"
    | "malformedUserNotice"
    | "emptyUserNoticeNumbers";
type OuterDerFraming = "indefinite" | "nonMinimal" | "highTagShort" | "highTagLeadingZero";

export type EncapsulatedContentEncoding = "primitive" | "constructed";
type FixtureEContentEncoding =
    | EncapsulatedContentEncoding
    | "constructedEmptySegment"
    | "constructedNestedSegment";

export interface RFC3161TokenFixtureOptions {
    hashAlgorithm?: HashAlgorithm;
    data?: Uint8Array;
    nonce?: Uint8Array;
    responseNonce?: Uint8Array | "missing" | "zero" | "negative";
    policy?: string;
    responsePolicy?: string;
    requestCertificate?: boolean;
    form?: "raw" | "response";
    status?: number;
    statusString?: string;
    statusStrings?: readonly string[];
    includeToken?: boolean;
    contentType?: "signedData" | "data";
    eContentType?: "tstInfo" | "data";
    eContentEncoding?: FixtureEContentEncoding;
    outerTokenFraming?: OuterDerFraming;
    responseOuterFraming?: OuterDerFraming;
    signerSid?: "issuerSerial" | "ski" | "zero";
    certificates?: "signer" | "decoyFirst" | "none" | "ambiguous";
    ess?: ESSMode;
    essAdditional?: ESSAdditionalMode;
    essIssuerSerial?: ESSIssuerSerialMode;
    essPolicies?: ESSPoliciesMode;
    eku?: EKUMode;
    certificateValidity?: CertificateValidity;
    imprint?: "valid" | "mismatch" | "wrongAlgorithm" | "wrongLength";
    signerCount?: 1 | 2;
    corruptSignature?: boolean;
}

export interface RFC3161TokenFixture {
    context: FixtureRequestContext;
    rawToken: Uint8Array;
    response: Uint8Array;
    input: Uint8Array;
    signerCertificate: Uint8Array;
    decoyCertificate: Uint8Array;
}

interface TokenSource {
    context: FixtureRequestContext;
    messageDigest: Uint8Array;
}

interface SuiteKeys {
    signer: CryptoKeyPair;
    decoy: CryptoKeyPair;
}

let suiteKeysPromise: Promise<SuiteKeys> | undefined;

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
    return new Uint8Array(bytes).buffer;
}

/**
 * Inspects the encoded CMS tree directly, without constructing PKIjs
 * EncapsulatedContentInfo (which normalizes primitive OCTET STRING values).
 */
export function encodedTstInfoEContentEncoding(input: Uint8Array): EncapsulatedContentEncoding {
    const parsed = asn1js.fromBER(toArrayBuffer(input));
    if (parsed.offset !== input.length || !(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("Fixture token is not complete DER");
    }

    const outerChildren = parsed.result.valueBlock.value;
    const contentInfo =
        outerChildren[0] instanceof asn1js.ObjectIdentifier
            ? parsed.result
            : outerChildren.length === 2 && outerChildren[1] instanceof asn1js.Sequence
              ? outerChildren[1]
              : undefined;
    if (!contentInfo) throw new Error("Fixture token is neither ContentInfo nor TimeStampResp");

    const contentInfoChildren = contentInfo.valueBlock.value;
    const explicitContent = contentInfoChildren[1];
    if (
        !(explicitContent instanceof asn1js.Constructed) ||
        explicitContent.idBlock.tagClass !== 3 ||
        explicitContent.idBlock.tagNumber !== 0 ||
        explicitContent.valueBlock.value.length !== 1
    ) {
        throw new Error("Fixture ContentInfo has malformed explicit content");
    }
    const signedData = explicitContent.valueBlock.value[0];
    if (!(signedData instanceof asn1js.Sequence)) {
        throw new Error("Fixture ContentInfo does not contain SignedData");
    }
    const signedDataChildren = signedData.valueBlock.value;
    const encapContentInfo = signedDataChildren[2];
    if (!(encapContentInfo instanceof asn1js.Sequence)) {
        throw new Error("Fixture SignedData has no EncapsulatedContentInfo");
    }
    const encapChildren = encapContentInfo.valueBlock.value;
    const explicitEContent = encapChildren[1];
    if (
        !(explicitEContent instanceof asn1js.Constructed) ||
        explicitEContent.idBlock.tagClass !== 3 ||
        explicitEContent.idBlock.tagNumber !== 0 ||
        explicitEContent.valueBlock.value.length !== 1
    ) {
        throw new Error("Fixture EncapsulatedContentInfo has malformed eContent");
    }
    const eContent = explicitEContent.valueBlock.value[0];
    if (!(eContent instanceof asn1js.OctetString)) {
        throw new Error("Fixture EncapsulatedContentInfo eContent is not an OCTET STRING");
    }
    return eContent.idBlock.isConstructed ? "constructed" : "primitive";
}

function reencodeTstInfoEContent(
    rawToken: Uint8Array,
    tstInfoBytes: Uint8Array,
    encoding: FixtureEContentEncoding
): Uint8Array {
    const parsed = asn1js.fromBER(toArrayBuffer(rawToken));
    if (parsed.offset !== rawToken.length || !(parsed.result instanceof asn1js.Sequence)) {
        throw new Error("Fixture raw token is not complete DER");
    }
    const contentInfoChildren = parsed.result.valueBlock.value;
    const explicitContent = contentInfoChildren[1];
    if (
        !(explicitContent instanceof asn1js.Constructed) ||
        explicitContent.valueBlock.value.length !== 1
    ) {
        throw new Error("Fixture raw token has malformed ContentInfo content");
    }
    const signedData = explicitContent.valueBlock.value[0];
    if (!(signedData instanceof asn1js.Sequence)) {
        throw new Error("Fixture raw token does not contain SignedData");
    }
    const encapContentInfo = signedData.valueBlock.value[2];
    if (!(encapContentInfo instanceof asn1js.Sequence)) {
        throw new Error("Fixture raw token has no EncapsulatedContentInfo");
    }
    const explicitEContent = encapContentInfo.valueBlock.value[1];
    if (
        !(explicitEContent instanceof asn1js.Constructed) ||
        explicitEContent.valueBlock.value.length !== 1
    ) {
        throw new Error("Fixture raw token has malformed eContent");
    }

    const primitive = new asn1js.OctetString({ valueHex: toArrayBuffer(tstInfoBytes) });
    const constructed = (segments: asn1js.OctetString[]): asn1js.OctetString =>
        new asn1js.OctetString({
            idBlock: { isConstructed: true },
            isConstructed: true,
            value: segments,
        });
    explicitEContent.valueBlock.value = [
        encoding === "primitive"
            ? primitive
            : encoding === "constructedEmptySegment"
              ? constructed([new asn1js.OctetString(), primitive])
              : encoding === "constructedNestedSegment"
                ? constructed([constructed([primitive])])
                : constructed([primitive]),
    ];
    const reencoded = new Uint8Array(parsed.result.toBER(false));
    const expectedEncoding = encoding === "primitive" ? "primitive" : "constructed";
    if (encodedTstInfoEContentEncoding(reencoded) !== expectedEncoding) {
        throw new Error(`Fixture failed to encode ${encoding} eContent`);
    }
    return reencoded;
}

function concatenateBytes(parts: readonly Uint8Array[]): Uint8Array {
    const length = parts.reduce((total, part) => total + part.length, 0);
    const output = new Uint8Array(length);
    let offset = 0;
    for (const part of parts) {
        output.set(part, offset);
        offset += part.length;
    }
    return output;
}

function canonicalLengthBytes(length: number): Uint8Array {
    if (length < 0x80) return new Uint8Array([length]);
    const octets: number[] = [];
    let remaining = length;
    while (remaining > 0) {
        octets.unshift(remaining & 0xff);
        remaining >>>= 8;
    }
    return new Uint8Array([0x80 | octets.length, ...octets]);
}

function outerDerContents(bytes: Uint8Array, description: string): Uint8Array {
    if (bytes[0] !== 0x30) throw new Error(`${description} is not a SEQUENCE`);
    const firstLength = bytes[1];
    if (firstLength === undefined || firstLength === 0x80 || firstLength > 0x84) {
        throw new Error(`${description} does not use a supported canonical DER length`);
    }
    if (firstLength < 0x80) {
        const end = 2 + firstLength;
        if (end !== bytes.length) throw new Error(`${description} is not complete DER`);
        return bytes.subarray(2);
    }

    const lengthOctets = firstLength & 0x7f;
    const start = 2;
    const end = start + lengthOctets;
    if (lengthOctets === 0 || end > bytes.length || bytes[start] === 0) {
        throw new Error(`${description} does not use a supported canonical DER length`);
    }
    let length = 0;
    for (const value of bytes.subarray(start, end)) length = (length << 8) | value;
    if (length < 0x80 || end + length !== bytes.length) {
        throw new Error(`${description} is not complete DER`);
    }
    return bytes.subarray(end);
}

function reframeOuterDer(bytes: Uint8Array, framing: OuterDerFraming, description: string): Uint8Array {
    const contents = outerDerContents(bytes, description);
    if (framing === "indefinite") {
        return concatenateBytes([new Uint8Array([0x30, 0x80]), contents, new Uint8Array([0, 0])]);
    }

    if (framing === "highTagShort" || framing === "highTagLeadingZero") {
        const tag =
            framing === "highTagShort"
                ? new Uint8Array([0x3f, 0x10])
                : new Uint8Array([0x3f, 0x80, 0x10]);
        return concatenateBytes([tag, canonicalLengthBytes(contents.length), contents]);
    }

    const length = canonicalLengthBytes(contents.length);
    const firstLengthByte = length[0];
    if (firstLengthByte === undefined) throw new Error("Fixture length is unexpectedly empty");
    const nonMinimalLength =
        contents.length < 0x80
            ? new Uint8Array([0x81, contents.length])
            : new Uint8Array([firstLengthByte + 1, 0, ...length.subarray(1)]);
    return concatenateBytes([new Uint8Array([0x30]), nonMinimalLength, contents]);
}

function replaceNestedToken(
    response: Uint8Array,
    canonicalToken: Uint8Array,
    framedToken: Uint8Array
): Uint8Array {
    const contents = outerDerContents(response, "Fixture TimeStampResp");
    let tokenOffset = -1;
    for (let index = 0; index <= contents.length - canonicalToken.length; index++) {
        if (bytesEqual(contents.subarray(index, index + canonicalToken.length), canonicalToken)) {
            tokenOffset = index;
            break;
        }
    }
    if (tokenOffset < 0) throw new Error("Fixture TimeStampResp does not contain the token bytes");
    const replaced = concatenateBytes([
        contents.subarray(0, tokenOffset),
        framedToken,
        contents.subarray(tokenOffset + canonicalToken.length),
    ]);
    return concatenateBytes([new Uint8Array([0x30]), canonicalLengthBytes(replaced.length), replaced]);
}

function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
    if (left.length !== right.length) return false;
    let difference = 0;
    for (let i = 0; i < left.length; i++) {
        const leftByte = left[i];
        const rightByte = right[i];
        if (leftByte === undefined || rightByte === undefined) return false;
        difference |= leftByte ^ rightByte;
    }
    return difference === 0;
}

function copyBytes(bytes: Uint8Array): Uint8Array {
    return new Uint8Array(bytes);
}

function oidForHashAlgorithm(hashAlgorithm: HashAlgorithm): string {
    const oid = HASH_ALGORITHM_TO_OID[hashAlgorithm];
    if (!oid) throw new Error(`Unsupported fixture hash algorithm: ${hashAlgorithm}`);
    return oid;
}

function digestLength(hashAlgorithm: HashAlgorithm): number {
    switch (hashAlgorithm) {
        case "SHA-256":
            return 32;
        case "SHA-384":
            return 48;
        case "SHA-512":
            return 64;
    }
}

async function getSuiteKeys(): Promise<SuiteKeys> {
    suiteKeysPromise ??= (async () => ({
        signer: await generateRSAKeyPair(),
        decoy: await generateRSAKeyPair(),
    }))();
    return suiteKeysPromise;
}

function makeEkuExtension(mode: EKUMode): pkijs.Extension[] {
    if (mode === "missing") return [];
    if (mode === "malformed") {
        return [
            new pkijs.Extension({
                extnID: ID_EXTENDED_KEY_USAGE,
                critical: true,
                extnValue: new Uint8Array([0x05, 0x00]).buffer,
            }),
        ];
    }

    const purposes =
        mode === "extra"
            ? [ID_KP_TIMESTAMPING, ID_KP_CLIENT_AUTH]
            : mode === "any"
              ? [ID_ANY_EXTENDED_KEY_USAGE]
              : [ID_KP_TIMESTAMPING];
    const extension = new pkijs.Extension({
        extnID: ID_EXTENDED_KEY_USAGE,
        critical: mode !== "noncritical",
        extnValue: new pkijs.ExtKeyUsage({ keyPurposes: purposes }).toSchema().toBER(false),
    });
    return mode === "duplicate" ? [extension, extension] : [extension];
}

function makeSkiExtension(ski: Uint8Array): pkijs.Extension {
    return new pkijs.Extension({
        extnID: ID_SUBJECT_KEY_IDENTIFIER,
        critical: false,
        extnValue: new asn1js.OctetString({ valueHex: toArrayBuffer(ski) }).toBER(false),
    });
}

async function createCertificate(
    keys: CryptoKeyPair,
    commonName: string,
    serial: number,
    ski: Uint8Array,
    eku: EKUMode,
    validity: CertificateValidity = "valid"
): Promise<pkijs.Certificate> {
    const certificate = new pkijs.Certificate();
    certificate.version = 2;
    certificate.serialNumber = new asn1js.Integer({ value: serial });
    certificate.subject.typesAndValues.push(
        new pkijs.AttributeTypeAndValue({
            type: "2.5.4.3",
            value: new asn1js.PrintableString({ value: commonName }),
        })
    );
    certificate.issuer = certificate.subject;
    if (validity === "expired") {
        certificate.notBefore.value = new Date("2020-01-01T00:00:00Z");
        certificate.notAfter.value = new Date("2025-01-01T00:00:00Z");
    } else if (validity === "notYetValid") {
        certificate.notBefore.value = new Date("2027-01-01T00:00:00Z");
        certificate.notAfter.value = new Date("2030-01-01T00:00:00Z");
    } else {
        certificate.notBefore.value = new Date("2025-01-01T00:00:00Z");
        certificate.notAfter.value = new Date("2030-01-01T00:00:00Z");
    }
    certificate.subjectPublicKeyInfo = await importKeyForCertificate(keys.publicKey);
    certificate.extensions = [makeSkiExtension(ski), ...makeEkuExtension(eku)];
    await certificate.sign(keys.privateKey, "SHA-256", cryptoEngine);
    return certificate;
}

function certificateBytes(certificate: pkijs.Certificate): Uint8Array {
    return new Uint8Array(certificate.toSchema().toBER(false));
}

function issuerSerial(certificate: pkijs.Certificate, includeIssuerUid = false): asn1js.Sequence {
    const schema = new pkijs.IssuerSerial({
        issuer: new pkijs.GeneralNames({
            names: [new pkijs.GeneralName({ type: 4, value: certificate.issuer })],
        }),
        serialNumber: certificate.serialNumber,
    }).toSchema();
    if (includeIssuerUid) {
        schema.valueBlock.value.push(
            new asn1js.BitString({ valueHex: toArrayBuffer(new Uint8Array([0x80])) })
        );
    }
    return schema;
}

async function certificateHash(
    certificate: pkijs.Certificate,
    algorithm: AlgorithmIdentifier
): Promise<Uint8Array> {
    return new Uint8Array(
        await crypto.subtle.digest(algorithm, certificate.toSchema().toBER(false))
    );
}

type AlgorithmIdentifier = "SHA-1" | "SHA-256";

async function createEssV1CertId(
    certificate: pkijs.Certificate,
    options: { mismatch?: boolean; includeIssuerSerial?: boolean; includeIssuerUid?: boolean } = {}
): Promise<asn1js.Sequence> {
    const hash = await certificateHash(certificate, "SHA-1");
    if (options.mismatch) {
        const first = hash[0];
        if (first === undefined) throw new Error("Fixture SHA-1 certificate hash is empty");
        hash[0] = first ^ 0xff;
    }
    return new asn1js.Sequence({
        value: [
            new asn1js.OctetString({ valueHex: toArrayBuffer(hash) }),
            ...(options.includeIssuerSerial !== false
                ? [issuerSerial(certificate, options.includeIssuerUid)]
                : []),
        ],
    });
}

function essPolicies(mode: ESSPoliciesMode | undefined): asn1js.Sequence | undefined {
    if (mode === undefined) return undefined;
    if (mode === "empty") return new asn1js.Sequence();
    if (mode === "malformed") {
        return new asn1js.Sequence({ value: [new asn1js.OctetString()] });
    }

    const noticeNumbers =
        mode === "emptyUserNoticeNumbers" ? [] : [new asn1js.Integer({ value: 1 })];
    const userNotice = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({
                value: [
                    new asn1js.Utf8String({ value: "Example TSA" }),
                    new asn1js.Sequence({ value: noticeNumbers }),
                ],
            }),
            new asn1js.Utf8String({ value: "Timestamp policy notice" }),
        ],
    });
    const malformedUserNotice = new asn1js.Sequence({
        value: [
            new asn1js.Sequence({
                value: [
                    new asn1js.OctetString({ valueHex: toArrayBuffer(new Uint8Array([1])) }),
                    new asn1js.Sequence({ value: [new asn1js.Integer({ value: 1 })] }),
                ],
            }),
        ],
    });
    const qualifiers =
        mode === "wrongCpsType"
            ? [
                  new pkijs.PolicyQualifierInfo({
                      policyQualifierId: ID_QT_CPS,
                      qualifier: new asn1js.OctetString({
                          valueHex: toArrayBuffer(new Uint8Array([1])),
                      }),
                  }),
              ]
            : mode === "wrongUserNoticeType"
              ? [
                    new pkijs.PolicyQualifierInfo({
                        policyQualifierId: ID_QT_UNOTICE,
                        qualifier: new asn1js.Utf8String({ value: "not a UserNotice" }),
                    }),
                ]
              : mode === "malformedUserNotice"
                ? [
                      new pkijs.PolicyQualifierInfo({
                          policyQualifierId: ID_QT_UNOTICE,
                          qualifier: malformedUserNotice,
                      }),
                  ]
                : mode === "emptyUserNoticeNumbers"
                  ? [
                        new pkijs.PolicyQualifierInfo({
                            policyQualifierId: ID_QT_UNOTICE,
                            qualifier: userNotice,
                        }),
                    ]
                : [
                      new pkijs.PolicyQualifierInfo({
                          policyQualifierId: ID_QT_CPS,
                          qualifier: new asn1js.IA5String({
                              value: "https://example.test/tsa-policy",
                          }),
                      }),
                      new pkijs.PolicyQualifierInfo({
                          policyQualifierId: ID_QT_UNOTICE,
                          qualifier: userNotice,
                      }),
                  ];
    const policy = new pkijs.PolicyInformation({
        policyIdentifier: "1.2.3.4.5.6.7",
        policyQualifiers: qualifiers,
    });
    return new asn1js.Sequence({ value: [policy.toSchema()] });
}

async function createEssV1(
    certificate: pkijs.Certificate,
    additionalCertificate: pkijs.Certificate,
    options: {
        mismatch?: boolean;
        additional?: ESSAdditionalMode;
        issuerSerial?: ESSIssuerSerialMode;
        policies?: ESSPoliciesMode;
    } = {}
): Promise<pkijs.Attribute> {
    const firstCertificate =
        options.additional === "wrongFirst" ? additionalCertificate : certificate;
    const certs: asn1js.Sequence[] = [
        await createEssV1CertId(firstCertificate, {
            mismatch: options.mismatch,
            includeIssuerUid: options.issuerSerial === "extraUidFirst",
        }),
    ];
    if (options.additional === "valid") {
        certs.push(
            await createEssV1CertId(additionalCertificate, {
                includeIssuerUid: options.issuerSerial === "extraUidAdditional",
            })
        );
    } else if (options.additional === "wrongFirst") {
        certs.push(await createEssV1CertId(certificate));
    } else if (options.additional === "malformed") {
        certs.push(
            new asn1js.Sequence({
                value: [new asn1js.OctetString({ valueHex: new ArrayBuffer(19) })],
            })
        );
    } else if (options.additional === "unsupportedAlgorithm") {
        certs.push(
            new asn1js.Sequence({
                value: [
                    new pkijs.AlgorithmIdentifier({ algorithmId: "1.2.3.4" }).toSchema(),
                    new asn1js.OctetString({ valueHex: new ArrayBuffer(20) }),
                ],
            })
        );
    }
    const value = [new asn1js.Sequence({ value: certs })];
    const policies = essPolicies(options.policies);
    if (policies) value.push(policies);
    return new pkijs.Attribute({
        type: ID_SIGNING_CERTIFICATE,
        values: [new asn1js.Sequence({ value })],
    });
}

async function createEssV2CertId(
    certificate: pkijs.Certificate,
    options: {
        mismatch?: boolean;
        unsupported?: boolean;
        includeIssuerSerial?: boolean;
        includeIssuerUid?: boolean;
    } = {}
): Promise<asn1js.Sequence> {
    const hashAlgorithm = "SHA-256";
    const oid = options.unsupported ? "1.2.3.4" : oidForHashAlgorithm(hashAlgorithm);
    const hash = await certificateHash(certificate, hashAlgorithm);
    if (options.mismatch) {
        const first = hash[0];
        if (first === undefined) throw new Error("Fixture SHA-256 certificate hash is empty");
        hash[0] = first ^ 0xff;
    }
    return new asn1js.Sequence({
        value: [
            ...(options.unsupported
                ? [new pkijs.AlgorithmIdentifier({ algorithmId: oid }).toSchema()]
                : []),
            new asn1js.OctetString({ valueHex: toArrayBuffer(hash) }),
            ...(options.includeIssuerSerial !== false
                ? [issuerSerial(certificate, options.includeIssuerUid)]
                : []),
        ],
    });
}

async function createEssV2(
    certificate: pkijs.Certificate,
    additionalCertificate: pkijs.Certificate,
    options: {
        mismatch?: boolean;
        unsupported?: boolean;
        additional?: ESSAdditionalMode;
        issuerSerial?: ESSIssuerSerialMode;
        policies?: ESSPoliciesMode;
    } = {}
): Promise<pkijs.Attribute> {
    const firstCertificate =
        options.additional === "wrongFirst" ? additionalCertificate : certificate;
    const certs: asn1js.Sequence[] = [
        await createEssV2CertId(firstCertificate, {
            mismatch: options.mismatch,
            unsupported: options.unsupported,
            includeIssuerUid: options.issuerSerial === "extraUidFirst",
        }),
    ];
    if (options.additional === "valid") {
        certs.push(
            await createEssV2CertId(additionalCertificate, {
                includeIssuerUid: options.issuerSerial === "extraUidAdditional",
            })
        );
    } else if (options.additional === "wrongFirst") {
        certs.push(await createEssV2CertId(certificate));
    } else if (options.additional === "malformed") {
        certs.push(
            new asn1js.Sequence({
                value: [new asn1js.OctetString({ valueHex: new ArrayBuffer(31) })],
            })
        );
    } else if (options.additional === "unsupportedAlgorithm") {
        certs.push(await createEssV2CertId(additionalCertificate, { unsupported: true }));
    }
    const value = [new asn1js.Sequence({ value: certs })];
    const policies = essPolicies(options.policies);
    if (policies) value.push(policies);
    return new pkijs.Attribute({
        type: ID_SIGNING_CERTIFICATE_V2,
        values: [new asn1js.Sequence({ value })],
    });
}

async function createEssAttributes(
    mode: ESSMode,
    certificate: pkijs.Certificate,
    additionalCertificate: pkijs.Certificate,
    options: Pick<
        RFC3161TokenFixtureOptions,
        "essAdditional" | "essIssuerSerial" | "essPolicies"
    >
): Promise<pkijs.Attribute[]> {
    switch (mode) {
        case "missing":
            return [];
        case "malformed":
            return [
                new pkijs.Attribute({
                    type: ID_SIGNING_CERTIFICATE_V2,
                    values: [new asn1js.OctetString({ valueHex: new Uint8Array([1]).buffer })],
                }),
            ];
        case "mismatched":
            return [await createEssV2(certificate, additionalCertificate, { mismatch: true })];
        case "duplicate": {
            const attribute = await createEssV2(certificate, additionalCertificate);
            return [attribute, attribute];
        }
        case "unsupported":
            return [await createEssV2(certificate, additionalCertificate, { unsupported: true })];
        case "conflicting":
            return [
                await createEssV1(certificate, additionalCertificate),
                await createEssV2(certificate, additionalCertificate, { mismatch: true }),
            ];
        case "v1":
            return [
                await createEssV1(certificate, additionalCertificate, {
                    additional: options.essAdditional,
                    issuerSerial: options.essIssuerSerial,
                    policies: options.essPolicies,
                }),
            ];
        case "v2":
            return [
                await createEssV2(certificate, additionalCertificate, {
                    additional: options.essAdditional,
                    issuerSerial: options.essIssuerSerial,
                    policies: options.essPolicies,
                }),
            ];
        case "both":
            return [
                await createEssV1(certificate, additionalCertificate, {
                    additional: options.essAdditional,
                    issuerSerial: options.essIssuerSerial,
                    policies: options.essPolicies,
                }),
                await createEssV2(certificate, additionalCertificate, {
                    additional: options.essAdditional,
                    issuerSerial: options.essIssuerSerial,
                    policies: options.essPolicies,
                }),
            ];
    }
}

function getResponseNonce(
    nonce: Uint8Array,
    responseNonce: RFC3161TokenFixtureOptions["responseNonce"]
): asn1js.Integer | undefined {
    if (responseNonce === "missing") return undefined;
    if (responseNonce === "zero") return new asn1js.Integer({ value: 0 });
    if (responseNonce === "negative") {
        return new asn1js.Integer({ valueHex: new Uint8Array([0x80]).buffer });
    }
    return new asn1js.Integer({ valueHex: toArrayBuffer(responseNonce ?? nonce) });
}

function makeSignerIdentifier(
    certificate: pkijs.Certificate,
    ski: Uint8Array,
    kind: NonNullable<RFC3161TokenFixtureOptions["signerSid"]>
): pkijs.IssuerAndSerialNumber | asn1js.Primitive {
    if (kind === "issuerSerial") {
        return new pkijs.IssuerAndSerialNumber({
            issuer: certificate.issuer,
            serialNumber: certificate.serialNumber,
        });
    }
    const valueHex = kind === "zero" ? new Uint8Array([0xde, 0xad]) : ski;
    return new asn1js.Primitive({
        idBlock: { tagClass: 3, tagNumber: 0 },
        valueHex: toArrayBuffer(valueHex),
    });
}

async function createToken(
    source: TokenSource,
    options: RFC3161TokenFixtureOptions
): Promise<Omit<RFC3161TokenFixture, "context">> {
    const suite = await getSuiteKeys();
    const eku = options.eku ?? "strict";
    const signerSki = new Uint8Array([0x42, 0x19, 0x75, 0x3c, 0x11, 0x2a, 0x8d, 0xfe]);
    const decoySki = new Uint8Array([0x73, 0x11, 0x04, 0xb2, 0x99, 0x7d, 0x22, 0x4f]);
    const signerCertificate = await createCertificate(
        suite.signer,
        "RFC3161 Fixture Signer",
        101,
        signerSki,
        eku,
        options.certificateValidity ?? "valid"
    );
    const decoyCertificate = await createCertificate(
        suite.decoy,
        "RFC3161 Fixture Decoy",
        202,
        decoySki,
        "strict"
    );

    let messageDigest = copyBytes(source.messageDigest);
    let imprintAlgorithm = source.context.hashAlgorithm;
    if (options.imprint === "mismatch") {
        const first = messageDigest[0];
        if (first === undefined) throw new Error("Fixture message imprint is empty");
        messageDigest[0] = first ^ 0xff;
    }
    if (options.imprint === "wrongLength") {
        messageDigest = messageDigest.slice(0, Math.max(1, messageDigest.length - 1));
    }
    if (options.imprint === "wrongAlgorithm") {
        imprintAlgorithm = source.context.hashAlgorithm === "SHA-256" ? "SHA-384" : "SHA-256";
        messageDigest = new Uint8Array(digestLength(imprintAlgorithm));
    }

    const tstInfo = new pkijs.TSTInfo({
        version: 1,
        policy: options.responsePolicy ?? source.context.policy ?? "1.2.3.4.5",
        messageImprint: new pkijs.MessageImprint({
            hashAlgorithm: new pkijs.AlgorithmIdentifier({
                algorithmId: oidForHashAlgorithm(imprintAlgorithm),
            }),
            hashedMessage: new asn1js.OctetString({ valueHex: toArrayBuffer(messageDigest) }),
        }),
        serialNumber: new asn1js.Integer({ value: 123456 }),
        genTime: new Date("2026-08-24T00:00:00Z"),
        nonce: getResponseNonce(source.context.nonce, options.responseNonce),
    });
    const tstInfoBytes = new Uint8Array(tstInfo.toSchema().toBER(false));
    const essAttributes = await createEssAttributes(
        options.ess ?? "v2",
        signerCertificate,
        decoyCertificate,
        options
    );
    const signedAttributes = [
        new pkijs.Attribute({
            type: ID_CONTENT_TYPE,
            values: [
                new asn1js.ObjectIdentifier({
                    value: options.eContentType === "data" ? ID_DATA : ID_CT_TST_INFO,
                }),
            ],
        }),
        new pkijs.Attribute({
            type: ID_MESSAGE_DIGEST,
            values: [
                new asn1js.OctetString({
                    valueHex: await crypto.subtle.digest("SHA-256", toArrayBuffer(tstInfoBytes)),
                }),
            ],
        }),
        ...essAttributes,
    ];
    const signerInfo = new pkijs.SignerInfo({
        version: options.signerSid === "issuerSerial" || options.signerSid === undefined ? 1 : 3,
        sid: makeSignerIdentifier(
            signerCertificate,
            signerSki,
            options.signerSid ?? "issuerSerial"
        ),
        signedAttrs: new pkijs.SignedAndUnsignedAttributes({
            type: 0,
            attributes: signedAttributes,
        }),
    });
    const certificates =
        options.certificates === "none"
            ? undefined
            : options.certificates === "decoyFirst"
              ? [decoyCertificate, signerCertificate]
              : options.certificates === "ambiguous"
                ? [signerCertificate, signerCertificate]
                : [signerCertificate];
    const signedData = new pkijs.SignedData({
        version: 3,
        encapContentInfo: new pkijs.EncapsulatedContentInfo({
            eContentType: options.eContentType === "data" ? ID_DATA : ID_CT_TST_INFO,
            eContent: new asn1js.OctetString({ valueHex: toArrayBuffer(tstInfoBytes) }),
        }),
        ...(certificates !== undefined && { certificates }),
        signerInfos: [signerInfo],
    });
    await signedData.sign(suite.signer.privateKey, 0, "SHA-256", undefined, cryptoEngine);
    if (options.signerCount === 2) {
        signedData.signerInfos.push(new pkijs.SignerInfo({ schema: signerInfo.toSchema() }));
    }
    const tokenContentInfo = new pkijs.ContentInfo({
        contentType: options.contentType === "data" ? ID_DATA : ID_SIGNED_DATA,
        content: signedData.toSchema(),
    });
    const canonicalRawToken = reencodeTstInfoEContent(
        new Uint8Array(tokenContentInfo.toSchema().toBER(false)),
        tstInfoBytes,
        options.eContentEncoding ?? "constructed"
    );
    if (options.corruptSignature) {
        const last = canonicalRawToken[canonicalRawToken.length - 1];
        if (last === undefined) throw new Error("Fixture token is empty");
        canonicalRawToken[canonicalRawToken.length - 1] = last ^ 0xff;
    }
    const rawTokenSchema = asn1js.fromBER(toArrayBuffer(canonicalRawToken));
    if (rawTokenSchema.offset !== canonicalRawToken.length) {
        throw new Error("Fixture re-encoded raw token is not complete DER");
    }
    const responseTokenContentInfo = new pkijs.ContentInfo({ schema: rawTokenSchema.result });
    const includeToken =
        options.includeToken ?? (options.status === undefined || options.status <= 1);
    const statusStrings =
        options.statusStrings ??
        (options.statusString === undefined ? undefined : [options.statusString]);
    const response = new pkijs.TimeStampResp({
        status: new pkijs.PKIStatusInfo({
            status: options.status ?? 0,
            ...(statusStrings !== undefined && {
                statusStrings: statusStrings.map((value) => new asn1js.Utf8String({ value })),
            }),
        }),
        ...(includeToken && { timeStampToken: responseTokenContentInfo }),
    });
    const canonicalResponse = new Uint8Array(response.toSchema().toBER(false));
    const rawToken =
        options.outerTokenFraming === undefined
            ? canonicalRawToken
            : reframeOuterDer(canonicalRawToken, options.outerTokenFraming, "Fixture ContentInfo");
    const nestedResponse =
        options.outerTokenFraming === undefined
            ? canonicalResponse
            : replaceNestedToken(canonicalResponse, canonicalRawToken, rawToken);
    const responseBytes =
        options.responseOuterFraming === undefined
            ? nestedResponse
            : reframeOuterDer(nestedResponse, options.responseOuterFraming, "Fixture TimeStampResp");
    return {
        rawToken,
        response: responseBytes,
        input: options.form === "response" ? responseBytes : rawToken,
        signerCertificate: certificateBytes(signerCertificate),
        decoyCertificate: certificateBytes(decoyCertificate),
    };
}

export async function createRFC3161TokenFixture(
    options: RFC3161TokenFixtureOptions = {}
): Promise<RFC3161TokenFixture> {
    const hashAlgorithm = options.hashAlgorithm ?? "SHA-256";
    const data = options.data ?? new Uint8Array([0x50, 0x44, 0x46, 0x2d, 0x74, 0x65, 0x73, 0x74]);
    const nonce = options.nonce ?? new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const context: FixtureRequestContext = {
        data: copyBytes(data),
        hashAlgorithm,
        nonce: copyBytes(nonce),
        ...(options.policy !== undefined && { policy: options.policy }),
        requestCertificate: options.requestCertificate ?? true,
    };
    const messageDigest = new Uint8Array(
        await crypto.subtle.digest(hashAlgorithm, toArrayBuffer(context.data))
    );
    return { context, ...(await createToken({ context, messageDigest }, options)) };
}

export async function createRFC3161TokenFixtureFromRequest(
    request: Uint8Array,
    options: Omit<
        RFC3161TokenFixtureOptions,
        "data" | "hashAlgorithm" | "nonce" | "policy" | "requestCertificate"
    > = {}
): Promise<Omit<RFC3161TokenFixture, "context">> {
    const parsed = asn1js.fromBER(toArrayBuffer(request));
    if (parsed.offset !== request.length) throw new Error("Fixture request is not complete DER");
    const tsq = new pkijs.TimeStampReq({ schema: parsed.result });
    const hashAlgorithm = OID_TO_HASH_ALGORITHM[tsq.messageImprint.hashAlgorithm.algorithmId];
    if (hashAlgorithm !== "SHA-256" && hashAlgorithm !== "SHA-384" && hashAlgorithm !== "SHA-512") {
        throw new Error("Fixture request has unsupported message-imprint algorithm");
    }
    const nonce = tsq.nonce ? new Uint8Array(tsq.nonce.valueBlock.valueHexView) : new Uint8Array();
    const context: FixtureRequestContext = {
        data: new Uint8Array(),
        hashAlgorithm,
        nonce,
        ...(tsq.reqPolicy !== undefined && { policy: tsq.reqPolicy }),
        requestCertificate: tsq.certReq ?? false,
    };
    const messageDigest = new Uint8Array(tsq.messageImprint.hashedMessage.valueBlock.valueHexView);
    const fixture = await createToken({ context, messageDigest }, options);
    if (
        !bytesEqual(
            messageDigest,
            new Uint8Array(tsq.messageImprint.hashedMessage.valueBlock.valueHexView)
        )
    ) {
        throw new Error("Fixture request message imprint changed unexpectedly");
    }
    return fixture;
}
